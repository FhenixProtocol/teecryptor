//! Teecryptor service entrypoint + boot sequence.
//!
//! Boot: init logging → read config (baked-env lookup, fail-closed) →
//! (per-partner attestation → STS federation → Secret Manager → load key) →
//! build state → flip healthcheck ready → serve.
//! With `--features mock`, the GCP chain is skipped and a throwaway ClientKey is
//! generated for local development only.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use sha2::{Digest, Sha256};
use teecryptor::ct_source::CtSource;
use teecryptor::http::{metrics_router, router, AppState};
use tracing::info;
use tracing_subscriber::EnvFilter;
// KeyStore + Zeroizing are used only by the mock loader; the real path goes
// through `cofhe-keys` + `key_source::assemble`, which own those types internally.
#[cfg(feature = "mock")]
use teecryptor::keys::KeyStore;
#[cfg(feature = "mock")]
use zeroize::Zeroizing;

/// Per-environment security policy, baked into the image. Holds the values that
/// used to be operator-set env vars (permit/commitment gates + threshold);
/// compiled in so they're attested, not runtime-overridable.
mod env_policy;

/// SHA-256 fingerprint (first 4 bytes, hex) of key material. Matches cofhe's
/// `rust_common::keygen::compute_key_hash`, so the value logged here is directly
/// comparable to the hashes cofhe (and the zk-verifier / threshold-network) log
/// for the same key. Logs only the digest, never the raw key bytes.
fn key_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..4])
}

#[cfg(test)]
mod fingerprint_tests {
    use super::key_fingerprint;

    // Locks key_fingerprint to SHA-256 (first 4 bytes, hex) — the exact algorithm
    // cofhe's `rust_common::keygen::compute_key_hash` uses. If it ever drifts, the
    // boot-logged hashes stop being comparable to cofhe/dispatcher and this test
    // fails loudly. Vectors are the standard SHA-256("") and SHA-256("abc").
    #[test]
    fn matches_cofhe_compute_key_hash_algorithm() {
        assert_eq!(key_fingerprint(b""), "e3b0c442");
        assert_eq!(key_fingerprint(b"abc"), "ba7816bf");
        assert_eq!(key_fingerprint(b"abc").len(), 8);
    }
}

// Service endpoint constants — intentionally NOT read from the environment, and
// excluded from the launcher's `allow_env_override` LABEL. If an attacker with
// compute.instances.setMetadata could override these, they could redirect the
// STS exchange to an endpoint they control, capture the genuine TDX-attested
// JWT, and replay it to real STS to impersonate the SA. Holding them in code
// closes that path.
// (The STS URL is `cofhe_keys::gcp_auth::DEFAULT_STS_URL` — also a
// compile-time const, same property.)
#[cfg(not(feature = "mock"))]
const ATTESTATION_SOCKET: &str = "/run/container_launcher/teeserver.sock";
#[cfg(not(feature = "mock"))]
const SM_URL: &str = "https://secretmanager.googleapis.com";
#[cfg(not(feature = "mock"))]
const GCS_URL: &str = "https://storage.googleapis.com";
// The FHE-priv secret each partner holds a Shamir share of. Hardcoded (not
// operator-overridable) to keep the env-override surface minimal.
#[cfg(not(feature = "mock"))]
const FHE_PRIV_SECRET: &str = "cofhe-tee-fhe-priv";
// NOTE: consumer-side attestation provenance verification was REMOVED (it crashed
// on Google JWKS `kid` rotation and was redundant with the partner attested-WIF
// write-gate), along with the keygen-origin allowlists it carried. The key SOURCE
// (partner set + bucket/object) is baked into the binary per environment
// (`cofhe_keys::reader::lookup`), so the `setMetadata`-redirection those allowlists
// guarded no longer exists. The end-to-end trust anchor is the ON-CHAIN SIGNATURE
// INVARIANT: the host chain accepts only results signed by the published
// decrypt-signer address, so serving a key from anywhere but the blessed source
// yields signatures the chain rejects.

struct Config {
    /// Baked-environment selector: names which compiled-in
    /// environment supplies the partner set + public-material location. Resolved
    /// FAIL-CLOSED at boot via `cofhe_keys::reader::lookup` — an unknown value
    /// aborts before any network call. Unused in mock mode.
    #[cfg_attr(feature = "mock", allow(dead_code))]
    env: String,
    /// The resolved baked source for `env`: partner projects + per-partner WIF
    /// pool audiences + public bucket/object. Compile-time data, never
    /// operator-settable.
    #[cfg(not(feature = "mock"))]
    env_cfg: &'static cofhe_keys::reader::EnvConfig,
    /// Shamir threshold T — minimum good shares required to reconstruct. Unused in
    /// mock mode.
    #[cfg_attr(feature = "mock", allow(dead_code))]
    threshold: u8,
    /// Base URL of the ct-server `/GetCT` source (required in all modes).
    ct_source_url: String,
    /// Per-request `/GetCT` timeout.
    getct_timeout: Duration,
    /// Listen address.
    bind_addr: String,
    /// Listen address of the Prometheus `/metrics` endpoint. A dedicated
    /// port (not a route on `bind_addr`): the LB fronts only the main port,
    /// so the scrape surface stays off the public path — reachable solely
    /// through the VM firewall. Env: `METRICS_ADDR` — a local-dev knob only;
    /// it is NOT in the image's env-override allowlist, since prod pins the
    /// port via EXPOSE + the firewall rule.
    metrics_addr: String,
    /// When `true`, `/decrypt` and `/sealoutput` gate on the ACL: a request
    /// carrying an ACP is checked with `isAllowedWithPermission`, one without it
    /// takes the `isPubliclyAllowed` path. An absent ACP is therefore not by
    /// itself a rejection. When `false`, the ACP field is ignored even if
    /// supplied.
    ///
    /// Baked per-env (`env_policy`) on the real boot path — every baked env sets
    /// it `true`; mock builds still read `REQUIRE_PERMIT` from the environment so
    /// the local docker-compose stack keeps working.
    ///
    /// The env vars that remain keep their pre-ACP `permit` wording
    /// (`REQUIRE_PERMIT`, `PERMIT_CHAINS_JSON`): they are the operator contract,
    /// wired into `compute/main.tf` as `tee-env-*` VM metadata keys and into
    /// cofhe's docker-compose, so renaming them would force a coordinated
    /// terraform apply on the staging and testnet TDX VMs for zero behavior
    /// change. The rule: identifiers that mirror an env var keep its wording;
    /// identifiers that name the type moved to ACP (`AcpData`, `acp_verifier`,
    /// the `acp_*` error codes).
    require_permit: bool,
    /// ACP verifier — `HashMap<host_chain_id, ChainConfig>` parsed from
    /// `PERMIT_CHAINS_JSON`. `Some` when the env var is set with a non-empty
    /// map. Required when `require_permit` is true; otherwise informational.
    acp_verifier: Option<teecryptor::permit::ChainsVerifierConfig>,
    /// When `true` (default, fail-closed), `/decrypt` and `/sealoutput` reject
    /// any handle lacking an on-chain commitment. Baked per-env (`env_policy`),
    /// was `REQUIRE_COMMITMENT`.
    enable_commitment_verification: bool,
    /// Commitment verifier — a single `CommitmentRegistry` endpoint parsed from
    /// `COMMITMENT_REGISTRY_*` env vars. `Some` when configured. Required when
    /// `enable_commitment_verification` is true; otherwise informational.
    commitment_verifier: Option<teecryptor::commitment::CommitmentConfig>,
    /// Max concurrent tfhe decrypts (wait-only CPU gate). Default: available
    /// parallelism (CPU/cgroup quota). Env: `DECRYPT_CONCURRENCY`.
    decrypt_concurrency: usize,
    /// Max in-flight requests before the 204 overload backstop. Default 1000.
    /// Env: `MAX_INFLIGHT`.
    max_inflight: usize,
}

/// Read an env var, or fall back to `default`. Shared by `Config::from_env`
/// and `parse_commitment_config`.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    fn from_env() -> Result<Self> {
        // GCP fields are required for the real boot path, but irrelevant in mock
        // mode (no attestation/Secret-Manager calls happen).
        #[cfg(not(feature = "mock"))]
        fn req(key: &str) -> Result<String> {
            std::env::var(key).with_context(|| format!("env var {key} not set"))
        }
        #[cfg(feature = "mock")]
        fn req(_key: &str) -> Result<String> {
            Ok(String::new())
        }

        let getct_timeout_ms: u64 = env_or("GETCT_TIMEOUT_MS", "5000")
            .parse()
            .context("GETCT_TIMEOUT_MS must be a positive integer (ms)")?;

        // Baked-environment selector. Two things resolve from ENV, both
        // compiled-in and fail-closed (an unknown value aborts before any network
        // call): the key SOURCE (partner set + WIF audiences + public
        // bucket/object) from `cofhe-keys`, and the security POLICY (permit /
        // commitment gates + Shamir threshold) from `env_policy`. COFHE_ENV only picks
        // WHICH blessed environment applies. Baking the policy (rather than
        // reading REQUIRE_PERMIT / REQUIRE_COMMITMENT / COMMITMENT_* / SHAMIR_*
        // from env) keeps it out of the operator-override surface — see
        // `env_policy`.
        let env = req("COFHE_ENV")?;
        #[cfg(not(feature = "mock"))]
        let env_cfg = cofhe_keys::reader::lookup(&env)
            .context("ENV must name a baked environment (fail-closed)")?;
        #[cfg(not(feature = "mock"))]
        let policy = env_policy::EnvPolicy::for_env(&env)
            .context("resolving baked security policy (fail-closed)")?;
        // Mock keeps sourcing these knobs from env so local docker-compose is
        // unaffected; the real boot path never takes this route.
        #[cfg(feature = "mock")]
        let policy = env_policy::EnvPolicy::from_env_mock()?;

        // Fail-closed ACL gate. The switch is baked per-env (was REQUIRE_PERMIT);
        // the verifier's chains carry API-keyed RPC URLs, so they stay
        // env-supplied via PERMIT_CHAINS_JSON. Gate on but no chains → boot bails,
        // so an open decryptor can't be served by forgetting the chains.
        let require_permit = policy.require_permit;
        let acp_verifier = parse_permit_chains()?;
        if require_permit && acp_verifier.is_none() {
            anyhow::bail!(
                "require_permit is baked on for this environment but PERMIT_CHAINS_JSON is not \
                 configured — set it with at least one chain"
            );
        }

        // Fail-closed commitment gate. The switch, version, registry ADDRESS and
        // warn-only are baked per-env (were REQUIRE_COMMITMENT / COMMITMENT_VERSION
        // / COMMITMENT_REGISTRY_ADDRESS / COMMITMENT_WARN_ONLY); the registry RPC
        // URL (API-keyed) stays env-supplied. Gate on but unconfigured → boot bails.
        let enable_commitment_verification = policy.enable_commitment_verification;
        let commitment_verifier = parse_commitment_config(&policy)?;
        if enable_commitment_verification && commitment_verifier.is_none() {
            anyhow::bail!(
                "enable_commitment_verification is baked on for this environment but the commitment verifier \
                 is not configured — set COMMITMENT_REGISTRY_RPC_URL"
            );
        }
        if commitment_verifier.as_ref().is_some_and(|c| c.warn_only()) {
            tracing::warn!(
                "commitment gate is in warning-instead-of-enforcement mode (baked \
                 warning_instead_of_enforcement=true): failures are logged but decrypts are \
                 ALLOWED — rebuild with it false to enforce"
            );
        }

        // Default = available parallelism (honours the TDX VM's cgroup CPU quota).
        let decrypt_concurrency: usize = match std::env::var("DECRYPT_CONCURRENCY") {
            Ok(v) => v
                .parse()
                .context("DECRYPT_CONCURRENCY must be a positive integer")?,
            Err(_) => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        };
        let max_inflight: usize = env_or("MAX_INFLIGHT", "1000")
            .parse()
            .context("MAX_INFLIGHT must be a positive integer")?;

        // Shamir threshold T comes from the cofhe-keys baked env map
        // (`EnvConfig.shamir_threshold`) — the SAME value the keygen producer splits
        // with and the zk-verifier reconstructs with, so there is ONE source of truth
        // and no cross-service drift (it is NOT duplicated in the security policy).
        // Validated fail-closed against the baked partner count: a T below the vsss
        // floor or above the partner count can never reconstruct — reject at boot.
        #[cfg(not(feature = "mock"))]
        let threshold: u8 = env_cfg.shamir_threshold;
        #[cfg(not(feature = "mock"))]
        validate_threshold(threshold, env_cfg.partners.len())?;
        // Mock skips the reader entirely (no baked partner set to reconstruct
        // against), so T is unused on this path — a fixed valid value keeps Config total.
        #[cfg(feature = "mock")]
        let threshold: u8 = 2;

        Ok(Config {
            env,
            #[cfg(not(feature = "mock"))]
            env_cfg,
            threshold,
            ct_source_url: std::env::var("CT_SOURCE_URL")
                .context("env var CT_SOURCE_URL not set")?,
            getct_timeout: Duration::from_millis(getct_timeout_ms),
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080"),
            metrics_addr: env_or("METRICS_ADDR", "0.0.0.0:9090"),
            require_permit,
            acp_verifier,
            enable_commitment_verification,
            commitment_verifier,
            decrypt_concurrency,
            max_inflight,
        })
    }
}

/// Fail-closed validation of the (now baked) Shamir threshold against the baked
/// partner set. Extracted so it can be unit-tested with synthetic values.
#[cfg(not(feature = "mock"))]
fn validate_threshold(threshold: u8, partner_count: usize) -> Result<()> {
    if threshold < cofhe_keys::shamir::MIN_THRESHOLD {
        anyhow::bail!("shamir_threshold must be >= 2 (vsss Gf256 minimum)");
    }
    if threshold as usize > partner_count {
        anyhow::bail!(
            "shamir_threshold ({threshold}) exceeds the number of partners ({partner_count})"
        );
    }
    Ok(())
}

/// The CoFHE `TaskManager` contract address. It is deployed deterministically, so it
/// is the SAME on every host chain and in every environment — baked as one attested
/// constant rather than per-chain operator input, so a `setMetadata`-capable operator
/// cannot point the permit gate at a TaskManager they control. Non-secret (a public
/// contract address); only the API-keyed RPC URLs stay env-supplied. Validated at
/// compile time by `address!`, so a typo in it is a build error, not a boot failure.
const TASK_MANAGER: alloy::primitives::Address =
    alloy::primitives::address!("0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9");

/// Parse `PERMIT_CHAINS_JSON` into a [`ChainsVerifierConfig`].
///
/// Format: a JSON object mapping `host_chain_id` (as a string, since JSON
/// object keys are strings) to per-chain settings — only the API-keyed RPC URL
/// (+ optional `timeout_ms`); the TaskManager address is baked
/// ([`TASK_MANAGER`]), not carried here:
///
/// ```json
/// {
///   "1":      { "rpc_url": "https://eth.llamarpc.com", "timeout_ms": 5000 },
///   "420105": { "rpc_url": "http://localhost:8545" }
/// }
/// ```
///
/// `timeout_ms` is optional (default: 5000). `Ok(None)` is returned if the env
/// var is unset or `"{}"`; that's equivalent to "no verifier installed", and
/// the caller cross-checks against the baked `require_permit` policy.
fn parse_permit_chains() -> Result<Option<teecryptor::permit::ChainsVerifierConfig>> {
    use std::collections::HashMap;
    use teecryptor::permit::{ChainConfig, ChainsVerifierConfig};

    /// Per-entry wire shape inside `PERMIT_CHAINS_JSON`. Carries only the API-keyed
    /// RPC URL (+ optional timeout); the TaskManager address is baked
    /// (`TASK_MANAGER`), not operator-supplied.
    #[derive(serde::Deserialize)]
    struct ChainEntry {
        rpc_url: String,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    }
    fn default_timeout_ms() -> u64 {
        5000
    }

    let raw = match std::env::var("PERMIT_CHAINS_JSON") {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let parsed: HashMap<String, ChainEntry> = serde_json::from_str(&raw)
        .context("PERMIT_CHAINS_JSON must be a JSON object mapping chain_id → entry")?;

    if parsed.is_empty() {
        return Ok(None);
    }

    let mut chains: HashMap<u64, ChainConfig> = HashMap::with_capacity(parsed.len());
    for (chain_id_str, entry) in parsed {
        let chain_id: u64 = chain_id_str.parse().with_context(|| {
            format!("PERMIT_CHAINS_JSON: chain id {chain_id_str:?} is not a u64")
        })?;
        // TaskManager is the baked `TASK_MANAGER` constant (deterministic + identical
        // on every chain and env, so attested rather than operator-settable). Builds
        // the pooled provider once here (fail-fast on a bad rpc_url) so every verify
        // call reuses the warm connection instead of dialing cold.
        let chain_cfg = ChainConfig::new(
            entry.rpc_url,
            TASK_MANAGER,
            Duration::from_millis(entry.timeout_ms),
        )
        .with_context(|| format!("PERMIT_CHAINS_JSON[{chain_id}]: invalid rpc_url"))?;
        chains.insert(chain_id, chain_cfg);
    }
    Ok(Some(ChainsVerifierConfig { chains }))
}

/// Parse the commitment-registry verifier from env.
///
/// Unlike the ACP verifier (one entry per host chain), the
/// `CommitmentRegistry` is a **single**, chain-agnostic contract keyed by
/// `(version, handle)`, so this is one endpoint + address + version; the
/// per-request `host_chain_id` is used only as a local cache key, never sent
/// to the registry.
///
/// Baked per-env (from `EnvPolicy`): the registry ADDRESS, the commitment
/// VERSION, and the WARN_ONLY relax flag — non-secret policy that must not be
/// operator-overridable.
///
/// Env-supplied (operational / secret-bearing):
///   - `COMMITMENT_REGISTRY_RPC_URL`  — API-keyed; required to enable, unset → `Ok(None)`
///   - `COMMITMENT_TIMEOUT_MS`        — default 5000; minimum 50 (a zero/near-
///     zero timeout would fail every registry call before it can answer)
///   - `COMMITMENT_CACHE_SIZE`        — default 100000 entries
///   - `COMMITMENT_CACHE_TTL_SECS`    — default 3600. How long a cached positive
///     lookup stays valid; bounds staleness when the chain + registry are wiped
///     and redeployed under a long-lived process (see the `commitment` module
///     docs). Must be greater than zero.
///
/// `Ok(None)` when the RPC URL is unset; the caller cross-checks against
/// `policy.enable_commitment_verification`.
fn parse_commitment_config(
    policy: &env_policy::EnvPolicy,
) -> Result<Option<teecryptor::commitment::CommitmentConfig>> {
    use std::num::NonZeroUsize;
    use teecryptor::commitment::{parse_version, CommitmentConfig};

    const MIN_TIMEOUT_MS: u64 = 50;

    // The registry RPC URL (API-keyed) is env-supplied and gates enablement:
    // unset → no commitment verifier installed.
    let rpc_url = match std::env::var("COMMITMENT_REGISTRY_RPC_URL") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    // Address + version come from the baked per-env [commitment] block (public,
    // non-secret). Its presence is guaranteed to match enable_commitment_verification by
    // `EnvPolicy::for_env`; the `?` guards the mock path (and any hand-built policy).
    let commitment = policy.commitment.as_ref().context(
        "COMMITMENT_REGISTRY_RPC_URL set but no [commitment] policy is baked for this environment",
    )?;
    let registry = commitment
        .registry_address
        .parse()
        .context("baked commitment registry_address must be a 0x-prefixed Ethereum address")?;
    let version = parse_version(&commitment.version)
        .map_err(|e| anyhow::anyhow!("baked commitment version invalid: {e}"))?;
    let timeout_ms: u64 = env_or("COMMITMENT_TIMEOUT_MS", "5000")
        .parse()
        .context("COMMITMENT_TIMEOUT_MS must be a positive integer (ms)")?;
    if timeout_ms < MIN_TIMEOUT_MS {
        anyhow::bail!(
            "COMMITMENT_TIMEOUT_MS={timeout_ms} is below the {MIN_TIMEOUT_MS}ms minimum — \
             a (near-)zero timeout would fail every registry call before it can answer"
        );
    }
    let cache_size: usize = env_or("COMMITMENT_CACHE_SIZE", "100000")
        .parse()
        .context("COMMITMENT_CACHE_SIZE must be a positive integer")?;
    let cache_size =
        NonZeroUsize::new(cache_size).context("COMMITMENT_CACHE_SIZE must be greater than zero")?;

    let cache_ttl_secs: u64 = env_or("COMMITMENT_CACHE_TTL_SECS", "3600")
        .parse()
        .context("COMMITMENT_CACHE_TTL_SECS must be a positive integer (seconds)")?;
    if cache_ttl_secs == 0 {
        anyhow::bail!(
            "COMMITMENT_CACHE_TTL_SECS=0 would expire every entry instantly, making the \
             cache a pure overhead — set a positive TTL"
        );
    }

    let warning_instead_of_enforcement = commitment.warning_instead_of_enforcement;

    let cfg = CommitmentConfig::new(
        rpc_url,
        registry,
        version,
        Duration::from_millis(timeout_ms),
        cache_size,
        Duration::from_secs(cache_ttl_secs),
    )
    .map_err(|e| anyhow::anyhow!("build commitment verifier: {e}"))?
    .with_warn_only(warning_instead_of_enforcement);
    Ok(Some(cfg))
}

/// Real boot + read path: per-partner attested federation (attest with each
/// partner's WIF audience → STS → that partner's SM bearer) → compute-SA GCS read
/// of the public material (metadata server; the material is public, no
/// federation needed) → reconstruct the FHE-priv secret across the partners (the
/// `cofhe-keys` reader gathers every share, filters liars by per-share
/// digest, reconstructs T-of-N, and validates against the published full
/// digest) → assemble the in-memory key
/// handles. The GCP endpoints are compile-time `const`s here (NOT
/// env-overridable) so a `setMetadata`-capable operator cannot redirect the STS
/// exchange, and the key SOURCE is the baked env config.
#[cfg(not(feature = "mock"))]
async fn load_keys(cfg: &Config) -> Result<teecryptor::key_source::LoadedKeys> {
    use cofhe_keys::gcp_auth::MetadataClient;
    use cofhe_keys::gcs::GcsClient;
    use cofhe_keys::reader::{partner_refs, read_fhe_priv, PartnerAccess, ReaderContext};
    use cofhe_keys::secrets::SecretManager;
    use teecryptor::boot::{load_partner_tokens, Endpoints, Timeouts};

    let partners = partner_refs(cfg.env_cfg, "teecryptor", FHE_PRIV_SECRET)?;
    let endpoints = Endpoints {
        attestation_socket: ATTESTATION_SOCKET,
        sts_url: cofhe_keys::gcp_auth::DEFAULT_STS_URL,
    };
    let timeouts = Timeouts::default();
    info!(
        env = %cfg.env,
        partners = partners.len(),
        "running per-partner attested federation"
    );
    let (partner_tokens, failed) = load_partner_tokens(&endpoints, &partners, &timeouts).await;
    if !failed.is_empty() {
        tracing::warn!(
            failed = ?failed,
            "some partners excluded at federation; reconstruction proceeds if >= threshold remain"
        );
    }

    // GCS bearer for the public material: the VM's own compute SA via the
    // metadata server (bounded — a hung metadata endpoint must not wedge boot).
    let gcs_token = tokio::time::timeout(
        timeouts.gcp,
        MetadataClient::new(cofhe_keys::gcp_auth::DEFAULT_METADATA_URL).token(),
    )
    .await
    .context("metadata token fetch timed out")?
    .context("fetch compute-SA token from metadata server")?;

    let sm = SecretManager::new(SM_URL);
    let gcs = GcsClient::new(GCS_URL);

    // Pair each surviving partner's federated token with its PartnerRef.
    let accesses: Vec<PartnerAccess> = partner_tokens
        .iter()
        .map(|t| {
            let partner = partners
                .iter()
                .find(|p| p.project_id == t.project_id)
                .expect("partner token without a matching PartnerRef — bug in load_partner_tokens");
            PartnerAccess {
                partner,
                sm_token: &t.sm_token,
            }
        })
        .collect();

    let ctx = ReaderContext {
        sm: &sm,
        gcs: &gcs,
        gcs_token: &gcs_token,
        public_bucket: cfg.env_cfg.public_bucket,
        public_object: cfg.env_cfg.public_object,
    };

    let share = read_fhe_priv(&ctx, &accesses, cfg.threshold)
        .await
        .context("reconstruct fhe-priv across partners")?;
    // Fingerprint the reconstructed ClientKey bytes before `assemble` consumes
    // them — same algorithm/token as cofhe's `log_key_hash`, so the value is
    // byte-comparable to fhe-engine's zone-0 key hash. (`assemble` zeroizes.)
    let client_key_hash = key_fingerprint(&share.client_key);
    let loaded = teecryptor::key_source::assemble(share)?;
    info!(
        "Key loaded: Client Key (zone 0) (hash: {})",
        client_key_hash
    );
    Ok(loaded)
}

/// Filenames inside `MOCK_KEYS_DIR`, matching cofhe's `deployments/keys/dev`
/// layout — the same directory its dispatcher and ct-server mount at `/app/keys`.
#[cfg(feature = "mock")]
const COFHE_CLIENT_KEY_FILE: &str = "ck.binfile";
#[cfg(feature = "mock")]
const COFHE_SIGNER_KEY_FILE: &str = "dispatcher_signer_pk";

/// Mock boot path (LOCAL DEV ONLY): no attestation, no GCP. Returns the FHE
/// `ClientKey` bytes and the signing service **together**, because they are only
/// meaningful as a pair — mixing them yields a Teecryptor that decrypts real
/// ciphertexts but signs with an identity no chain trusts, or vice versa.
///
/// `MOCK_KEYS_DIR` selects between the only two coherent modes:
///
/// - **unset** — fully self-contained: a fresh throwaway `ClientKey` and a
///   throwaway signer. Good for `/healthz` and HTTP-error smoke tests; it cannot
///   decrypt real cofhe ciphertexts and its signatures verify nowhere.
/// - **set** — stand in for cofhe's dev decryptor: read the `ClientKey` from
///   `<dir>/ck.binfile` and the signer from `<dir>/dispatcher_signer_pk`, i.e.
///   cofhe's committed dev keys. Teecryptor then decrypts real ct-server output
///   and signs as the same on-chain identity the local stack already trusts.
///
/// Both files are required when the dir is set — a partial directory is a
/// misconfiguration, not a half-mode, so it fails at boot instead of silently
/// falling back to a throwaway.
///
/// This whole function is compiled out of the production binary
/// (`#[cfg(feature = "mock")]`), so no environment variable can influence key or
/// signer material there: the real path reconstructs both from the FHE-priv
/// Shamir secret. `MOCK_KEYS_DIR` is likewise absent from the Dockerfile
/// `allow_env_override` LABEL, so a Confidential Space VM drops it too.
#[cfg(feature = "mock")]
fn load_mock_keys() -> Result<(
    Zeroizing<Vec<u8>>,
    teecryptor::signing::service::SigningService,
)> {
    // `var_os`, not `var`: a non-UTF-8 path is a real value, and collapsing it
    // into the unset branch would silently boot throwaway keys.
    let dir = match std::env::var_os("MOCK_KEYS_DIR") {
        None => return throwaway_mock_keys(),
        Some(v) if v.is_empty() => return throwaway_mock_keys(),
        Some(v) => std::path::PathBuf::from(v),
    };
    let dir = dir.as_path();
    let client_key_path = dir.join(COFHE_CLIENT_KEY_FILE);
    let signer_key_path = dir.join(COFHE_SIGNER_KEY_FILE);
    tracing::warn!(
        dir = %dir.display(),
        "MOCK MODE: loading cofhe dev keys from MOCK_KEYS_DIR — NOT attested, NOT for production"
    );

    let key_bytes = Zeroizing::new(
        std::fs::read(&client_key_path)
            .with_context(|| format!("read ClientKey {}", client_key_path.display()))?,
    );
    let svc = teecryptor::signing::service::SigningService::from_key_file(&signer_key_path)
        .with_context(|| format!("read signer key {}", signer_key_path.display()))?;
    info!(
        "Signing service initialized with address: {} (from MOCK_KEYS_DIR)",
        svc.evm_address()
    );

    Ok((key_bytes, svc))
}

/// The self-contained half of [`load_mock_keys`]: a throwaway `ClientKey` and a
/// throwaway signer. Signing stays on so "a running Teecryptor always signs"
/// holds here too; the signatures simply verify nowhere.
#[cfg(feature = "mock")]
fn throwaway_mock_keys() -> Result<(
    Zeroizing<Vec<u8>>,
    teecryptor::signing::service::SigningService,
)> {
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::{generate_keys, ConfigBuilder};

    tracing::warn!("MOCK MODE: generating throwaway ClientKey — NOT attested, NOT for production");
    let (ck, _sk) = generate_keys(ConfigBuilder::default().build());
    let mut key_bytes = Vec::new();
    safe_serialize(&ck, &mut key_bytes, 1 << 30).context("serialize mock key")?;

    let signer_bytes = Zeroizing::new(dryoc::rng::randombytes_buf(32));
    let svc = teecryptor::signing::service::SigningService::from_bytes(signer_bytes)
        .context("build mock signing service")?;
    tracing::warn!(
        "MOCK MODE: throwaway signer ({}) — NOT attested, won't verify on-chain",
        svc.evm_address()
    );

    Ok((Zeroizing::new(key_bytes), svc))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // Install the rustls crypto provider explicitly so a second provider
    // entering the dep tree can never cause a lazy-init panic mid-boot.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring crypto provider");

    let cfg = Config::from_env()?;

    // Real path: reconstruct the FHE-priv secret across the partners and assemble the
    // in-memory handles. The decrypt-path signer is bundled in the secret, so it's
    // always present — no separate fetch, and no way to boot unsigned.
    #[cfg(not(feature = "mock"))]
    let (keys, signing_svc) = {
        let loaded = load_keys(&cfg)
            .await
            .context("load + reconstruct FHE-priv key")?;
        // `(hash: ...)` was logged inside load_keys; log the derived signer address
        // (byte-comparable to the published decrypt_signer_address) here.
        info!(
            "Signing service initialized with address: {}",
            loaded.signer.evm_address()
        );
        (loaded.keys, Some(loaded.signer))
    };

    // Mock loads its ClientKey and signer as one unit — see load_mock_keys for why
    // they cannot be chosen independently. Signing is always on, so "a running
    // Teecryptor always signs" holds on this path too.
    #[cfg(feature = "mock")]
    let (keys, signing_svc) = {
        let (key_bytes, svc) = load_mock_keys()?;
        let client_key_hash = key_fingerprint(&key_bytes[..]);
        let keys = KeyStore::load(key_bytes).map_err(|e| anyhow::anyhow!("load FHE key: {e}"))?;
        info!(
            "Key loaded: Client Key (zone 0) (hash: {})",
            client_key_hash
        );
        (keys, Some(svc))
    };

    let ct_source = CtSource::new(&cfg.ct_source_url, cfg.getct_timeout)
        .map_err(|e| anyhow::anyhow!("build ct-source client: {e}"))?;
    // The health loop shares this client, and therefore its warm connection
    // pool, with the request path.
    let probe_ct_source = ct_source.clone();

    let mut state = AppState::new(keys, ct_source, signing_svc);
    if cfg.require_permit {
        // require_permit guarantees acp_verifier is Some (checked in
        // Config::from_env), so the `expect` below never fires.
        state = state.with_acp_verifier(
            cfg.acp_verifier
                .clone()
                .expect("require_permit but no acp_verifier — bug in Config::from_env"),
        );
        info!("ACP verification enabled (baked require_permit=true)");
    }
    // Only reachable on the mock/local path, where require_permit is an env toggle;
    // every baked (non-mock) env has require_permit=true, so this is compiled out of
    // the attested production binary.
    #[cfg(feature = "mock")]
    if !cfg.require_permit && cfg.acp_verifier.is_some() {
        tracing::warn!("ACP verifier env is set but require_permit=false — ACPs will be ignored");
    }
    if cfg.enable_commitment_verification {
        // enable_commitment_verification guarantees commitment_verifier is Some (checked in
        // Config::from_env), so the unwrap branch is never taken.
        let cv = cfg.commitment_verifier.clone().expect(
            "enable_commitment_verification but no commitment_verifier — bug in Config::from_env",
        );
        info!(
            registry = %cv.registry,
            version = %cv.version,
            "commitment enforcement enabled (baked enable_commitment_verification=true)"
        );
        // Boot-time registry probe: fail fast on a wrong address / unreachable
        // RPC (otherwise every decrypt 502s), and warn loudly on a version
        // that isn't Active (otherwise every decrypt 204s until the client's
        // retry budget silently runs out). Non-Active is a warn, not a bail: a
        // version may legitimately be activated after this VM boots.
        let status = teecryptor::commitment::probe_registry(&cv)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "commitment registry boot probe failed: {e} — check \
                     COMMITMENT_REGISTRY_RPC_URL / COMMITMENT_REGISTRY_ADDRESS"
                )
            })?;
        {
            use teecryptor::commitment::VersionStatus;
            if VersionStatus::from_u8(status) == Some(VersionStatus::Active) {
                info!(
                    registry = %cv.registry,
                    version = %cv.version,
                    "commitment registry probe: version Active"
                );
            } else {
                tracing::warn!(
                    registry = %cv.registry,
                    version = %cv.version,
                    status = VersionStatus::name_of(status),
                    "commitment registry probe: version NOT Active — decrypts will \
                     return 204 until commitments can land (check COMMITMENT_VERSION \
                     against the engine/poster)"
                );
            }
        }
        state = state.with_commitment_verifier(cv);
    }
    // Only reachable on the mock/local path; in a baked (non-mock) build a verifier
    // exists only when the gate is baked on, so this is compiled out of production.
    #[cfg(feature = "mock")]
    if !cfg.enable_commitment_verification && cfg.commitment_verifier.is_some() {
        tracing::warn!(
            "commitment verifier is set but enable_commitment_verification=false — commitments \
             will not be enforced"
        );
    }
    state = state.with_concurrency(cfg.decrypt_concurrency, cfg.max_inflight);
    info!(
        decrypt_concurrency = cfg.decrypt_concurrency,
        max_inflight = cfg.max_inflight,
        "CPU gate configured"
    );
    // The real metrics pipeline, built once with everything it needs known:
    // the served-chain set bounds `host_chain_id`, and the push half is
    // constructed exactly once — a discarded pipeline blocks on drop to flush.
    let served_chains: Vec<u64> = cfg
        .acp_verifier
        .as_ref()
        .map(|v| v.chains.keys().copied().collect())
        .unwrap_or_default();
    // Dependency probes. teecryptor publishes its own verdict
    // (`teecryptor_healthy`) instead of leaving a status page to re-derive
    // health from parts: what an unreachable dependency MEANS is a decision
    // for the service that owns it. Only what this deployment configures gets
    // a series — a disabled gate has nothing to be up or down about.
    let mut probed: Vec<&'static str> = vec![teecryptor::metrics::CT_SOURCE];
    if cfg.commitment_verifier.is_some() {
        probed.push(teecryptor::metrics::COMMITMENT_REGISTRY);
    }
    let health = teecryptor::metrics::Health::new(probed, served_chains.clone());

    // Push is not configuration: every real build pushes to the compiled-in
    // Google endpoint (see `GOOGLE_TELEMETRY_ENDPOINT` for why), and only the
    // mock (local dev) build is scrape-only — a dev machine has no VM identity
    // to push as.
    let metrics = if cfg!(feature = "mock") {
        teecryptor::metrics::Metrics::new(served_chains)
    } else {
        info!(
            endpoint = teecryptor::metrics::GOOGLE_TELEMETRY_ENDPOINT,
            "metrics: OTLP push enabled"
        );
        teecryptor::metrics::Metrics::with_otlp(
            served_chains.clone(),
            teecryptor::metrics::OtlpSettings {
                endpoint: teecryptor::metrics::GOOGLE_TELEMETRY_ENDPOINT.to_string(),
                env: cfg.env.clone(),
                metadata_host: None,
            },
        )
        .unwrap_or_else(|e| {
            // Fail-open: a metadata blip or a missing IAM grant must not
            // turn a monitoring gap into a manual-recovery outage. The
            // absence alert (metrics-target-down) is what catches this.
            tracing::error!(
                error = %e,
                "metrics: OTLP push pipeline failed to build — running WITHOUT metrics export"
            );
            teecryptor::metrics::Metrics::new(served_chains)
        })
    };
    state = state.with_metrics(metrics.with_health(Arc::clone(&health)));

    state.set_ready(); // boot fully succeeded

    // Probing runs on its own task: it must never sit in the request path, and
    // a wedged dependency must delay only the next round.
    tokio::spawn(probe_dependencies(
        Arc::clone(&health),
        probe_ct_source,
        cfg.acp_verifier.clone(),
        cfg.commitment_verifier.clone(),
    ));

    // Two servers, one process: the API router and the text exposition on its
    // own port. In push mode that port is NOT a collection path — OTLP is —
    // it is the IAP-only debug surface an operator reads when a push looks
    // wrong; in prometheus mode (local dev) it is the only path.
    // Fail-fast: if either server dies the whole process exits (and the
    // launcher restarts it) rather than limping along half-up.
    tokio::try_join!(
        serve(&cfg.bind_addr, router(state.clone()), "teecryptor"),
        serve(&cfg.metrics_addr, metrics_router(&state), "metrics"),
    )?;
    Ok(())
}

/// How often dependencies are probed. Short enough that a status page reacts
/// within one page refresh, long enough to be invisible beside real traffic.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Probe every configured dependency forever, writing results into `health`.
///
/// Sequential within a round on purpose: each probe is timeout-bounded and a
/// handful of cheap requests every 15s needs no concurrency, so one slow
/// dependency delays the remainder of its own round and nothing else.
///
/// Rounds start on a fixed tick rather than [`PROBE_INTERVAL`] after the
/// previous round ended, so probe timeouts do not stretch the cadence. A
/// round that overruns the interval (every probe timing out at once) delays
/// the next tick instead of bursting to catch up.
async fn probe_dependencies(
    health: Arc<teecryptor::metrics::Health>,
    ct_source: CtSource,
    acp: Option<teecryptor::permit::ChainsVerifierConfig>,
    commitment: Option<teecryptor::commitment::CommitmentConfig>,
) {
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        health.set(teecryptor::metrics::CT_SOURCE, ct_source.probe().await);
        if let Some(cv) = &commitment {
            health.set(teecryptor::metrics::COMMITMENT_REGISTRY, cv.probe().await);
        }
        if let Some(chains) = &acp {
            for (chain_id, chain) in &chains.chains {
                health.set_chain(*chain_id, chain.probe().await);
            }
        }
    }
}

/// Bind `addr` and serve `app` until ctrl-c, logging as `name`. Each call
/// registers its own ctrl-c listener, so concurrent servers all drain
/// gracefully on the same signal.
async fn serve(addr: &str, app: Router, name: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!(addr = %addr, "{name} listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .with_context(|| format!("{name} server error"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env-var manipulation races by default — cargo test runs tests in
    /// parallel via threads in the same process. Serialize the env-touching
    /// tests with a process-wide mutex.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII snapshot-restore for a fixed set of env vars. Clears them on
    /// construction so each test starts from a known-blank state.
    struct EnvGuard {
        snapshots: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let snapshots: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in keys {
                std::env::remove_var(k);
            }
            Self {
                snapshots,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.snapshots {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    const KEYS: &[&str] = &[
        "CT_SOURCE_URL",
        "GETCT_TIMEOUT_MS",
        "BIND_ADDR",
        "METRICS_ADDR",
        "COFHE_ENV",
        "PERMIT_CHAINS_JSON",
        "COMMITMENT_REGISTRY_RPC_URL",
        "COMMITMENT_TIMEOUT_MS",
        "COMMITMENT_CACHE_SIZE",
        "COMMITMENT_CACHE_TTL_SECS",
        "DECRYPT_CONCURRENCY",
        "MAX_INFLIGHT",
        // Baked per-env on the real boot path; the mock/local path still reads them.
        // Cleared either way so a stray value in the developer's shell can't perturb a test.
        "SHAMIR_THRESHOLD",
        "REQUIRE_PERMIT",
        "ENABLE_COMMITMENT_VERIFICATION",
        "COMMITMENT_WARNING_INSTEAD_OF_ENFORCEMENT",
        "COMMITMENT_VERSION",
        "COMMITMENT_REGISTRY_ADDRESS",
        // Mock-only local-run switch (compiled out of production); cleared so a
        // stray shell value can't perturb a test.
        "MOCK_KEYS_DIR",
    ];

    /// `MOCK_KEYS_DIR` must load the ClientKey and the signer together or fail.
    /// A partial directory is a misconfiguration: silently falling back to a
    /// throwaway would produce a Teecryptor that looks healthy but whose
    /// signatures verify nowhere.
    #[cfg(feature = "mock")]
    mod mock_keys_dir {
        use super::*;

        /// Populate a temp dir with the requested files. `ck.binfile` contents are
        /// never parsed here — `load_mock_keys` only reads bytes; `KeyStore::load`
        /// validates them later in `main`.
        fn keys_dir(client_key: Option<&[u8]>, signer: Option<&[u8]>) -> tempfile::TempDir {
            let dir = tempfile::tempdir().expect("tempdir");
            if let Some(b) = client_key {
                std::fs::write(dir.path().join(COFHE_CLIENT_KEY_FILE), b).expect("write ck");
            }
            if let Some(b) = signer {
                std::fs::write(dir.path().join(COFHE_SIGNER_KEY_FILE), b).expect("write signer");
            }
            dir
        }

        #[test]
        fn loads_client_key_and_signer_from_the_dir() {
            let _g = EnvGuard::new(KEYS);
            let signer_bytes = [7u8; 32];
            let dir = keys_dir(Some(b"client-key-bytes"), Some(&signer_bytes));
            std::env::set_var("MOCK_KEYS_DIR", dir.path());

            let (key_bytes, svc) = load_mock_keys().expect("both keys present");

            assert_eq!(&key_bytes[..], b"client-key-bytes");
            let expected = teecryptor::signing::service::SigningService::from_bytes(
                zeroize::Zeroizing::new(signer_bytes.to_vec()),
            )
            .expect("reference signer");
            assert_eq!(
                svc.evm_address().to_string(),
                expected.evm_address().to_string(),
                "signer must come from the dir, not a throwaway"
            );
        }

        #[test]
        fn missing_signer_fails_instead_of_falling_back() {
            let _g = EnvGuard::new(KEYS);
            let dir = keys_dir(Some(b"client-key-bytes"), None);
            std::env::set_var("MOCK_KEYS_DIR", dir.path());

            let err = match load_mock_keys() {
                Ok(_) => panic!("partial dir must not boot"),
                Err(e) => e,
            };
            assert!(
                format!("{err:#}").contains(COFHE_SIGNER_KEY_FILE),
                "error should name the missing signer file, got: {err:#}"
            );
        }

        #[test]
        fn missing_client_key_fails_instead_of_falling_back() {
            let _g = EnvGuard::new(KEYS);
            let dir = keys_dir(None, Some(&[7u8; 32]));
            std::env::set_var("MOCK_KEYS_DIR", dir.path());

            let err = match load_mock_keys() {
                Ok(_) => panic!("partial dir must not boot"),
                Err(e) => e,
            };
            assert!(
                format!("{err:#}").contains(COFHE_CLIENT_KEY_FILE),
                "error should name the missing ClientKey file, got: {err:#}"
            );
        }

        /// A non-UTF-8 path is a real value, not "unset" — it must fail rather
        /// than quietly boot throwaway keys.
        #[cfg(unix)]
        #[test]
        fn non_utf8_dir_is_not_treated_as_unset() {
            use std::os::unix::ffi::OsStrExt;
            let _g = EnvGuard::new(KEYS);
            let bad = std::ffi::OsStr::from_bytes(b"/tmp/teecryptor-\xff-not-utf8");
            std::env::set_var("MOCK_KEYS_DIR", bad);

            match load_mock_keys() {
                Ok(_) => panic!("a non-UTF-8 dir must not fall back to throwaway keys"),
                Err(e) => assert!(
                    format!("{e:#}").contains(COFHE_CLIENT_KEY_FILE),
                    "should fail reading the ClientKey under that dir, got: {e:#}"
                ),
            }
        }

        #[test]
        fn empty_value_is_treated_as_unset() {
            let _g = EnvGuard::new(KEYS);
            std::env::set_var("MOCK_KEYS_DIR", "");

            // Falls through to the self-contained path rather than trying to read
            // "/ck.binfile" off the filesystem root.
            let (key_bytes, _svc) = load_mock_keys().expect("throwaway path");
            assert!(
                !key_bytes.is_empty(),
                "throwaway ClientKey must be produced"
            );
        }
    }

    /// One permit chain — enough to satisfy the (baked-on) permit gate so a test
    /// can reach later checks. Non-secret stub values. Only the real-boot-path
    /// tests use it; mock builds source the gates from env.
    #[cfg(not(feature = "mock"))]
    const STUB_CHAINS: &str = r#"{"1":{"rpc_url":"http://x"}}"#;

    /// A minimal valid non-mock boot: COFHE_ENV=testnet + a stub permit chain
    /// (permit gate is baked ON in every env) + a CT source + a stub registry RPC.
    ///
    /// The registry RPC is part of the baseline because the commitment gate is now
    /// baked ON for every env, so a boot without it fail-closes.
    #[cfg(not(feature = "mock"))]
    fn set_valid_testnet_baseline() {
        std::env::set_var("COFHE_ENV", "testnet");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        std::env::set_var("COMMITMENT_REGISTRY_RPC_URL", "http://x");
    }

    /// Assert `Config::from_env()` errors and its anyhow chain mentions `needle`.
    fn assert_from_env_errors_with(needle: &str) {
        match Config::from_env() {
            Ok(_) => panic!("expected error mentioning {needle:?}"),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(msg.contains(needle), "expected {needle:?}, got: {msg}");
            }
        }
    }

    // These tests exercise the baked per-env policy + fail-closed selector, which
    // only exist in the real boot path (`#[cfg(not(feature = "mock"))]`).

    /// The baked-environment selector is REQUIRED — no default env.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_env_required() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("CT_SOURCE_URL", "http://x");
        // COFHE_ENV deliberately unset.
        assert_from_env_errors_with("COFHE_ENV");
    }

    /// COFHE_ENV=staging resolves the compiled-in source (5 partners + bucket/object)
    /// AND the baked security policy (permit + commitment gates ON). Both RPC
    /// inputs are stubbed so boot succeeds.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_env_staging_resolves_baked_source_and_policy() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "staging");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        std::env::set_var("COMMITMENT_REGISTRY_RPC_URL", "http://x");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.env, "staging");
        assert_eq!(cfg.env_cfg.partners.len(), 5);
        assert_eq!(cfg.env_cfg.partners[0].project_id, "cofhe-tee-partner-1");
        assert_eq!(cfg.env_cfg.public_bucket, "localcofhenix");
        assert_eq!(
            cfg.env_cfg.public_object,
            "generator/keys/versionized/0/public-material"
        );
        assert_eq!(cfg.threshold, 2);
        // Baked staging policy: both gates on.
        assert!(cfg.require_permit);
        assert!(cfg.enable_commitment_verification);
        assert!(cfg.commitment_verifier.is_some());
    }

    /// COFHE_ENV=mainnet resolves the baked source — six key-share holders, threshold 3
    /// — AND the baked policy: permit ON, commitment baked ON and ENFORCING (v1) with a
    /// TBD registry address. Mainnet fail-closes at boot until COMMITMENT_REGISTRY_RPC_URL
    /// is set.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_env_mainnet_resolves_baked_source_and_policy() {
        // Source (partners / bucket / T) resolves from the baked cofhe-keys map.
        let src = cofhe_keys::reader::lookup("mainnet").expect("baked mainnet source");
        assert_eq!(src.partners.len(), 6);
        assert_eq!(src.partners[0].project_id, "fhenix-507307");
        assert_eq!(src.public_bucket, "fhenix-mainnet-keys");
        assert_eq!(
            src.public_object,
            "generator/keys/versionized/0/public-material"
        );
        assert_eq!(src.shamir_threshold, 3); // must match the keygen var-file's split

        // Policy resolves: permit on, commitment baked ON + ENFORCING (v1), with the
        // registry address a TBD placeholder until the mainnet contract is deployed.
        let p = env_policy::EnvPolicy::for_env("mainnet").expect("baked mainnet policy");
        assert!(p.require_permit);
        assert!(p.enable_commitment_verification);
        let c = p.commitment.expect("mainnet has a [commitment] block");
        assert_eq!(
            c.version,
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(c.registry_address, "TBD");
        assert!(!c.warning_instead_of_enforcement);

        // Because commitment is baked ON but the registry RPC is env-supplied, a mainnet
        // boot FAIL-CLOSES until COMMITMENT_REGISTRY_RPC_URL is set — mainnet teecryptor
        // is intentionally not deployable until the contract is live and the RPC lands.
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "mainnet");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        assert_from_env_errors_with("COMMITMENT_REGISTRY_RPC_URL");
    }

    /// FAIL-CLOSED: a COFHE_ENV outside the baked map aborts at boot (the key-source
    /// lookup rejects it first), before any network call — no default, no fallback.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_env_unknown_fails_closed() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "bogus");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        assert_from_env_errors_with("unknown environment");
    }

    /// The threshold is now a baked constant, so its bounds are validated
    /// directly (no env to drive them). Floor = vsss min (2); ceiling = partners.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn validate_threshold_bounds() {
        assert!(validate_threshold(2, 5).is_ok());
        assert!(validate_threshold(5, 5).is_ok());
        let too_high = format!("{:#}", validate_threshold(6, 5).unwrap_err());
        assert!(
            too_high.contains("exceeds the number of partners"),
            "{too_high}"
        );
        let too_low = format!("{:#}", validate_threshold(1, 5).unwrap_err());
        assert!(too_low.contains("must be >= 2"), "{too_low}");
    }

    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_missing_ct_source_url_errors() {
        let _g = EnvGuard::new(KEYS);
        // Full valid baseline minus CT_SOURCE_URL, so the assertion isolates that
        // failure. Building the env by hand here would trip the (baked-on)
        // commitment gate first, which is a different error.
        set_valid_testnet_baseline();
        std::env::remove_var("CT_SOURCE_URL");
        assert_from_env_errors_with("CT_SOURCE_URL");
    }

    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_defaults_apply_when_only_required_set() {
        let _g = EnvGuard::new(KEYS);
        set_valid_testnet_baseline();
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.ct_source_url, "http://x");
        assert_eq!(cfg.getct_timeout, Duration::from_millis(5000));
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.metrics_addr, "0.0.0.0:9090");
    }

    /// Baked fail-closed permit gate: COFHE_ENV=testnet bakes require_permit=true, so a
    /// missing PERMIT_CHAINS_JSON must bail — no open decryptor by omission.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_permit_on_by_default_requires_permit_chains() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "testnet");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        // PERMIT_CHAINS_JSON deliberately unset.
        assert_from_env_errors_with("PERMIT_CHAINS_JSON");
    }

    /// GETCT_TIMEOUT_MS is parsed before the selector, so a bad value errors
    /// regardless of COFHE_ENV — no baseline needed.
    #[test]
    fn config_bad_getct_timeout_errors() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("GETCT_TIMEOUT_MS", "not-a-number");
        assert_from_env_errors_with("GETCT_TIMEOUT_MS");
    }

    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_concurrency_defaults_and_overrides() {
        let _g = EnvGuard::new(KEYS);
        set_valid_testnet_baseline();

        // Defaults: MAX_INFLIGHT = 1000, decrypt_concurrency = available (>= 1).
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.max_inflight, 1000);
        assert!(cfg.decrypt_concurrency >= 1);

        // Overrides take effect.
        std::env::set_var("DECRYPT_CONCURRENCY", "4");
        std::env::set_var("MAX_INFLIGHT", "2000");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.decrypt_concurrency, 4);
        assert_eq!(cfg.max_inflight, 2000);
    }

    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_custom_overrides_take_effect() {
        let _g = EnvGuard::new(KEYS);
        set_valid_testnet_baseline();
        std::env::set_var("GETCT_TIMEOUT_MS", "1234");
        std::env::set_var("BIND_ADDR", "127.0.0.1:9999");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.getct_timeout, Duration::from_millis(1234));
        assert_eq!(cfg.bind_addr, "127.0.0.1:9999");
    }

    // ---------- PERMIT_CHAINS_JSON parser (env-supplied) ------------------
    // The chains map carries API-keyed RPC URLs, so it stays env; the parser is
    // tested directly rather than through the (baked) permit gate.

    #[test]
    fn permit_chains_unset_yields_none() {
        let _g = EnvGuard::new(KEYS);
        assert!(parse_permit_chains().expect("parse").is_none());
    }

    #[test]
    fn permit_chains_multi_chain_parses() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var(
            "PERMIT_CHAINS_JSON",
            r#"{
                "1":      { "rpc_url": "https://eth.example", "timeout_ms": 7000 },
                "420105": { "rpc_url": "http://localhost:8545" }
            }"#,
        );
        let verifier = parse_permit_chains()
            .expect("parse")
            .expect("acp_verifier present");
        assert_eq!(verifier.len(), 2);

        let eth = verifier.get(1).expect("chain 1 present");
        assert_eq!(eth.rpc_url, "https://eth.example");
        assert_eq!(eth.timeout, Duration::from_millis(7000));
        // TaskManager comes from the baked constant, not the env JSON.
        assert_eq!(eth.task_manager, TASK_MANAGER);

        let local = verifier.get(420105).expect("chain 420105 present");
        assert_eq!(local.rpc_url, "http://localhost:8545");
        // timeout default = 5000ms when omitted
        assert_eq!(local.timeout, Duration::from_millis(5000));

        // A chain not in the map is None.
        assert!(verifier.get(999_999).is_none());
    }

    #[test]
    fn permit_chains_empty_object_yields_none() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("PERMIT_CHAINS_JSON", "{}");
        assert!(parse_permit_chains().expect("parse").is_none());
    }

    #[test]
    fn permit_chains_bad_chain_id_errors() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var(
            "PERMIT_CHAINS_JSON",
            r#"{ "not-a-number": { "rpc_url": "http://x" } }"#,
        );
        let e = format!("{:#}", parse_permit_chains().unwrap_err());
        assert!(e.contains("not a u64"), "{e}");
    }

    // ---------- commitment verifier (baked policy + env RPC) --------------

    /// Baked fail-closed commitment gate: COFHE_ENV=staging bakes enable_commitment_verification=
    /// true, so a missing registry RPC must bail.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_commitment_on_by_default_requires_registry() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "staging");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        // COMMITMENT_REGISTRY_RPC_URL deliberately unset.
        assert_from_env_errors_with("COMMITMENT_REGISTRY");
    }

    /// COFHE_ENV=staging: the registry ADDRESS + VERSION come from the baked policy;
    /// only the (API-keyed) RPC URL is env-supplied. The baked version is the
    /// canonical 0x + 64 hex digits, whose last byte is 0x02.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_commitment_uses_baked_address_and_version() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "staging");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        std::env::set_var("COMMITMENT_REGISTRY_RPC_URL", "http://localhost:8545");
        let cfg = Config::from_env().expect("from_env");
        let cv = cfg
            .commitment_verifier
            .expect("commitment_verifier present");
        assert_eq!(cv.rpc_url, "http://localhost:8545");
        // Baked staging version is canonical; its last byte is 0x02.
        assert_eq!(cv.version[31], 0x02);
        // Registry ADDRESS comes from the baked policy (not env) — assert the exact
        // staging address so a wrong/edited toml is caught here (compare lowercased to
        // sidestep EIP-55 checksum casing).
        assert_eq!(
            cv.registry.to_string().to_lowercase(),
            "0x8045cb9b8b179139181b5d6129d1556b7a5a4c48"
        );
        // staging bakes warning_instead_of_enforcement=true → the verifier runs in
        // warn-only (log-and-allow) mode.
        assert!(cv.warn_only());
    }

    /// COMMITMENT_TIMEOUT_MS below the 50ms floor must bail at boot — a
    /// (near-)zero timeout would otherwise fail every registry call at runtime.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_commitment_timeout_below_floor_bails() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COFHE_ENV", "staging");
        std::env::set_var("CT_SOURCE_URL", "http://x");
        std::env::set_var("PERMIT_CHAINS_JSON", STUB_CHAINS);
        std::env::set_var("COMMITMENT_REGISTRY_RPC_URL", "http://localhost:8545");
        std::env::set_var("COMMITMENT_TIMEOUT_MS", "0");
        assert_from_env_errors_with("COMMITMENT_TIMEOUT_MS");
    }

    /// COFHE_ENV=testnet bakes the commitment gate ON in warn-only mode: the
    /// verifier is installed (so the gate runs and logs) and the baked policy says
    /// log-and-allow rather than block.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn config_testnet_bakes_commitment_warn_only() {
        let _g = EnvGuard::new(KEYS);
        set_valid_testnet_baseline();
        let cfg = Config::from_env().expect("from_env");
        assert!(cfg.enable_commitment_verification);
        assert!(cfg.commitment_verifier.is_some());
        assert!(cfg.require_permit);
        let p = env_policy::EnvPolicy::for_env("testnet").expect("testnet policy");
        assert!(
            p.commitment
                .expect("testnet has a [commitment] block")
                .warning_instead_of_enforcement
        );
    }

    /// A policy with no `[commitment]` block must reject a stray
    /// `COMMITMENT_REGISTRY_RPC_URL` rather than silently ignore it — the operator
    /// is told their config can't be honored.
    ///
    /// Driven through `parse_commitment_config` with a hand-built policy rather
    /// than a baked env: every baked env now enables the gate, so no `COFHE_ENV`
    /// value reaches this branch. It stays reachable on the mock path and for any
    /// future commitment-OFF env, so it keeps its test.
    #[cfg(not(feature = "mock"))]
    #[test]
    fn commitment_off_policy_rejects_stray_registry_rpc() {
        let _g = EnvGuard::new(KEYS);
        std::env::set_var("COMMITMENT_REGISTRY_RPC_URL", "http://x");
        let policy = env_policy::EnvPolicy {
            require_permit: true,
            enable_commitment_verification: false,
            commitment: None,
        };
        let err = parse_commitment_config(&policy).expect_err("expected a fail-closed error");
        let msg = format!("{err:#}");
        assert!(msg.contains("no [commitment] policy is baked"), "{msg}");
    }
}
