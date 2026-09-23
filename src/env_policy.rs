//! Per-environment security policy, baked into the binary.
//!
//! `REQUIRE_PERMIT`, `REQUIRE_COMMITMENT`, `COMMITMENT_WARN_ONLY`,
//! `COMMITMENT_VERSION`, and `COMMITMENT_REGISTRY_ADDRESS` used to be operator-set
//! env vars. Confidential Space lets an operator override any var listed in the
//! image's `allow_env_override` LABEL, and the partner CEL attests only the image
//! digest — never the env — so an operator could weaken the permit/commitment gates
//! without breaking attestation. These values are now selected by `COFHE_ENV`
//! (exactly like cofhe-keys' key SOURCE) from a file compiled into the binary with
//! `include_str!`, so their bytes are part of the attested image digest and changing
//! policy requires a rebuild + partner re-pin (explicit consent). The Shamir
//! threshold (was `SHAMIR_THRESHOLD`) is baked too, but in the shared cofhe-keys env
//! map — one source shared with the producer + the other consumers, not here.
//!
//! What deliberately stays env-supplied: the RPC endpoints
//! (`COMMITMENT_REGISTRY_RPC_URL`, `PERMIT_CHAINS_JSON`) carry API keys that must
//! not be embedded in a publicly-pullable image.

use anyhow::{Context, Result};
use serde::Deserialize;

/// The per-environment constants baked into the image. Every environment has the
/// same top-level shape; the commitment gate's detail travels as one optional
/// sub-table, present iff that environment turns the gate on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvPolicy {
    /// Fail-closed ACL master switch (was `REQUIRE_PERMIT`).
    pub require_permit: bool,
    /// Fail-closed commitment master switch (was `REQUIRE_COMMITMENT`).
    pub enable_commitment_verification: bool,
    /// Commitment-gate detail. Present iff `enable_commitment_verification` — an env with the
    /// gate off carries no `[commitment]` block (the registry it would point at
    /// isn't deployed there). The registry *RPC URL* stays env-supplied
    /// (API-keyed); only the public address/version/avoid-enforcement are baked.
    #[serde(default)]
    pub commitment: Option<CommitmentPolicy>,
    /// OTLP push of metrics to the compiled-in Telemetry endpoint. Defaults to
    /// on; an env opts out with `metrics_push = false`. Baked rather than an env
    /// var so an operator cannot silence monitoring on an attested image.
    #[serde(default = "default_true")]
    pub metrics_push: bool,
}

fn default_true() -> bool {
    true
}

/// The baked commitment-gate detail (non-secret; the API-keyed RPC URL is env).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentPolicy {
    /// Canonical commitment version: `0x` + 64 hex digits, byte-identical to
    /// the registry key. Validated by `parse_version`; short forms are refused.
    pub version: String,
    /// `CommitmentRegistry` contract address (was `COMMITMENT_REGISTRY_ADDRESS`).
    pub registry_address: String,
    /// Run the gate but log-and-allow instead of blocking on a commitment
    /// failure — for gradual rollout (was `COMMITMENT_WARN_ONLY`).
    #[serde(default)]
    pub warning_instead_of_enforcement: bool,
}

impl EnvPolicy {
    /// Resolve the baked policy for `env`. FAIL-CLOSED: an env with no baked
    /// policy is a hard error — mirrors `cofhe_keys::reader::lookup`, so the set
    /// of known envs stays in lockstep with the baked key SOURCE.
    #[cfg(not(feature = "mock"))]
    pub fn for_env(env: &str) -> Result<Self> {
        let raw = match env {
            "staging" => include_str!("envs/staging.toml"),
            "testnet" => include_str!("envs/testnet.toml"),
            "mainnet" => include_str!("envs/mainnet.toml"),
            other => anyhow::bail!(
                "no baked security policy for COFHE_ENV={other:?} \
                 (fail-closed; add src/envs/{other}.toml)"
            ),
        };
        let policy: EnvPolicy =
            toml::from_str(raw).with_context(|| format!("parsing baked env policy for {env:?}"))?;
        // The commitment switch and the presence of a [commitment] block must
        // agree — no on-gate without config, no stray config while off.
        if policy.enable_commitment_verification != policy.commitment.is_some() {
            anyhow::bail!(
                "baked policy for {env:?}: enable_commitment_verification={} but the [commitment] block is {}",
                policy.enable_commitment_verification,
                if policy.commitment.is_some() {
                    "present"
                } else {
                    "missing"
                }
            );
        }
        Ok(policy)
    }

    /// Mock builds keep sourcing these knobs from the environment, so the local
    /// `docker-compose` stack (`REQUIRE_PERMIT=false`, `ENABLE_COMMITMENT_VERIFICATION=false`,
    /// …) is unaffected. The real boot path never takes this route.
    ///
    /// `COMMITMENT_REGISTRY_ADDRESS_FILE` takes precedence over
    /// `COMMITMENT_REGISTRY_ADDRESS`: a local stack deploys the registry as part
    /// of itself, so the address does not exist yet when compose interpolates
    /// env, and the proxy lands at `f(deployer, nonce)` — it moves whenever the
    /// contracts deploy sequence changes. Reading the address the deployer wrote
    /// keeps the two in lockstep across `cofhe-contracts` bumps, which a
    /// hardcoded compose default cannot.
    #[cfg(feature = "mock")]
    pub fn from_env_mock() -> Result<Self> {
        fn flag(key: &str, default: &str) -> Result<bool> {
            std::env::var(key)
                .unwrap_or_else(|_| default.to_string())
                .parse()
                .with_context(|| format!("{key} must be `true` or `false`"))
        }
        // Empty means unset, as with MOCK_KEYS_DIR: compose passes a var through
        // as the empty string to disable it (`${VAR:-}`), which is how the local
        // stack turns the address file off to pin an address by hand.
        fn non_empty(key: &str) -> Option<String> {
            std::env::var(key).ok().filter(|v| !v.is_empty())
        }
        let enable_commitment_verification = flag("ENABLE_COMMITMENT_VERIFICATION", "true")?;
        // The [commitment] block is present iff the gate is on — the SAME invariant
        // `for_env` enforces on the baked path. (Sourcing the block on a stray address
        // while the gate is off would build the enable=false + commitment=Some state
        // that `for_env` rejects as impossible.)
        let commitment = if enable_commitment_verification {
            Some(CommitmentPolicy {
                version: std::env::var("COMMITMENT_VERSION").unwrap_or_else(|_| {
                    "0x0000000000000000000000000000000000000000000000000000000000000002".to_string()
                }),
                registry_address: resolve_registry_address(
                    non_empty("COMMITMENT_REGISTRY_ADDRESS_FILE").as_deref(),
                    non_empty("COMMITMENT_REGISTRY_ADDRESS").as_deref(),
                )?,
                warning_instead_of_enforcement: flag(
                    "COMMITMENT_WARNING_INSTEAD_OF_ENFORCEMENT",
                    "false",
                )?,
            })
        } else {
            None
        };
        Ok(Self {
            require_permit: flag("REQUIRE_PERMIT", "true")?,
            enable_commitment_verification,
            commitment,
            // Mock builds never push (no VM identity); the value is unused there.
            metrics_push: false,
        })
    }
}

/// Resolve the mock registry address from the file path, else the literal.
///
/// Takes both values rather than reading the environment so the precedence and
/// the failure messages are testable without mutating process-global env.
///
/// Every failure names the variable that would fix it: an empty or absent
/// address otherwise surfaces from the caller as "must be a 0x-prefixed
/// Ethereum address", which blames the value instead of the missing wiring.
#[cfg(feature = "mock")]
fn resolve_registry_address(file: Option<&str>, literal: Option<&str>) -> Result<String> {
    let Some(path) = file else {
        return literal.map(str::to_string).context(
            "the commitment gate is on but neither COMMITMENT_REGISTRY_ADDRESS \
             nor COMMITMENT_REGISTRY_ADDRESS_FILE is set",
        );
    };
    let address = std::fs::read_to_string(path)
        .with_context(|| {
            format!(
                "COMMITMENT_REGISTRY_ADDRESS_FILE {path} is unreadable — is the deployments \
                 volume mounted and contracts-deployer finished?"
            )
        })?
        .trim()
        .to_string();
    if address.is_empty() {
        anyhow::bail!("COMMITMENT_REGISTRY_ADDRESS_FILE {path} is empty");
    }
    Ok(address)
}

#[cfg(all(test, feature = "mock"))]
mod mock_tests {
    use super::*;

    const ADDRESS: &str = "0x2F7F4Ea04A0213C114b1070909a7f70cbaB2A909";

    /// `contracts-deployer` writes the address with no trailing newline, but a
    /// hand-edited file or a `echo >` redirect has one.
    #[test]
    fn file_contents_are_trimmed() {
        let dir = std::env::temp_dir().join("tc-regaddr-trim");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("address.txt");
        std::fs::write(&path, format!("{ADDRESS}\n")).unwrap();

        let got = resolve_registry_address(Some(path.to_str().unwrap()), None).unwrap();

        assert_eq!(got, ADDRESS);
    }

    /// The file wins even when a stale literal is also set — that stale compose
    /// default is exactly what this path exists to stop honouring.
    #[test]
    fn file_takes_precedence_over_the_literal() {
        let dir = std::env::temp_dir().join("tc-regaddr-precedence");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("address.txt");
        std::fs::write(&path, ADDRESS).unwrap();

        let got = resolve_registry_address(Some(path.to_str().unwrap()), Some("0xstale")).unwrap();

        assert_eq!(got, ADDRESS);
    }

    #[test]
    fn falls_back_to_the_literal_when_no_file_is_given() {
        let got = resolve_registry_address(None, Some(ADDRESS)).unwrap();

        assert_eq!(got, ADDRESS);
    }

    /// Fails closed rather than falling back: a set-but-unreadable file means
    /// the volume is missing or the deployer has not finished, and silently
    /// using a stale literal would reintroduce the bug this path fixes.
    #[test]
    fn a_missing_file_is_an_error_naming_the_variable() {
        let err = resolve_registry_address(Some("/nonexistent/address.txt"), Some(ADDRESS))
            .expect_err("an unreadable file must not fall back");

        assert!(err
            .to_string()
            .contains("COMMITMENT_REGISTRY_ADDRESS_FILE /nonexistent/address.txt"));
    }

    /// The deployer creates the file before writing it, so a race or a failed
    /// deploy can leave it empty.
    #[test]
    fn an_empty_file_is_an_error() {
        let dir = std::env::temp_dir().join("tc-regaddr-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("address.txt");
        std::fs::write(&path, "  \n").unwrap();

        let err = resolve_registry_address(Some(path.to_str().unwrap()), None)
            .expect_err("an empty file must not pass through");

        assert!(err.to_string().contains("is empty"));
    }

    #[test]
    fn neither_source_is_an_error_naming_both_variables() {
        let err = resolve_registry_address(None, None).expect_err("no source must fail");

        let msg = err.to_string();
        assert!(msg.contains("COMMITMENT_REGISTRY_ADDRESS"));
        assert!(msg.contains("COMMITMENT_REGISTRY_ADDRESS_FILE"));
    }
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;

    #[test]
    fn staging_policy_matches_baked_values() {
        let p = EnvPolicy::for_env("staging").expect("staging policy");
        assert!(p.require_permit);
        assert!(p.enable_commitment_verification);
        let c = p.commitment.expect("staging has a [commitment] block");
        assert_eq!(
            c.version,
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(
            c.registry_address,
            "0x8045cb9b8b179139181b5d6129D1556B7a5a4C48"
        );
        assert!(c.warning_instead_of_enforcement);
        assert!(!p.metrics_push);
    }

    #[test]
    fn metrics_push_defaults_on() {
        assert!(EnvPolicy::for_env("testnet").unwrap().metrics_push);
        assert!(EnvPolicy::for_env("mainnet").unwrap().metrics_push);
    }

    #[test]
    fn testnet_policy_is_commitment_warn_only() {
        let p = EnvPolicy::for_env("testnet").expect("testnet policy");
        assert!(p.require_permit);
        assert!(p.enable_commitment_verification);
        let c = p.commitment.expect("testnet has a [commitment] block");
        assert_eq!(
            c.version,
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(
            c.registry_address,
            "0x4ed29DD2bda5055ADaB10ff63f5556F6774e7D9F"
        );
        // Rollout posture: the gate runs and logs, but never blocks a decrypt.
        // Version 1 is still Active on that registry and holds most of the
        // history, so pre-cutover handles miss under version 2.
        assert!(c.warning_instead_of_enforcement);
    }

    /// FAIL-CLOSED: an env with no baked policy is rejected — same posture as the
    /// key-source `lookup`, so the two never drift apart silently.
    #[test]
    fn unknown_env_fails_closed() {
        // mainnet is now a baked env (rehearsal); genuinely-unknown envs still fail.
        assert!(EnvPolicy::for_env("mainnet").is_ok());
        assert!(EnvPolicy::for_env("prod").is_err());
        assert!(EnvPolicy::for_env("").is_err());
    }

    /// Lockstep with the baked key SOURCE: every env in the shared `cofhe-keys`
    /// map must have a matching baked security policy here. Driving the loop off
    /// `cofhe_keys::reader::env_names()` (the same list the reader resolves) means a
    /// new env added there can't ship without a policy — this test fails first.
    #[test]
    fn for_env_covers_every_baked_key_env() {
        for name in cofhe_keys::reader::env_names() {
            assert!(
                EnvPolicy::for_env(name).is_ok(),
                "cofhe-keys bakes env {name:?} but there is no matching security policy"
            );
        }
    }
}
