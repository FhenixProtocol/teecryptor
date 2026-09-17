//! On-chain **commitment** enforcement: before decrypting/sealing a handle,
//! confirm the FHE engine actually posted a commitment for it in cofhe's
//! `CommitmentRegistry`, and that the commitment **matches the ciphertext
//! bytes** fetched from ct-server. A missing commitment means the ciphertext
//! was never legitimately produced-and-committed by the engine; a mismatching
//! one means ct-server served bytes the engine never committed to — both
//! refuse the decrypt. There is deliberately no partial mode: `REQUIRE_COMMITMENT`
//! is the single switch, and when it's on the gate enforces existence **and**
//! integrity.
//!
//! This mirrors [`crate::permit`] structurally (pooled alloy provider built
//! once at boot, bounded-timeout `eth_call`, error enum → HTTP mapping) but
//! differs in one important way: the `CommitmentRegistry` is a **single
//! chain-agnostic contract** (its own registry chain — Arbitrum in prod,
//! co-located on devnet), NOT one contract per host chain. Commitments are
//! keyed by `(version, handle)` only — `getCommitment(bytes32 version,
//! bytes32 handle)` — so there is exactly one endpoint + address + version
//! here, and the caller's `host_chain_id` is used only for the local cache
//! key, never sent on the wire. (This is also why the ACL check and the
//! commitment check cannot be collapsed into one `eth_call` — they live on
//! different chains.)
//!
//! ## What the commitment is
//!
//! The engine posts `keccak256(ct_data)` per handle (commitment v2) — see cofhe
//! `fhe-engine/src/types.rs` (`calc_commitment`). [`calc_commitment`] reproduces
//! that formula byte-for-byte so the HTTP layer can compare the on-chain value
//! against the ciphertext it actually fetched. The security zone is NOT in the
//! value; it is bound by the handle's byte 31 (the on-chain lookup key).
//! Getting the formula wrong fails closed (every decrypt 502s), so it must stay
//! in lockstep with the engine.
//!
//! ## Performance
//!
//! A posted commitment is **immutable** (the registry is write-once — see
//! `CommitmentRegistry.postCommitments`), so a "present" answer stays true for
//! as long as the registry it came from does, and the hash is cached — repeat
//! handles skip the RPC entirely. Absent answers are deliberately NOT cached:
//! caching attacker-chosen keys would let random-handle spam evict the warm
//! positive entries, and a pending commitment should be picked up the moment it
//! lands. The cost is one registry `eth_call` per poll of a still-pending
//! handle, which the registry-side RPC (or an eRPC cache in front of it)
//! absorbs.
//!
//! Positive entries carry a **TTL** (`COMMITMENT_CACHE_TTL_SECS`) on top of the
//! LRU capacity, because "immutable on-chain" only holds while the chain does:
//! on a non-production environment the chain and registry get wiped and
//! redeployed under a long-lived teecryptor process, and a never-expiring cache
//! then serves pre-reset hashes forever — every decrypt of a
//! previously-seen handle fails the integrity gate with `commitment_mismatch`
//! even though the fresh registry holds the right value. The TTL bounds how
//! long that can last, and [`refresh_commitment`] (driven by the integrity
//! check on mismatch) fixes it on the first affected request.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use lru::LruCache;
use thiserror::Error;

// cofhe's CommitmentRegistry Hardhat artifact under `abi/`: the `abi` array is
// verbatim from cofhe (the chain-agnostic interface), but `bytecode` /
// `deployedBytecode` are intentionally blanked to `0x` — teecryptor only reads
// the contract, and the `sol!` macro consumes only the `abi` array (same as
// TaskManager/ACL in `permit.rs`). See the compatibility doc in the gitops repo for the sync procedure.
#[allow(missing_docs)]
mod abi_loader {
    use alloy::sol;
    sol!(
        #[sol(rpc)]
        #[derive(Debug)]
        ICommitmentRegistry,
        "abi/CommitmentRegistry.json"
    );
}
pub use abi_loader::ICommitmentRegistry;

/// Mirror of `CommitmentRegistry.VersionStatus` (discriminants pin the enum
/// order from `CommitmentRegistry.sol`). `Active` is the only status under
/// which the poster can land commitments for a given version; anything else at
/// boot almost certainly means a misconfigured `COMMITMENT_VERSION`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    /// Version was never registered.
    Unset = 0,
    /// Version is live — the poster can land commitments under it.
    Active = 1,
    /// Version was superseded; existing commitments remain readable.
    Deprecated = 2,
    /// Version was revoked; commitments under it must not be trusted.
    Revoked = 3,
}

impl VersionStatus {
    /// Decode the registry's on-chain `uint8`; `None` for values this build
    /// doesn't know (a registry newer than us).
    pub fn from_u8(status: u8) -> Option<Self> {
        [Self::Unset, Self::Active, Self::Deprecated, Self::Revoked]
            .into_iter()
            .find(|s| *s as u8 == status)
    }

    /// Human-readable name for logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unset => "Unset",
            Self::Active => "Active",
            Self::Deprecated => "Deprecated",
            Self::Revoked => "Revoked",
        }
    }

    /// [`Self::name`] for a raw on-chain value, with undecodable values
    /// (see [`Self::from_u8`]) rendered as `"Unknown"` instead of erroring —
    /// boot logging must not fail on a registry newer than this build.
    pub fn name_of(status: u8) -> &'static str {
        Self::from_u8(status).map_or("Unknown", Self::name)
    }
}

/// Errors from commitment verification. The HTTP layer maps each to a stable
/// `error` code + status; nothing internal is leaked to callers.
#[derive(Debug, Error)]
pub enum CommitmentError {
    /// `getCommitment` returned `bytes32(0)` — no commitment for this handle.
    /// May be transient (the poster hasn't landed it yet) or permanent (the
    /// handle was never legitimately computed). The HTTP layer treats it as
    /// retryable so a lagging commitment naturally resolves on re-submit.
    #[error("commitment not found on-chain")]
    NotFound,
    /// The verifier is not configured (bad RPC URL or registry address).
    #[error("commitment verifier not configured: {0}")]
    Misconfigured(String),
    /// The RPC call to the registry exceeded its timeout.
    #[error("commitment verifier timed out after {0:?}")]
    Timeout(Duration),
    /// Any other failure on the RPC path (transport, contract decode, etc).
    #[error("commitment verifier transport error: {0}")]
    Transport(String),
}

/// One positive cache entry: the on-chain commit hash plus when it was read, so
/// [`CommitmentConfig::get_from_cache`] can expire it (see the module docs on
/// why "immutable" is not "eternal").
#[derive(Clone, Copy)]
struct CacheEntry {
    commit: FixedBytes<32>,
    stored_at: Instant,
}

/// `(host_chain_id, handle) -> ` [`CacheEntry`], LRU-bounded by
/// `COMMITMENT_CACHE_SIZE`.
type CommitmentCache = LruCache<(u64, U256), CacheEntry>;

/// Result of a commitment lookup: the hash, plus whether it came from the local
/// cache. Callers use `from_cache` to tell a genuine integrity failure from a
/// cache that outlived the registry it was populated from — see
/// [`refresh_commitment`].
#[derive(Debug, Clone, Copy)]
pub struct FetchedCommitment {
    /// The commit hash to compare the fetched ciphertext bytes against.
    pub hash: FixedBytes<32>,
    /// True when `hash` was served from the local cache (no RPC this call).
    pub from_cache: bool,
}

/// Verifier config for the single commitment registry. The alloy `provider` is
/// built **once** here (fail-fast on a bad URL) and cloned per call — a cheap
/// `Arc` bump that reuses the warm connection pool, same rationale as
/// [`crate::permit::ChainConfig`]. Cloning the whole config shares the same
/// provider pool **and** the same cache (both behind `Arc`).
#[derive(Clone)]
pub struct CommitmentConfig {
    /// JSON-RPC endpoint of the registry chain.
    pub rpc_url: String,
    /// Deployed `CommitmentRegistry` address on the registry chain.
    pub registry: Address,
    /// The `bytes32` commitment version to query — must equal the engine's
    /// `COMMITMENT_VERSION` (see [`parse_version`]). Configured, not hard-coded,
    /// because the engine bumps it when FHE params change.
    pub version: FixedBytes<32>,
    /// Bounds the RPC round-trip; a slow registry must not wedge `/decrypt`.
    pub timeout: Duration,
    /// Warn-only (gradual-rollout) mode: when true the gate still runs and
    /// logs, but a commitment failure (missing, mismatched, or RPC error) is a
    /// WARN + allow instead of a block. Set from the baked per-env
    /// `warning_instead_of_enforcement` policy; default false (enforce). Flip it
    /// back to false (and rebuild) once the warn logs are clean.
    warn_only: bool,
    /// Pre-bound contract instance (address + pooled provider), built once in
    /// [`CommitmentConfig::new`]. The instance itself is a stateless wrapper —
    /// the connection pool lives in the provider inside it — but binding it
    /// once saves the per-call construction and keeps call sites clean.
    contract: ICommitmentRegistry::ICommitmentRegistryInstance<DynProvider>,
    /// How long a cached positive entry stays valid. Set via
    /// `COMMITMENT_CACHE_TTL_SECS`; bounds staleness across an environment
    /// (chain + registry) redeploy under a long-lived process.
    cache_ttl: Duration,
    /// `(host_chain_id, handle) -> commit hash` cache. Only positive results
    /// are stored (commitments are write-once); absent results are never
    /// cached — see the module docs.
    cache: Arc<Mutex<CommitmentCache>>,
}

impl std::fmt::Debug for CommitmentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitmentConfig")
            .field("rpc_url", &self.rpc_url)
            .field("registry", &self.registry)
            .field("version", &self.version)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl CommitmentConfig {
    /// Build the verifier config, constructing the pooled provider once so it's
    /// reused across requests. A bad `rpc_url` fails here (at boot), not on the
    /// first `/decrypt`.
    pub fn new(
        rpc_url: String,
        registry: Address,
        version: FixedBytes<32>,
        timeout: Duration,
        cache_size: NonZeroUsize,
        cache_ttl: Duration,
    ) -> Result<Self, CommitmentError> {
        let url = rpc_url
            .parse()
            .map_err(|e| CommitmentError::Misconfigured(format!("rpc_url parse: {e}")))?;
        let provider = ProviderBuilder::new().connect_http(url).erased();
        Ok(Self {
            rpc_url,
            registry,
            version,
            timeout,
            warn_only: false,
            contract: ICommitmentRegistry::new(registry, provider),
            cache_ttl,
            cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        })
    }

    /// Builder: put the gate in warn-only (gradual-rollout) mode — see the
    /// `warn_only` field. Default (unset) is enforce.
    pub fn with_warn_only(mut self, warn_only: bool) -> Self {
        self.warn_only = warn_only;
        self
    }

    /// Is the registry's RPC answering? `true` only if `eth_blockNumber`
    /// returns within the configured timeout.
    ///
    /// The same shape as [`crate::permit::ChainConfig::probe`], and for the
    /// same reason: prove reachability without depending on a contract call
    /// that could fail for unrelated reasons.
    pub async fn probe(&self) -> bool {
        use alloy::providers::Provider as _;
        matches!(
            tokio::time::timeout(self.timeout, self.contract.provider().get_block_number()).await,
            Ok(Ok(_))
        )
    }

    /// Whether the gate is in warn-only mode: logs commitment failures but
    /// allows the decrypt instead of blocking.
    pub fn warn_only(&self) -> bool {
        self.warn_only
    }

    /// Cached commit hash for `(host_chain_id, handle)`, if previously seen and
    /// still within `cache_ttl`. Also refreshes the entry's LRU recency. An
    /// expired entry is dropped and reported as a miss, so the caller re-reads
    /// the registry.
    fn get_from_cache(&self, host_chain_id: u64, handle: U256) -> Option<FixedBytes<32>> {
        let key = (host_chain_id, handle);
        let mut cache = self.lock_cache();
        // Copy the entry out so the expiry branch can mutate the cache.
        let entry = cache.get(&key).copied()?;
        if entry.stored_at.elapsed() < self.cache_ttl {
            return Some(entry.commit);
        }
        cache.pop(&key);
        None
    }

    /// Record a confirmed commit hash, stamped with the read time. Entries leave
    /// the cache on LRU eviction, on TTL expiry (see [`Self::get_from_cache`]),
    /// or explicitly via [`Self::evict_from_cache`].
    fn put_in_cache(&self, host_chain_id: u64, handle: U256, commit: FixedBytes<32>) {
        self.lock_cache().put(
            (host_chain_id, handle),
            CacheEntry {
                commit,
                stored_at: Instant::now(),
            },
        );
    }

    /// Drop any cached entry for `(host_chain_id, handle)`. Used when a
    /// cache-bypassing re-read finds no commitment at all: the cached hash
    /// cannot be from the registry we're now talking to, so it must not survive.
    fn evict_from_cache(&self, host_chain_id: u64, handle: U256) {
        self.lock_cache().pop(&(host_chain_id, handle));
    }

    /// Lock the shared cache, recovering from poisoning. The critical sections
    /// are single `LruCache` get/put calls; if one ever panics mid-operation
    /// the worst outcome of continuing is a stale/missing entry (an extra
    /// RPC), which beats panicking every subsequent request — prioritize
    /// stability.
    fn lock_cache(&self) -> std::sync::MutexGuard<'_, CommitmentCache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Number of hex digits in a canonical commitment version, after the `0x`.
const VERSION_HEX_DIGITS: usize = 64;

/// Parse a commitment version into the `bytes32` registry key.
///
/// Accepts only the canonical spelling: `0x` followed by exactly 64 hex digits,
/// byte-identical to the key the registry stores, to what cofhe's producers post
/// (`rust-common`'s `checked_version` gates those at compile time), and to the
/// value ops activate. Short forms are refused on purpose — a bare `"10"` reads
/// as ten to a human and sixteen as hex, and this side picks which bucket to
/// READ, so guessing wrong makes every decrypt miss (fail-closed).
pub fn parse_version(s: &str) -> Result<FixedBytes<32>, String> {
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("version must start with 0x, got {s:?}"))?;
    if digits.len() != VERSION_HEX_DIGITS {
        return Err(format!(
            "version must be 0x followed by {VERSION_HEX_DIGITS} hex digits, got {} in {s:?}",
            digits.len()
        ));
    }
    // Lowercase only: cofhe gates its constants to lowercase at compile time, and
    // hex::decode would otherwise accept an uppercase second spelling of the same
    // key -- one canonical form means one string, not two.
    if digits.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(format!("version must be lowercase hex, got {s:?}"));
    }
    let bytes = hex::decode(digits).map_err(|e| format!("version not hex: {e}"))?;
    Ok(FixedBytes::from_slice(&bytes))
}

/// Compute the commit hash of a ciphertext: `keccak256(data)` (commitment v2),
/// byte-identical to the engine's `calc_commitment` (cofhe
/// `fhe-engine/src/types.rs`). This is the value the poster writes into
/// `CommitmentRegistry`; hashing the stored bytes ct-server served and
/// comparing against the on-chain answer binds the decrypt to the exact
/// ciphertext the engine committed to.
///
/// The security zone is intentionally absent from the preimage (v1 was
/// `keccak256(data || security_zone_le_i32)`); it is bound instead by the
/// handle's byte 31 (the on-chain lookup key). Dropping it unifies op-result
/// commitments with verifier-signed input commitments (ct-server's `/StoreCts`
/// path already posts `keccak256(data)`), so a single format covers every
/// source.
///
/// LOCKED PAIR: this function and the engine's `calc_commitment` must stay
/// byte-identical forever — commitments are immutable on-chain, and `data`
/// here must be the *stored* bytes served verbatim (never locally re-expanded
/// / re-serialized ones). The golden-vector suite (`tests/golden_vectors.rs`)
/// pins this formula against committed fixtures. This is the commitment-VALUE
/// formula; it is NOT the handle-derivation formula (type/zone stamped into
/// bytes 30/31). Handles are lookup keys; only this value carries integrity.
pub fn calc_commitment(data: &[u8]) -> FixedBytes<32> {
    keccak256(data)
}

/// Verify a commitment exists for `handle` on the registry chain by calling
/// `CommitmentRegistry.getCommitment(version, handle)`. A
/// non-zero return means "committed" → `Ok(commit_hash)`; `bytes32(0)` →
/// [`CommitmentError::NotFound`].
///
/// Positive results are cached for `COMMITMENT_CACHE_TTL_SECS`; absent results
/// always re-hit the RPC (see the module docs for why). The returned
/// [`FetchedCommitment`] says whether the hash came from the cache, so a caller
/// whose integrity comparison fails can re-read past a possibly-stale entry
/// with [`refresh_commitment`] before refusing.
pub async fn fetch_commitment(
    cfg: &CommitmentConfig,
    handle: U256,
    host_chain_id: u64,
) -> Result<FetchedCommitment, CommitmentError> {
    // Fast path: consult the cache before touching the network.
    if let Some(hash) = cfg.get_from_cache(host_chain_id, handle) {
        return Ok(FetchedCommitment {
            hash,
            from_cache: true,
        });
    }

    refresh_commitment(cfg, handle, host_chain_id)
        .await
        .map(|hash| FetchedCommitment {
            hash,
            from_cache: false,
        })
}

/// [`fetch_commitment`] without the cache fast path: always reads the registry,
/// then reconciles the cache with what the chain actually says — a non-zero
/// answer replaces the cached hash (and re-stamps its TTL), a zero answer evicts
/// it.
///
/// This is the escape hatch from a cache that outlived its registry: the
/// integrity check calls it when a *cached* expectation mismatches the fetched
/// ciphertext, so a decrypt is only refused on a hash the chain confirms right
/// now.
pub async fn refresh_commitment(
    cfg: &CommitmentConfig,
    handle: U256,
    host_chain_id: u64,
) -> Result<FixedBytes<32>, CommitmentError> {
    let handle_b32 = FixedBytes::<32>::from(handle.to_be_bytes::<32>());
    let call = cfg.contract.getCommitment(cfg.version, handle_b32);
    let commit = tokio::time::timeout(cfg.timeout, call.call())
        .await
        .map_err(|_| CommitmentError::Timeout(cfg.timeout))?
        .map_err(map_contract_error)?;

    if commit != FixedBytes::ZERO {
        cfg.put_in_cache(host_chain_id, handle, commit);
        Ok(commit)
    } else {
        cfg.evict_from_cache(host_chain_id, handle);
        Err(CommitmentError::NotFound)
    }
}

/// Boot-time registry probe: a single bounded `getVersionStatus(version)` call.
/// Returns the configured version's on-chain status so the caller can warn on
/// anything that isn't `Active`.
///
/// The registry is chain-agnostic — one status per version, independent of the
/// host chain a handle came from — so this is a single call, not per-chain.
/// The call doubles as a reachability check: a wrong address / unreachable RPC
/// makes it error, which aborts boot.
///
/// This exists because both misconfig failure modes are otherwise only visible
/// at first traffic, and both are nasty: a wrong address/unreachable RPC turns
/// every decrypt into a client-fatal 502, and a wrong version makes every
/// lookup return zero — clients silently burn their whole retry budget before
/// failing. Failing (or warning) at boot is where the operator is looking.
pub async fn probe_registry(cfg: &CommitmentConfig) -> Result<u8, CommitmentError> {
    let call = cfg.contract.getVersionStatus(cfg.version);
    tokio::time::timeout(cfg.timeout, call.call())
        .await
        .map_err(|_| CommitmentError::Timeout(cfg.timeout))?
        .map_err(map_contract_error)
}

/// `getCommitment` is a plain view getter that returns `bytes32(0)` rather than
/// reverting when absent, so any contract-call error here is transport/infra
/// (unreachable RPC, decode failure) → surfaced as [`CommitmentError::Transport`]
/// (mapped to 502 by the HTTP layer), never a caller-fixable 4xx.
fn map_contract_error(e: alloy::contract::Error) -> CommitmentError {
    CommitmentError::Transport(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{spawn_json_rpc_mock, spawn_json_rpc_mock_seq};
    use std::sync::atomic::Ordering;

    const CHAIN: u64 = 420105;
    const REGISTRY: Address =
        alloy::primitives::address!("00000000000000000000000000000000000000cc");
    const NONZERO_B32: &str = "0x00000000000000000000000000000000000000000000000000000000000000ab";
    /// A *different* non-zero commitment, standing in for what a wiped-and-
    /// redeployed registry returns for a handle the cache already holds.
    const REDEPLOYED_B32: &str =
        "0x00000000000000000000000000000000000000000000000000000000000000cd";
    const ZERO_B32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    fn cfg(url: String) -> CommitmentConfig {
        cfg_with_ttl(url, Duration::from_secs(3600))
    }

    fn cfg_with_ttl(url: String, cache_ttl: Duration) -> CommitmentConfig {
        CommitmentConfig::new(
            url,
            REGISTRY,
            parse_version("0x0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
            Duration::from_secs(5),
            NonZeroUsize::new(1024).unwrap(),
            cache_ttl,
        )
        .expect("valid rpc_url")
    }

    #[tokio::test]
    async fn present_commitment_returns_hash() {
        let (url, _) = spawn_json_rpc_mock(NONZERO_B32).await;
        let c = cfg(url);
        let fetched = fetch_commitment(&c, U256::from(1u8), CHAIN)
            .await
            .expect("present commitment should verify");
        assert_eq!(
            fetched.hash[31], 0xab,
            "must return the on-chain commit hash"
        );
        assert!(!fetched.from_cache, "first lookup came from the RPC");
    }

    #[tokio::test]
    async fn absent_commitment_not_found() {
        let (url, _) = spawn_json_rpc_mock(ZERO_B32).await;
        let c = cfg(url);
        let err = fetch_commitment(&c, U256::from(1u8), CHAIN)
            .await
            .unwrap_err();
        assert!(matches!(err, CommitmentError::NotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn positive_result_cached_skips_rpc() {
        let (url, reqs) = spawn_json_rpc_mock(NONZERO_B32).await;
        let c = cfg(url);
        let h = U256::from(7u8);
        let first = fetch_commitment(&c, h, CHAIN).await.unwrap();
        let second = fetch_commitment(&c, h, CHAIN).await.unwrap();
        assert_eq!(
            first.hash, second.hash,
            "cached hash must equal the RPC answer"
        );
        assert!(second.from_cache, "second lookup must report a cache hit");
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            1,
            "second lookup should hit the positive cache, not the RPC"
        );
    }

    #[tokio::test]
    async fn expired_entry_is_a_miss_and_rereads_rpc() {
        // TTL bounds staleness: past it the entry is dropped and the registry is
        // re-read, which is what saves a long-lived process from a cache
        // populated before the chain + registry were wiped and redeployed.
        let (url, reqs) = spawn_json_rpc_mock(NONZERO_B32).await;
        let c = cfg_with_ttl(url, Duration::from_millis(20));
        let h = U256::from(3u8);
        assert!(!fetch_commitment(&c, h, CHAIN).await.unwrap().from_cache);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let after = fetch_commitment(&c, h, CHAIN).await.unwrap();
        assert!(
            !after.from_cache,
            "an expired entry must be treated as a miss"
        );
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            2,
            "the expired lookup must re-hit the RPC"
        );
    }

    #[tokio::test]
    async fn refresh_bypasses_cache_and_replaces_the_entry() {
        // The registry answers 0xab, then (as if redeployed) 0xcd. A cached
        // expectation that mismatches the ciphertext drives `refresh_commitment`,
        // which must read past the cache and leave the fresh value behind.
        let (url, reqs) =
            spawn_json_rpc_mock_seq(vec![NONZERO_B32.to_string(), REDEPLOYED_B32.to_string()])
                .await;
        let c = cfg(url);
        let h = U256::from(5u8);
        assert_eq!(fetch_commitment(&c, h, CHAIN).await.unwrap().hash[31], 0xab);
        assert!(
            fetch_commitment(&c, h, CHAIN).await.unwrap().from_cache,
            "warm cache serves the stale 0xab"
        );
        assert_eq!(reqs.load(Ordering::SeqCst), 1);

        let fresh = refresh_commitment(&c, h, CHAIN).await.unwrap();
        assert_eq!(fresh[31], 0xcd, "refresh must ignore the cached hash");
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            2,
            "refresh always hits the RPC"
        );

        let after = fetch_commitment(&c, h, CHAIN).await.unwrap();
        assert!(after.from_cache, "refresh must repopulate the cache");
        assert_eq!(
            after.hash[31], 0xcd,
            "with the fresh value, not the stale one"
        );
        assert_eq!(reqs.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn refresh_not_found_evicts_the_cached_entry() {
        // If the re-read finds nothing, the cached hash cannot belong to the
        // registry we're now talking to — it must not survive to be compared
        // against again.
        let (url, reqs) =
            spawn_json_rpc_mock_seq(vec![NONZERO_B32.to_string(), ZERO_B32.to_string()]).await;
        let c = cfg(url);
        let h = U256::from(9u8);
        assert_eq!(fetch_commitment(&c, h, CHAIN).await.unwrap().hash[31], 0xab);

        let err = refresh_commitment(&c, h, CHAIN).await.unwrap_err();
        assert!(matches!(err, CommitmentError::NotFound), "got {err:?}");

        // The mock now answers bytes32(0) forever: if the stale entry survived,
        // this would succeed from cache instead of erroring on a fresh read.
        let err = fetch_commitment(&c, h, CHAIN).await.unwrap_err();
        assert!(matches!(err, CommitmentError::NotFound), "got {err:?}");
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            3,
            "post-eviction lookup must re-hit the RPC"
        );
    }

    #[tokio::test]
    async fn absent_result_not_cached_rechecks_rpc() {
        // Absent answers are never cached: attacker-chosen keys must not evict
        // warm positives, and a landing commitment must be seen immediately.
        let (url, reqs) = spawn_json_rpc_mock(ZERO_B32).await;
        let c = cfg(url);
        let h = U256::from(11u8);
        assert!(fetch_commitment(&c, h, CHAIN).await.is_err());
        assert!(fetch_commitment(&c, h, CHAIN).await.is_err());
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            2,
            "every absent lookup must re-hit the RPC (no negative caching)"
        );
    }

    #[tokio::test]
    async fn bad_rpc_url_fails_at_construction() {
        let err = CommitmentConfig::new(
            "not a url".into(),
            REGISTRY,
            FixedBytes::ZERO,
            Duration::from_secs(5),
            NonZeroUsize::new(16).unwrap(),
            Duration::from_secs(3600),
        )
        .unwrap_err();
        assert!(
            matches!(err, CommitmentError::Misconfigured(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn unreachable_rpc_maps_to_transport() {
        // Reserved always-refusing port → transport error, not NotFound.
        let c = cfg("http://127.0.0.1:1".into());
        let err = fetch_commitment(&c, U256::from(1u8), CHAIN)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                CommitmentError::Transport(_) | CommitmentError::Timeout(_)
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn probe_returns_version_status() {
        // Mock answers every eth_call with uint8(1) = Active. The chain-agnostic
        // registry has one status per version, so the probe is a single call.
        let (url, reqs) = spawn_json_rpc_mock(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .await;
        let c = cfg(url);
        let status = probe_registry(&c).await.expect("probe ok");
        assert_eq!(status, 1);
        assert_eq!(VersionStatus::from_u8(status), Some(VersionStatus::Active));
        assert_eq!(
            reqs.load(Ordering::SeqCst),
            1,
            "one getVersionStatus call — no per-chain fan-out"
        );
    }

    #[tokio::test]
    async fn probe_unreachable_rpc_fails() {
        // The probe doubles as a reachability check: a dead RPC aborts boot.
        let c = cfg("http://127.0.0.1:1".into());
        let err = probe_registry(&c).await.unwrap_err();
        assert!(
            matches!(
                err,
                CommitmentError::Transport(_) | CommitmentError::Timeout(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn calc_commitment_is_keccak256_of_data() {
        // Layout guard (v2): keccak256(data), zone-free — byte-identical to
        // cofhe fhe-engine's calc_commitment. The security zone is bound by the
        // handle, not folded into the value. If the preimage ever regains the
        // zone (or any suffix), this fails.
        let data = b"ciphertext-bytes";
        assert_eq!(calc_commitment(data), keccak256(data));

        // Cross-repo known-answer vector, shared byte-for-byte with the engine's
        // calc_commitment KAT and zk-verifier's input ct_hash.
        assert_eq!(
            hex::encode(calc_commitment(&[0xde, 0xad, 0xbe, 0xef])),
            "d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1"
        );
    }

    #[test]
    fn parse_version_accepts_only_the_canonical_form() {
        let full = "0x00000000000000000000000000000000000000000000000000000000000000ab";
        assert_eq!(parse_version(full).unwrap()[31], 0xab);
        assert_eq!(
            parse_version("0x0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap()[31],
            0x02
        );
    }

    #[test]
    fn parse_version_refuses_short_forms() {
        // The whole point: "2" and "10" read one way to a human and another as
        // hex. Refusing them is what keeps this in lockstep with the poster.
        for short in ["2", "0x2", "0x02", "10", "0x10", "abc"] {
            assert!(
                parse_version(short).is_err(),
                "short form {short:?} must not parse"
            );
        }
    }

    #[test]
    fn parse_version_refuses_uppercase() {
        // One spelling, not two: cofhe gates its constants to lowercase at compile
        // time, so an uppercase value here would be a second canonical form.
        assert!(parse_version(&format!("0x{}", "0".repeat(62) + "0A")).is_err());
    }

    #[test]
    fn parse_version_refuses_malformed() {
        for bad in ["", "0x", "zz", "0xzz"] {
            assert!(parse_version(bad).is_err(), "{bad:?} must not parse");
        }
        // Wrong width, either direction.
        assert!(parse_version(&format!("0x{}", "ab".repeat(33))).is_err());
        assert!(parse_version(&format!("0x{}", "0".repeat(63))).is_err());
    }
}
