//! Loads and holds the FHE [`ClientKey`] for the lifetime of the process.
//!
//! Phase 1 supports security zone 0 only; [`KeyStore::client_key`] returns
//! `None` for any other zone. The raw secret bytes are consumed by
//! [`KeyStore::load`] and zeroized as soon as deserialization succeeds.

use tfhe::safe_serialization::safe_deserialize;
use tfhe::ClientKey;
use zeroize::Zeroizing;

use crate::direct_decrypt::DirectDecryptKey;
use crate::error::TeecryptorError;

/// Upper bound on the deserialized key size, matching cofhe's `safe_serde` cap.
const KEY_SIZE_LIMIT: u64 = 1 << 30; // 1 GiB

/// Holds the zone-0 `ClientKey` for the process lifetime.
///
/// The key is held unwrapped: `tfhe::ClientKey` does **not** implement `Zeroize`
/// (verified against tfhe 1.5.1 — it lacks `DefaultIsZeroes`), so a `Zeroizing`
/// wrapper won't compile and the struct can't be scrubbed on drop. This is
/// acceptable because (a) the raw serialized bytes ARE zeroized at load, (b) the
/// service runs in TDX-encrypted memory, and (c) `tee-restart-policy = Never`
/// means the key lives for the whole process and is never dropped in normal
/// operation. This matches cofhe, which also holds `ClientKey` unwrapped.
pub struct KeyStore {
    zone_0: ClientKey,
    /// Small LWE secret key for direct decryption of compressed cts, derived
    /// from `zone_0` once at load — the derivation clones the `ClientKey`
    /// (tfhe only exposes its parts by-value), so doing it per-decrypt would
    /// waste a ~40 KB copy on every request.
    zone_0_direct: DirectDecryptKey,
}

impl KeyStore {
    /// Deserialize `bytes` (tfhe-rs `safe_serialize` of a [`ClientKey`]) into a
    /// `KeyStore`. Consumes the secret buffer so it is zeroized as soon as
    /// deserialization succeeds.
    pub fn load(bytes: Zeroizing<Vec<u8>>) -> Result<Self, TeecryptorError> {
        let ck: ClientKey = safe_deserialize(&bytes[..], KEY_SIZE_LIMIT)
            .map_err(|e| TeecryptorError::KeyLoad(format!("safe_deserialize: {e}")))?;
        let direct = DirectDecryptKey::from_client_key(&ck)
            .map_err(|e| TeecryptorError::KeyLoad(format!("direct-decrypt key: {e}")))?;
        // `bytes` is dropped (and zeroized) at the end of this scope.
        Ok(Self {
            zone_0: ck,
            zone_0_direct: direct,
        })
    }

    /// Return the `ClientKey` for `zone`, or `None` if unsupported.
    /// Phase 1: only zone 0 is populated.
    pub fn client_key(&self, zone: i32) -> Option<&ClientKey> {
        if zone == 0 {
            Some(&self.zone_0)
        } else {
            None
        }
    }

    /// Return the [`DirectDecryptKey`] for `zone`, or `None` if unsupported.
    /// Derived once at [`KeyStore::load`]; same zone support as
    /// [`KeyStore::client_key`].
    pub fn direct_key(&self, zone: i32) -> Option<&DirectDecryptKey> {
        if zone == 0 {
            Some(&self.zone_0_direct)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::{generate_keys, ConfigBuilder};

    fn fresh_client_key() -> ClientKey {
        let config = ConfigBuilder::default().build();
        let (ck, _sk) = generate_keys(config);
        ck
    }

    #[test]
    fn round_trip_serialize_then_load() {
        let original = fresh_client_key();
        let mut bytes = Vec::new();
        safe_serialize(&original, &mut bytes, KEY_SIZE_LIMIT).expect("serialize");
        let store = KeyStore::load(Zeroizing::new(bytes)).expect("load");
        assert!(store.client_key(0).is_some());
        assert!(store.client_key(1).is_none());
        assert!(store.client_key(-1).is_none());
    }

    #[test]
    fn garbage_bytes_rejected() {
        let garbage = Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(KeyStore::load(garbage).is_err());
    }
}
