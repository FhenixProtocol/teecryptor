//! FHE-priv key source: reconstruct the Shamir-split FHE-priv secret from the
//! partners via the embedded `cofhe-keys` reader and assemble it into the
//! in-memory key handles teecryptor serves with.
//!
//! Replaces the legacy single-secret Secret-Manager fetch. The reconstructed
//! secret is **never persisted** — it lives only inside the [`KeyStore`] /
//! [`SigningService`] for the process lifetime (TDX-encrypted memory), and the
//! transient share bytes are zeroized by the reader and on assembly.
//!
//! The reader is **auth-agnostic** (`CONSUMER-INTEGRATION.md`): the caller supplies
//! the Secret-Manager / GCS access token its own attested identity obtained (the
//! `keys-access` SA impersonation, pattern A — unchanged). This module owns only
//! the teecryptor-side glue: turning the reconstructed [`FhePrivShare`]
//! into a [`KeyStore`] + [`SigningService`]. The gather, liar-filtering,
//! T-of-N reconstruction, and full-digest validation all live in `cofhe-keys`
//! (one shared, tested implementation) — not re-tested here.

use anyhow::Result;
use cofhe_keys::serialization::FhePrivShare;
use zeroize::Zeroizing;

use crate::keys::KeyStore;
use crate::signing::service::SigningService;

/// The in-memory key handles assembled from the reconstructed FHE-priv secret.
pub struct LoadedKeys {
    /// FHE `ClientKey` used to decrypt cofhe ciphertexts.
    pub keys: KeyStore,
    /// Response signer built from `decrypt_signer_priv` (bundled in the FHE-priv
    /// secret — TeeCryptor consumes both, so there is no separate signer fetch).
    pub signer: SigningService,
}

/// Turn a verified + reconstructed [`FhePrivShare`] into the in-memory handles.
/// `client_key` → [`KeyStore`]; `decrypt_signer_priv` → response signer.
/// Consumes the share so each secret buffer is zeroized as soon as it is loaded.
///
/// This is the single seam this integration adds on teecryptor's side: the
/// producer's wire types decoded into teecryptor's runtime types.
pub fn assemble(share: FhePrivShare) -> Result<LoadedKeys> {
    // Wrap both secret components in `Zeroizing` up front so EVERY exit path — the
    // length bail, a failed deserialize, or success — drops the bytes zeroized, not
    // just the happy path. (`KeyStore::load` / `SigningService::from_bytes` consume
    // the `Zeroizing`, so they own the wipe once called.)
    let client_key = Zeroizing::new(share.client_key);
    let signer_priv = Zeroizing::new(share.decrypt_signer_priv);
    // The decrypt signer is contractually a 32-byte secp256k1 scalar (the producer
    // writes `SigningKey::to_bytes()`, fixed 32 B, and the reader validates the
    // reconstruction against the published full digest — so a healthy ceremony
    // always yields 32 B here). This guard is defense-in-depth: `k256::from_slice`
    // is lenient (it left-pads a short input into a *different* valid key — a wrong
    // signing address — rather than rejecting it), and the legacy single-secret path
    // had this explicit check (main.rs), so keep it at the new seam.
    if signer_priv.len() != SIGNER_KEY_LEN {
        anyhow::bail!(
            "decrypt_signer_priv must be {SIGNER_KEY_LEN} bytes, got {}",
            signer_priv.len()
        );
    }
    let keys =
        KeyStore::load(client_key).map_err(|e| anyhow::anyhow!("load FHE client_key: {e}"))?;
    let signer = SigningService::from_bytes(signer_priv)
        .map_err(|e| anyhow::anyhow!("build signer from decrypt_signer_priv: {e}"))?;
    Ok(LoadedKeys { keys, signer })
}

/// Expected length of the secp256k1 `decrypt_signer_priv` scalar.
const SIGNER_KEY_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::{generate_keys, ConfigBuilder};

    // safe_serialized bytes of a fresh zone-0 ClientKey — the shape the producer
    // writes into `FhePrivShare.client_key`, decoded by `KeyStore::load`.
    fn fresh_client_key_bytes() -> Vec<u8> {
        let (ck, _sk) = generate_keys(ConfigBuilder::default().build());
        let mut bytes = Vec::new();
        safe_serialize(&ck, &mut bytes, 1 << 30).unwrap();
        bytes
    }

    // The one seam this integration adds: a verified+reconstructed FhePrivShare
    // decodes into teecryptor's runtime types — the zone-0 ClientKey loads, and the
    // bundled decrypt_signer_priv yields a usable signer with a derivable address.
    #[test]
    fn assemble_loads_keystore_and_signer() {
        let signer_priv = vec![0x11u8; 32];
        // Reference address derived straight from the priv — what the loaded
        // signer (and the published `decrypt_signer_address`) must match.
        let expected_addr = SigningService::from_bytes(Zeroizing::new(signer_priv.clone()))
            .unwrap()
            .evm_address()
            .to_string();

        let share = FhePrivShare {
            client_key: fresh_client_key_bytes(),
            decrypt_signer_priv: signer_priv,
        };
        let loaded = assemble(share).expect("assemble");
        assert!(loaded.keys.client_key(0).is_some(), "zone-0 key loaded");
        assert!(loaded.keys.client_key(1).is_none(), "only zone 0 populated");
        assert_eq!(loaded.signer.evm_address(), expected_addr);
    }

    // A malformed signer component (wrong length) is rejected, not panicked on —
    // the secp256k1 private key must be exactly 32 bytes.
    #[test]
    fn assemble_rejects_bad_signer_len() {
        let share = FhePrivShare {
            client_key: fresh_client_key_bytes(),
            decrypt_signer_priv: vec![0x11u8; 31],
        };
        assert!(assemble(share).is_err());
    }

    // A corrupt client_key is rejected by KeyStore::load (bounded safe_deserialize),
    // not panicked on.
    #[test]
    fn assemble_rejects_garbage_client_key() {
        let share = FhePrivShare {
            client_key: vec![0xde, 0xad, 0xbe, 0xef],
            decrypt_signer_priv: vec![0x11u8; 32],
        };
        assert!(assemble(share).is_err());
    }
}
