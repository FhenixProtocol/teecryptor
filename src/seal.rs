//! Sealed-output: encrypt a decrypted plaintext to the caller's
//! [`sealingKey`](crate::permit::AcpData::sealing_key) using NaCl
//! `crypto_box` (X25519 + XSalsa20-Poly1305). Byte-for-byte compatible with
//! cofhe dispatcher's `encrypt_for_user` in
//! `threshold-network/crates/dispatcher/src/operations/sealoutput.rs`,
//! so the same caller-side decrypt code that consumes the dispatcher's
//! sealed responses consumes Teecryptor's unchanged.
//!
//! Threat-model notes (read before deploying):
//!
//! * **Confidentiality:** the sealed bytes are decryptable only by the
//!   holder of the secret key corresponding to `sealingKey`. The
//!   permit's EIP-712 signature binds `sealingKey` to the issuer's EOA
//!   when permit verification is enabled.
//!
//! * **Response binding gap:** Teecryptor does **not** sign the
//!   `(handle, sealed, ephemeral_pk, nonce)` tuple — Phase 1 has no
//!   in-TEE signing key. An MITM with network access to the response
//!   path could in principle replay or swap an older valid response
//!   from the same `sealingKey`. Deploy behind TLS until a Phase 3
//!   attested-signing-key feature lands. The same gap exists in cofhe
//!   dispatcher when its signing service is not configured.
//!
//! * **Caller-side responsibilities:** caller chooses a fresh
//!   `sealingKey` per permit, never reuses the keypair across distinct
//!   permission contexts, and verifies the response matches the
//!   handle it requested (out-of-band, since the wire format does not
//!   carry the handle inside the sealed payload — matching cofhe).

use dryoc::dryocbox::{DryocBox, KeyPair, NewByteArray, Nonce, PublicKey};
use thiserror::Error;

/// Bytes the caller needs to decrypt the sealed output:
///
/// * `data` — the dryoc `crypto_box`: 16-byte Poly1305 tag followed by the
///   ciphertext (same length as the plaintext).
/// * `public_key` — the **ephemeral** X25519 public key Teecryptor generated
///   for this single response. The caller combines this with their own
///   secret key (the secret half of `sealingKey`) to derive the shared
///   secret.
/// * `nonce` — 24-byte random nonce. Never reused.
#[derive(Debug, Clone)]
pub struct SealedOutput {
    /// Sealed ciphertext (tag-prefixed). Wire field name: `data`.
    pub data: Vec<u8>,
    /// Ephemeral X25519 public key (32 bytes). Wire field name: `public_key`.
    pub public_key: Vec<u8>,
    /// XSalsa20 nonce (24 bytes). Wire field name: `nonce`.
    pub nonce: Vec<u8>,
}

/// Errors from sealing a plaintext to a caller's pubkey.
#[derive(Debug, Error)]
pub enum SealError {
    /// `sealingKey` was not exactly 32 bytes after hex decode.
    #[error("sealingKey must be 32 bytes, got {0}")]
    BadKeyLength(usize),
    /// `sealingKey` is a known-degenerate Curve25519 point (currently:
    /// all-zero). Treating it as a valid pubkey produces a constant /
    /// attacker-known shared secret, which would let the attacker decrypt.
    #[error("sealingKey is a degenerate (low-order) Curve25519 point")]
    DegenerateKey,
    /// The underlying NaCl `crypto_box` call failed. Should not happen with
    /// valid inputs; if it does, treat as an internal fault.
    #[error("crypto_box encryption failed: {0}")]
    EncryptFailed(String),
}

/// Seal `plaintext` to `recipient_public_key`. Mirrors cofhe's
/// `encrypt_for_user`. Generates a fresh ephemeral keypair and nonce per call.
///
/// `recipient_public_key` must be exactly 32 bytes (a Curve25519 public key).
/// This function rejects the all-zero pubkey as a defense-in-depth check; full
/// low-order point screening is not performed (matches dryoc/libsodium
/// behavior).
pub fn seal_to_user(
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<SealedOutput, SealError> {
    if recipient_public_key.len() != 32 {
        return Err(SealError::BadKeyLength(recipient_public_key.len()));
    }
    // Reject the all-zero pubkey explicitly. dryoc/libsodium accepts it and
    // would produce a deterministic shared secret an attacker can reproduce —
    // and in cofhe parlance this would be a "permit with no real recipient".
    // Stricter low-order point screening (per X25519 spec Appendix A) would
    // catch a handful of other malicious inputs; not implemented here because
    // dryoc itself doesn't, and we want byte-identical behavior with cofhe.
    if recipient_public_key.iter().all(|&b| b == 0) {
        return Err(SealError::DegenerateKey);
    }

    let ephemeral_keypair = KeyPair::gen();
    let nonce = Nonce::gen();

    // The length check above guarantees TryFrom succeeds; the .expect is
    // unreachable in practice but kept rather than `unwrap` for grep-ability.
    let recipient_pk = PublicKey::try_from(recipient_public_key)
        .expect("recipient_public_key length already checked");

    let dryocbox = DryocBox::encrypt_to_vecbox(
        plaintext,
        &nonce,
        &recipient_pk,
        &ephemeral_keypair.secret_key,
    )
    .map_err(|e| SealError::EncryptFailed(e.to_string()))?;

    Ok(SealedOutput {
        data: dryocbox.to_vec(),
        public_key: ephemeral_keypair.public_key.to_vec(),
        nonce: nonce.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dryoc::dryocbox::DryocBox;

    use dryoc::types::Bytes;

    /// Pull the 32 raw bytes out of a dryoc `PublicKey` for tests.
    fn pk_bytes(p: &PublicKey) -> &[u8] {
        Bytes::as_slice(p)
    }

    #[test]
    fn round_trips_to_a_fresh_keypair() {
        // The caller generates an X25519 keypair, hands the public key to
        // Teecryptor as `sealingKey`, and decrypts the response with the
        // secret half. We simulate that here.
        let caller = KeyPair::gen();
        let plaintext = b"hello teecryptor, this is the plaintext from a real decrypt";

        let sealed = seal_to_user(pk_bytes(&caller.public_key), plaintext).expect("seal");

        // Reconstruct the dryoc box from wire bytes and decrypt with the
        // caller's secret key + the ephemeral public key we returned.
        let dryocbox = DryocBox::from_bytes(&sealed.data).expect("parse sealed box");
        let eph_pk = PublicKey::try_from(sealed.public_key.as_slice()).expect("eph pk len");
        let nonce = Nonce::try_from(sealed.nonce.as_slice()).expect("nonce len");

        let recovered = dryocbox
            .decrypt_to_vec(&nonce, &eph_pk, &caller.secret_key)
            .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let plaintext = b"x";
        for bad_len in [0usize, 1, 31, 33, 64] {
            let bad_key = vec![0xab; bad_len];
            let err = seal_to_user(&bad_key, plaintext).unwrap_err();
            assert!(
                matches!(err, SealError::BadKeyLength(n) if n == bad_len),
                "len {bad_len} should error, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_zero_pubkey() {
        let zero = [0u8; 32];
        let err = seal_to_user(&zero, b"x").unwrap_err();
        assert!(matches!(err, SealError::DegenerateKey), "got {err:?}");
    }

    #[test]
    fn fresh_ephemeral_keypair_per_call() {
        // Two seals to the same recipient should produce different ephemeral
        // public keys + nonces (so reuse-of-nonce attacks against XSalsa20 are
        // not possible across requests).
        let caller = KeyPair::gen();
        let pk = pk_bytes(&caller.public_key);
        let a = seal_to_user(pk, b"a").unwrap();
        let b = seal_to_user(pk, b"a").unwrap();
        assert_ne!(a.public_key, b.public_key, "ephemeral pk reused");
        assert_ne!(a.nonce, b.nonce, "nonce reused");
        // And the sealed payloads MUST be different (different keys/nonces).
        assert_ne!(a.data, b.data, "sealed payload reused");
    }

    #[test]
    fn output_byte_lengths_match_nacl() {
        let caller = KeyPair::gen();
        let plaintext = vec![0u8; 100];
        let sealed = seal_to_user(pk_bytes(&caller.public_key), &plaintext).unwrap();
        assert_eq!(sealed.public_key.len(), 32, "X25519 public key is 32 bytes");
        assert_eq!(sealed.nonce.len(), 24, "XSalsa20 nonce is 24 bytes");
        // crypto_box ciphertext = 16-byte Poly1305 tag + ciphertext.
        assert_eq!(
            sealed.data.len(),
            16 + plaintext.len(),
            "crypto_box adds a 16-byte tag"
        );
    }
}
