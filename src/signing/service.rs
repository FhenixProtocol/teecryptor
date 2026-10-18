// Mirrors dispatcher/src/signing/service.rs — same byte layouts for sign_decrypt
// and sign_sealoutput.
// BORROW-NOT-FORK: Loaded from a Secret Manager secret at boot instead of from a file.
// Phase 2 extracts to a shared fhenix/tdx-common crate.

use primitive_types::U256;
use zeroize::Zeroizing;

use super::{
    error::SigningError,
    evm_address::EvmAddress,
    signer::{SignatureVFormat, Signer},
};

/// Service that holds a signing key and exposes the two signing operations
/// needed by Teecryptor: `sign_decrypt` and `sign_sealoutput`.
///
/// Both methods produce byte-identical output to the cofhe dispatcher's
/// `SigningService` — same keccak preimage layouts, same low-S normalization.
pub struct SigningService {
    signer: Signer,
    evm_address: EvmAddress,
}

impl SigningService {
    /// Create a new `SigningService` from an already-constructed [`Signer`].
    /// Derives and caches the EVM address.
    pub fn new(signer: Signer) -> Self {
        let evm_address = EvmAddress::from(&signer);
        Self {
            signer,
            evm_address,
        }
    }

    /// Build a `SigningService` from raw 32-byte key material.
    /// The [`Zeroizing`] wrapper ensures the bytes are wiped when dropped.
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SigningError> {
        let signer = Signer::from_bytes(&bytes)?;
        Ok(Self::new(signer))
    }

    /// Build a `SigningService` by reading a raw 32-byte secp256k1 private key
    /// from a file. This is the LOCAL/DEV boot path (`MOCK_KEYS_DIR`): it lets a
    /// mock-build Teecryptor sign as cofhe's `dispatcher_signer_pk` instead of a
    /// throwaway key, so signatures verify identically against the local stack
    /// (same signing identity => same on-chain signer address). The production
    /// binary never calls this — its signer comes from the FHE-priv Shamir secret.
    #[cfg(feature = "mock")]
    pub fn from_key_file(path: impl AsRef<std::path::Path>) -> Result<Self, SigningError> {
        // Wrap at read time so the length-mismatch return below cannot drop raw
        // private-key bytes un-wiped.
        let bytes = Zeroizing::new(std::fs::read(path.as_ref())?); // io::Error => KeyFileError
        if bytes.len() != 32 {
            return Err(SigningError::InvalidKey(format!(
                "signer key file must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Self::from_bytes(bytes)
    }

    /// Returns the cached 0x-prefixed EVM address (42 chars).
    pub fn evm_address(&self) -> &str {
        &self.evm_address
    }

    /// Sign a decrypt result.
    ///
    /// Byte layout (must match dispatcher exactly):
    /// ```text
    /// keccak256(
    ///   result(32 B, U256 big-endian)
    ///   ‖ encryption_type(4 B, i32 big-endian)
    ///   ‖ chain_id(8 B, u64 big-endian)
    ///   ‖ ct_hash(32 B, hex-parsed, exactly 32 bytes)
    /// )
    /// ```
    ///
    /// # Errors
    /// `ct_hash` that is not exactly 32 bytes of hex, or a signing failure.
    pub fn sign_decrypt(
        &self,
        plaintext: &U256,
        encryption_type: i32,
        chain_id: u64,
        ct_hash: &str,
        v_format: SignatureVFormat,
    ) -> Result<String, SigningError> {
        let mut preimage = Vec::with_capacity(76);

        // result: U256 → 32 bytes big-endian
        let result_bytes = plaintext.to_big_endian();
        preimage.extend_from_slice(&result_bytes);

        // encryption_type: i32 big-endian (4 bytes)
        preimage.extend_from_slice(&encryption_type.to_be_bytes());

        // chain_id: u64 big-endian (8 bytes)
        preimage.extend_from_slice(&chain_id.to_be_bytes());

        // ct_hash: hex-parsed, exactly 32 bytes
        preimage.extend_from_slice(&parse_ct_hash(ct_hash)?);

        let hash = Signer::keccak256(&preimage);
        self.signer.sign_prehash_to_hex_with_format(&hash, v_format)
    }

    /// Sign a seal-output bundle.
    ///
    /// Byte layout (must match dispatcher exactly):
    /// ```text
    /// keccak256(
    ///   sealed ‖ ephemeral_pk ‖ nonce
    ///   ‖ encryption_type(4 B, i32 big-endian)
    ///   ‖ chain_id(8 B, u64 big-endian)
    ///   ‖ ct_hash(32 B, hex-parsed, exactly 32 bytes)
    /// )
    /// ```
    // Mirrors the dispatcher's `sign_sealoutput` arity exactly (sealed, eph_pk,
    // nonce, enc_type, chain_id, ct_hash, v_format) — same allow as upstream.
    ///
    /// # Errors
    /// `ct_hash` that is not exactly 32 bytes of hex, or a signing failure.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_sealoutput(
        &self,
        sealed: &[u8],
        ephemeral_pk: &[u8],
        nonce: &[u8],
        encryption_type: i32,
        chain_id: u64,
        ct_hash: &str,
        v_format: SignatureVFormat,
    ) -> Result<String, SigningError> {
        let mut preimage = Vec::with_capacity(sealed.len() + ephemeral_pk.len() + nonce.len() + 44);

        preimage.extend_from_slice(sealed);
        preimage.extend_from_slice(ephemeral_pk);
        preimage.extend_from_slice(nonce);

        // encryption_type: i32 big-endian (4 bytes)
        preimage.extend_from_slice(&encryption_type.to_be_bytes());

        // chain_id: u64 big-endian (8 bytes)
        preimage.extend_from_slice(&chain_id.to_be_bytes());

        // ct_hash: hex-parsed, exactly 32 bytes
        preimage.extend_from_slice(&parse_ct_hash(ct_hash)?);

        let hash = Signer::keccak256(&preimage);
        self.signer.sign_prehash_to_hex_with_format(&hash, v_format)
    }
}

/// Parse a hex ciphertext handle (with or without a "0x" prefix) into exactly
/// 32 bytes.
///
/// Deliberately stricter than the dispatcher helper it mirrors, which pads a
/// short input and truncates a long one: a padded or truncated value is not
/// the handle the caller named. The HTTP layer canonicalises the handle
/// before it gets here; this is the second lock.
fn parse_ct_hash(hex_str: &str) -> Result<[u8; 32], SigningError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)?;
    <[u8; 32]>::try_from(bytes).map_err(|bytes| {
        SigningError::HexDecodeError(format!("ct_hash must be 32 bytes, got {}", bytes.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::signer::SignatureVFormat;
    use primitive_types::U256;

    fn test_service() -> SigningService {
        SigningService::new(Signer::from_bytes(&[1u8; 32]).unwrap())
    }

    /// A well-formed handle: 32 bytes as 64 hex digits.
    const HANDLE: &str = "0xabababababababababababababababababababababababababababababababab";

    /// No signature for anything that is not a 32-byte handle: odd-length,
    /// over-long, short and empty spellings alike.
    #[test]
    fn sign_decrypt_rejects_handle_that_is_not_32_bytes() {
        let svc = test_service();
        let pt = U256::from(1u32);
        for bad in [
            format!("0x{}", "a".repeat(63)),
            format!("0x{}{}", "11".repeat(32), "22"),
            "0xabcd".to_string(),
            "0x".to_string(),
        ] {
            assert!(
                svc.sign_decrypt(&pt, 0, 1, &bad, SignatureVFormat::Raw)
                    .is_err(),
                "signed handle {bad}"
            );
        }
    }

    #[test]
    fn sign_sealoutput_rejects_handle_that_is_not_32_bytes() {
        let svc = test_service();
        let odd = format!("0x{}", "a".repeat(63));
        let signed = svc.sign_sealoutput(
            b"sealed",
            &[1u8; 32],
            &[2u8; 24],
            0,
            1,
            &odd,
            SignatureVFormat::Raw,
        );
        assert!(signed.is_err(), "signed an odd-length handle");
    }

    #[test]
    fn sign_decrypt_returns_130_char_hex() {
        let svc = test_service();
        let pt = U256::from(42u32);
        let sig = svc
            .sign_decrypt(&pt, 4, 420105, HANDLE, SignatureVFormat::Raw)
            .unwrap();
        assert_eq!(sig.len(), 130);
        assert!(hex::decode(&sig).is_ok());
    }

    #[test]
    fn sign_decrypt_deterministic() {
        let svc = test_service();
        let pt = U256::from(1u32);
        let s1 = svc
            .sign_decrypt(&pt, 2, 1, HANDLE, SignatureVFormat::Raw)
            .unwrap();
        let s2 = svc
            .sign_decrypt(&pt, 2, 1, HANDLE, SignatureVFormat::Raw)
            .unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn sign_decrypt_different_plaintexts_differ() {
        let svc = test_service();
        let s1 = svc
            .sign_decrypt(&U256::from(1u32), 2, 1, HANDLE, SignatureVFormat::Raw)
            .unwrap();
        let s2 = svc
            .sign_decrypt(&U256::from(2u32), 2, 1, HANDLE, SignatureVFormat::Raw)
            .unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn sign_sealoutput_returns_130_char_hex() {
        let svc = test_service();
        let sig = svc
            .sign_sealoutput(
                &[1u8, 2, 3],
                &[4u8, 5, 6],
                &[7u8, 8, 9],
                4,
                420105,
                HANDLE,
                SignatureVFormat::Raw,
            )
            .unwrap();
        assert_eq!(sig.len(), 130);
    }

    #[test]
    fn evm_address_is_42_chars_0x_prefixed() {
        let svc = test_service();
        assert!(svc.evm_address().starts_with("0x"));
        assert_eq!(svc.evm_address().len(), 42);
    }

    #[test]
    fn from_bytes_builds_service() {
        use zeroize::Zeroizing;
        let bytes = Zeroizing::new(vec![0x42u8; 32]);
        let svc = SigningService::from_bytes(bytes).unwrap();
        assert_eq!(svc.evm_address().len(), 42);
    }

    /// `from_key_file` is mock-only, so its tests are too.
    #[cfg(feature = "mock")]
    mod from_key_file {
        use super::*;

        /// A temp dir per test — fixed paths under `temp_dir()` collide between
        /// concurrent runs of this binary on one machine.
        fn key_file(name: &str, contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(name);
            std::fs::write(&path, contents).expect("write key");
            (dir, path)
        }

        #[test]
        fn loads_32_byte_key_matching_from_bytes() {
            let key = [0x42u8; 32];
            let (_dir, path) = key_file("signer_pk", &key);

            let from_file = SigningService::from_key_file(&path).unwrap();
            let from_bytes = SigningService::from_bytes(Zeroizing::new(key.to_vec())).unwrap();

            // Same key bytes => same signing identity => same EVM address.
            assert_eq!(from_file.evm_address(), from_bytes.evm_address());
        }

        #[test]
        fn rejects_wrong_length() {
            let (_dir, path) = key_file("signer_pk", &[0u8; 31]); // 31 bytes, not 32

            let err = match SigningService::from_key_file(&path) {
                Ok(_) => panic!("expected error for a 31-byte key file"),
                Err(e) => e,
            };
            let msg = err.to_string();
            assert!(
                msg.contains("32"),
                "error should state expected length: {msg}"
            );
            assert!(
                msg.contains("31"),
                "error should state actual length: {msg}"
            );
        }

        #[test]
        fn missing_file_is_key_file_error() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("absent");

            let err = match SigningService::from_key_file(&path) {
                Ok(_) => panic!("expected error for a missing key file"),
                Err(e) => e,
            };
            assert!(
                matches!(err, SigningError::KeyFileError(_)),
                "missing file should be KeyFileError, got: {err:?}"
            );
        }
    }
}
