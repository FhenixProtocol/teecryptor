//! Signing alignment test: proves Teecryptor's signing preimage is byte-identical
//! to the cofhe dispatcher's. If this test breaks, on-chain ecrecover will recover
//! the wrong address and publishDecryptResult will fail.
//!
//! Reference: dispatcher/src/signing/service.rs::sign_decrypt / sign_sealoutput

use primitive_types::U256;
use teecryptor::signing::service::SigningService;
use teecryptor::signing::{SignatureVFormat, Signer};

fn test_signer() -> (SigningService, Signer) {
    let key = [0x42u8; 32];
    let svc = SigningService::new(Signer::from_bytes(&key).unwrap());
    let ref_signer = Signer::from_bytes(&key).unwrap();
    (svc, ref_signer)
}

/// Reference implementation: replicates the dispatcher's sign_decrypt preimage
/// construction inline without importing from cofhe.
fn reference_sign_decrypt(
    signer: &Signer,
    plaintext: U256,
    encryption_type: i32,
    chain_id: u64,
    ct_hash_hex: &str,
) -> String {
    let result_bytes = plaintext.to_big_endian();

    let ct_stripped = ct_hash_hex.strip_prefix("0x").unwrap_or(ct_hash_hex);
    let ct_bytes = hex::decode(ct_stripped).unwrap_or_default();
    let mut ct_hash = [0u8; 32];
    let start = 32usize.saturating_sub(ct_bytes.len());
    ct_hash[start..].copy_from_slice(&ct_bytes[..ct_bytes.len().min(32)]);

    let mut msg = Vec::new();
    msg.extend_from_slice(&result_bytes);
    msg.extend_from_slice(&encryption_type.to_be_bytes());
    msg.extend_from_slice(&chain_id.to_be_bytes());
    msg.extend_from_slice(&ct_hash);

    let hash = Signer::keccak256(&msg);
    signer
        .sign_prehash_to_hex_with_format(&hash, SignatureVFormat::Raw)
        .unwrap()
}

#[test]
fn sign_decrypt_matches_reference_implementation() {
    let (svc, ref_signer) = test_signer();

    let plaintext = U256::from(0xdeadbeef_u64);
    let enc_type = 4i32;
    let chain_id = 420105u64;
    let ct_hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let ours = svc
        .sign_decrypt(
            &plaintext,
            enc_type,
            chain_id,
            ct_hash,
            SignatureVFormat::Raw,
        )
        .unwrap();
    let reference = reference_sign_decrypt(&ref_signer, plaintext, enc_type, chain_id, ct_hash);

    assert_eq!(
        ours, reference,
        "signing preimage mismatch — on-chain ecrecover will recover wrong address"
    );
    assert_eq!(
        ours.len(),
        130,
        "signature must be 130 hex chars (65 bytes)"
    );
}

#[test]
fn sign_decrypt_evm_v_format_differs_only_in_last_byte() {
    let (svc, _) = test_signer();
    let pt = U256::from(42u32);

    let raw = svc
        .sign_decrypt(&pt, 4, 1, "0xabcd", SignatureVFormat::Raw)
        .unwrap();
    let evm = svc
        .sign_decrypt(&pt, 4, 1, "0xabcd", SignatureVFormat::Evm)
        .unwrap();

    let raw_b = hex::decode(&raw).unwrap();
    let evm_b = hex::decode(&evm).unwrap();
    // r+s (first 64 bytes) must be identical; only recovery id differs
    assert_eq!(
        &raw_b[..64],
        &evm_b[..64],
        "r and s must not change between formats"
    );
    assert_eq!(raw_b[64] + 27, evm_b[64], "evm v = raw v + 27");
}

#[test]
fn signer_address_is_42_chars_0x_prefixed() {
    let (svc, _) = test_signer();
    let addr = svc.evm_address();
    assert!(addr.starts_with("0x"), "must be 0x-prefixed");
    assert_eq!(addr.len(), 42, "must be 20 bytes = 40 hex chars + 0x");
}
