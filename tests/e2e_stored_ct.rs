//! End-to-end verification against a REAL ct-server (localcofhe or staging
//! via IAP tunnel): fetch a ciphertext through the production `CtSource`
//! (`POST /GetStoredCt`, requires cofhe PR #799 deployed) and prove the
//! served bytes are the handle preimage — without needing registry access —
//! by reconstructing the handle from them as keccak256(data) plus the byte-30
//! type / byte-31 zone stamp per
//! `ct-server/src/hash.rs::adjust_hash_for_metadata` (the zone lives in the
//! stamp, not the keccak preimage). A match proves ct-server served the stored
//! bytes verbatim — the property teecryptor's commitment gate depends on.
//!
//! Ignored by default; run manually with the stack up:
//!
//! ```sh
//! CT_SERVER_URL=http://localhost:9450 CT_HANDLE=0x<handle> \
//!   cargo test --test e2e_stored_ct -- --ignored --nocapture
//! ```
//!
//! Optionally set `CLIENT_KEY_PATH` (safe_serialized ClientKey, e.g. the
//! localcofhe dev key) to also direct-decrypt the fetched ct and print the
//! value.

use std::time::Duration;

use teecryptor::cofhe_layout::{TRIVIAL_ENCRYPT_FLAG, TYPE_BYTE, TYPE_MASK, ZONE_BYTE};
use teecryptor::ct_source::CtSource;
use teecryptor::decrypt::EncryptionType;
use teecryptor::direct_decrypt::{decrypt_compressed, DirectDecryptKey};

fn strip0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

#[tokio::test]
#[ignore]
async fn stored_ct_bytes_are_the_handle_preimage() {
    let url = std::env::var("CT_SERVER_URL").expect("set CT_SERVER_URL");
    let handle = std::env::var("CT_HANDLE").expect("set CT_HANDLE (0x…32-byte handle)");

    let source = CtSource::new(&url, Duration::from_secs(15)).expect("client");
    let ct = source.fetch(&handle).await.expect("GetStoredCt fetch");
    println!(
        "fetched: {} bytes, uint_type={}, zone={}, compact={}, gzipped={}",
        ct.data.len(),
        ct.encryption_type,
        ct.security_zone,
        ct.compact,
        ct.gzipped
    );
    assert!(!ct.compact, "compact ct served — contract violation");

    // Reconstruct the handle from the served bytes: keccak256(data) plus the
    // byte-30 type / byte-31 zone metadata stamp (adjust_hash_for_metadata).
    // There is one preimage formula — the security zone lives in the stamp,
    // never in the keccak preimage (same as the commitment value now; see
    // `calc_commitment`). A match proves the served bytes are byte-identical to
    // the handle's preimage — the property the commitment gate depends on.
    let preimage: [u8; 32] = *alloy::primitives::keccak256(&ct.data);

    let stamp = |mut h: [u8; 32], trivial: bool| {
        h[TYPE_BYTE] = ct.encryption_type as u8 & TYPE_MASK;
        if trivial {
            h[TYPE_BYTE] |= TRIVIAL_ENCRYPT_FLAG;
        }
        h[ZONE_BYTE] = ct.security_zone as u8;
        h
    };

    let requested = hex::decode(strip0x(&handle)).expect("handle hex");
    let candidates = [
        ("keccak(data)", stamp(preimage, false)),
        ("keccak(data), trivial flag", stamp(preimage, true)),
    ];
    let matched = candidates.iter().find(|(_, h)| requested == *h);
    let Some((which, _)) = matched else {
        panic!(
            "served bytes are NOT the handle preimage!\n  \
             handle:        {}\n  keccak(data):  0x{}\n  \
             → ct-server is serving derived (re-expanded?) bytes, or the hash \
             formula drifted",
            handle,
            hex::encode(stamp(preimage, false)),
        );
    };
    println!("OK: served bytes reconstruct the handle via {which} (preimage verified)");

    // Optional: direct-decrypt with a provided client key.
    if let Ok(key_path) = std::env::var("CLIENT_KEY_PATH") {
        use tfhe::safe_serialization::safe_deserialize;
        let ck: tfhe::ClientKey = safe_deserialize(
            std::fs::read(&key_path)
                .expect("read client key")
                .as_slice(),
            1 << 30,
        )
        .expect("client key deserialize");
        let ty = EncryptionType::from_i32(ct.encryption_type).expect("type");
        let value = if ct.gzipped {
            let dk = DirectDecryptKey::from_client_key(&ck).expect("direct key");
            decrypt_compressed(&dk, ty, &ct.data).expect("direct decrypt")
        } else {
            #[cfg(feature = "legacy-plain-decrypt")]
            {
                teecryptor::decrypt::decrypt(&ck, ty, &ct.data).expect("plain decrypt")
            }
            #[cfg(not(feature = "legacy-plain-decrypt"))]
            {
                panic!("non-gzipped ct: rebuild with --features legacy-plain-decrypt to decrypt it")
            }
        };
        println!(
            "decrypted ({}): {value}",
            if ct.gzipped {
                "direct path"
            } else {
                "plain path"
            }
        );
    }
}
