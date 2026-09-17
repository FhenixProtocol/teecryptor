//! Golden-vector tripwire for the direct-decrypt path.
//!
//! `tests/fixtures/golden/` holds a committed test `ClientKey` plus
//! engine-style compressed ciphertexts (`safe_serialize(ct.compress())` under
//! the production parameter set) with their expected plaintexts and commitment
//! hashes. The verify test replays them through the real code paths:
//! `calc_commitment` over the fixture bytes, then
//! `direct_decrypt::decrypt_compressed`.
//!
//! Why this exists: the mirror decoding in `direct_decrypt` and the
//! commitment formula are only sound while tfhe's serialization layout and
//! the engine's hash preimage stay fixed. On-chain commitments are permanent,
//! so any drift (a tfhe bump changing versionized layout, a mirror edit, a
//! hash-formula change) must fail CI *loudly* instead of stranding committed
//! ciphertexts. If this test breaks after a deliberate tfhe upgrade, that is
//! the signal to plan a commitment-rotation migration — then regenerate the
//! fixtures with `cargo test --test golden_vectors -- --ignored --nocapture`.
//!
//! The fixture key is a throwaway generated for these vectors only — it never
//! decrypts real data.

use std::fs;
use std::path::PathBuf;

use primitive_types::U256;
use teecryptor::commitment::calc_commitment;
use teecryptor::decrypt::EncryptionType;
use teecryptor::direct_decrypt::{decrypt_compressed, DirectDecryptKey};
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::ClientKey;

const LIMIT: u64 = 1 << 30;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("golden")
}

/// One golden vector: a fixture file plus what it must hash to and decrypt to.
#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    /// Fixture filename under `tests/fixtures/golden/`.
    file: String,
    /// cofhe `EncryptionType` discriminant.
    uint_type: i32,
    /// Expected plaintext, 32-byte big-endian hex (no 0x).
    value_be_hex: String,
    /// Expected `calc_commitment(bytes)`, 32-byte hex (no 0x).
    commit_hash_hex: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// tfhe version the fixtures were generated with, for the failure message.
    tfhe_version: String,
    entries: Vec<Entry>,
}

#[test]
fn golden_vectors_hash_and_direct_decrypt() {
    let dir = fixtures_dir();
    let manifest: Manifest = serde_json::from_slice(&fs::read(dir.join("manifest.json")).expect(
        "golden fixtures missing — generate them once with \
             `cargo test --test golden_vectors -- --ignored --nocapture`",
    ))
    .expect("manifest.json parse");

    let ck: ClientKey = safe_deserialize(
        fs::read(dir.join("client_key.bin"))
            .expect("client_key.bin")
            .as_slice(),
        LIMIT,
    )
    .expect("fixture client key deserializes under the current tfhe");
    let dk = DirectDecryptKey::from_client_key(&ck).expect("direct key extraction");

    for e in &manifest.entries {
        let bytes = fs::read(dir.join(&e.file)).expect(&e.file);

        // 1. Commitment formula stability: these hashes are what would sit
        //    on-chain forever for these bytes.
        let hash = calc_commitment(&bytes);
        assert_eq!(
            hex::encode(hash),
            e.commit_hash_hex,
            "{}: commitment hash drifted (fixtures generated with tfhe {}) — \
             on-chain commitments over old bytes would strand",
            e.file,
            manifest.tfhe_version,
        );

        // 2. Direct-decrypt stability: mirror layout + decode math against
        //    bytes produced by an earlier build.
        let ty = EncryptionType::from_i32(e.uint_type).expect("fixture type");
        let got = decrypt_compressed(&dk, ty, &bytes)
            .unwrap_or_else(|err| panic!("{}: direct decrypt failed: {err}", e.file));
        let be: [u8; 32] = got.to_big_endian();
        assert_eq!(
            hex::encode(be),
            e.value_be_hex,
            "{}: decrypted value drifted (fixtures generated with tfhe {})",
            e.file,
            manifest.tfhe_version,
        );
    }
}

/// Regenerates the fixtures. Run manually — and only as part of a deliberate
/// migration — with:
/// `cargo test --test golden_vectors -- --ignored --nocapture`
#[test]
#[ignore]
fn regenerate_golden_vectors() {
    use tfhe::prelude::FheEncrypt;
    use tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use tfhe::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::{
        ConfigBuilder, FheBool, FheUint128, FheUint160, FheUint32, FheUint64, FheUint8, ServerKey,
    };

    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("fixtures dir");

    // Mirror the engine's keygen config (compute + dedicated compact PKE +
    // casting params) so the fixture key has the exact production shape.
    let config = ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
        .use_dedicated_compact_public_key_parameters((
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ))
        .build();
    let ck = ClientKey::generate(config);
    let sk = ServerKey::new(&ck);
    tfhe::set_server_key(sk);

    let mut buf = Vec::new();
    safe_serialize(&ck, &mut buf, LIMIT).expect("serialize ck");
    fs::write(dir.join("client_key.bin"), &buf).expect("write ck");

    let mut entries = Vec::new();
    let mut push = |file: &str, uint_type: i32, value: U256, bytes: Vec<u8>| {
        let be: [u8; 32] = value.to_big_endian();
        entries.push(Entry {
            file: file.to_string(),
            uint_type,
            value_be_hex: hex::encode(be),
            commit_hash_hex: hex::encode(calc_commitment(&bytes)),
        });
        fs::write(dir.join(file), &bytes).expect("write fixture");
    };
    macro_rules! vector {
        ($file:expr, $ty:expr, $fhety:ty, $val:expr, $u256:expr) => {{
            let ct = <$fhety>::encrypt($val, &ck).compress();
            let mut b = Vec::new();
            safe_serialize(&ct, &mut b, LIMIT).expect("serialize ct");
            push($file, $ty, $u256, b);
        }};
    }

    vector!("bool_true.bin", 0, FheBool, true, U256::one());
    vector!("u8_ab.bin", 2, FheUint8, 0xABu8, U256::from(0xABu8));
    vector!(
        "u32_deadbeef.bin",
        4,
        FheUint32,
        0xDEAD_BEEFu32,
        U256::from(0xDEAD_BEEFu32)
    );
    vector!("u64_max.bin", 5, FheUint64, u64::MAX, U256::from(u64::MAX));
    vector!(
        "u128_max.bin",
        6,
        FheUint128,
        u128::MAX,
        U256::from(u128::MAX)
    );
    vector!(
        "u160_addr.bin",
        7,
        FheUint160,
        0xFFFF_FFFF_FFFF_FFFFu64,
        U256::from(0xFFFF_FFFF_FFFF_FFFFu64)
    );

    let manifest = Manifest {
        tfhe_version: "1.5.1".to_string(),
        entries,
    };
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");
    println!("golden fixtures regenerated at {}", dir.display());
}
