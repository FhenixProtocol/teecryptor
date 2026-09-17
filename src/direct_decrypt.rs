//! Direct client-key decryption of modulus-switched **compressed** ciphertexts
//! — no `decompress()`, no PBS, no `ServerKey`, and no patched tfhe.
//!
//! Why this exists: cofhe's fhe-engine stores computed results in tfhe's
//! modulus-switched compressed form (`FheUint::compress()`), and the on-chain
//! commitment is `keccak(compressed_bytes ‖ zone)` over exactly those bytes.
//! Re-expanding them anywhere else can never reproduce committed bytes,
//! because `decompress()` runs a PBS whose output depends on the FFT backend
//! (SIMD dispatch + plan selection) of the machine that runs it. Verifying the
//! commitment over the *stored* bytes and decrypting them directly removes
//! byte-reproducibility from the trust story entirely.
//!
//! Why it is sound: the modulus-switched compressed ct is still an LWE
//! ciphertext under the client's small LWE secret key — every coefficient
//! rounded from 64 bits down to `log_modulus` (= log2(2N)) bits. tfhe's
//! `decompress()` PBS exists only to produce a ct that supports *further
//! computation* (noise refresh); a key holder that only wants the plaintext
//! can decrypt with a dot product. The decode window is the same one the
//! decompression PBS itself uses for its blind rotation, so correctness
//! carries the same failure bound (p_fail) as the decompress path.
//!
//! How the private fields are reached without forking tfhe: the stored bytes
//! are `safe_serialize`d (header + recursively *versionized* encoding), so we
//! first let tfhe's own public `safe_deserialize` handle that wire format,
//! then re-encode the value with plain `bincode` and deserialize *those*
//! bytes into local mirror structs that replicate the (much simpler)
//! non-versionized serde layout, field-for-field and variant-for-variant.
//! The mirrors bottom out at public core_crypto types — in particular
//! `PackedIntegers<u64>`, whose fields (`initial_len`, `log_modulus`,
//! `packed_coeffs`) are validated against the key *before* unpacking, since
//! `safe_deserialize` runs without conformance and its own `extract()` would
//! unpack (and allocate) straight from attacker-controlled lengths. The
//! round-trip costs microseconds on a ~12 KB ct. Layout drift is pinned away by
//! the exact `tfhe = "=1.5.1"` dependency; the round-trip tests below fail
//! loudly if a bump ever changes the layout.
//!
//! Scope: only the `ModulusSwitched` compressed variant — the only form
//! fhe-engine produces (`res.compress()` calls
//! `switch_modulus_and_compress_parallelized`). The `Seeded` variant (client
//! side compressed *encryption*) never flows through engine storage and is
//! rejected explicitly.

use primitive_types::U256;
use serde::Deserialize;
use tfhe::core_crypto::prelude::compressed_modulus_switched_multi_bit_lwe_ciphertext::CompressedModulusSwitchedMultiBitLweCiphertext;
use tfhe::core_crypto::prelude::packed_integers::PackedIntegers;
use tfhe::core_crypto::prelude::{LweDimension, PBSOrder};
use tfhe::safe_serialization::safe_deserialize;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::{AtomicPatternKind, CarryModulus, MessageModulus};
use tfhe::{
    ClientKey, CompressedFheBool, CompressedFheUint128, CompressedFheUint16, CompressedFheUint160,
    CompressedFheUint32, CompressedFheUint64, CompressedFheUint8, Tag,
};
use zeroize::Zeroizing;

use crate::decrypt::EncryptionType;
use crate::error::DecryptError;

/// Upper bound on a single deserialized ciphertext. The largest supported class
/// (`CompressedFheUint160`) is ~150 KB in modulus-switched compressed form, so
/// 1 MiB is ~7× the largest legitimate ct while denying a hostile ct-server a
/// multi-GB allocation through `safe_deserialize`. (cofhe's `safe_serde` caps
/// at 1 GiB, but that bounds whole batch payloads, not one ciphertext.)
const CT_SIZE_LIMIT: u64 = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Serde mirrors of tfhe 1.5.1's plain (non-versionized) layouts.
//
// bincode encodes structs as their fields in declaration order and enums as a
// u32 variant index + payload, so each mirror must list fields/variants in
// exactly the order of the tfhe original (cited per item). Zero-sized fields
// (`id` marker on CompressedFheUint) encode to nothing and are omitted.
// ---------------------------------------------------------------------------

/// Mirror of `high_level_api::integers::unsigned::compressed::CompressedFheUint`
/// (fields: `ciphertext`, `id` (zero-sized), `tag`).
#[derive(Deserialize)]
struct UintMirror {
    ciphertext: RadixMirror,
    #[allow(dead_code)]
    tag: Tag,
}

/// Mirror of hl `CompressedRadixCiphertext` (variants: `Seeded`,
/// `ModulusSwitched`). The seeded payload is deserialized into the public
/// integer type only to keep the variant shape; it is rejected right after.
#[derive(Deserialize)]
enum RadixMirror {
    // Payloads of rejected variants are never read, but must be present (and
    // correctly typed) so bincode can decode past the variant tag.
    Seeded(#[allow(dead_code)] tfhe::integer::ciphertext::CompressedRadixCiphertext),
    ModulusSwitched(MsRadixMirror),
}

/// Mirror of `integer::ciphertext::CompressedModulusSwitchedRadixCiphertext`
/// (newtype over the `Generic` struct).
#[derive(Deserialize)]
struct MsRadixMirror(GenericMirror);

/// Mirror of `CompressedModulusSwitchedRadixCiphertextGeneric`
/// (fields: `paired_blocks`, `last_block`).
#[derive(Deserialize)]
struct GenericMirror {
    paired_blocks: Vec<BlockMirror>,
    last_block: Option<BlockMirror>,
}

/// Mirror of `shortint::ciphertext::CompressedModulusSwitchedCiphertext`
/// (fields: `compressed_modulus_switched_lwe_ciphertext`, `degree`,
/// `message_modulus`, `carry_modulus`, `atomic_pattern`).
#[derive(Deserialize)]
struct BlockMirror {
    compressed_modulus_switched_lwe_ciphertext: InternalMirror,
    /// `Degree` mirrored as its newtype payload — the tfhe type's field is
    /// crate-private and the value is not needed for decoding.
    #[allow(dead_code)]
    degree: u64,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    atomic_pattern: AtomicPatternKind,
}

/// Mirror of `shortint::ciphertext::InternalCompressedModulusSwitchedCiphertext`
/// (variants: `Classic`, `MultiBit`).
#[derive(Deserialize)]
enum InternalMirror {
    Classic(ClassicMsCtMirror),
    MultiBit(#[allow(dead_code)] CompressedModulusSwitchedMultiBitLweCiphertext<u64>),
}

/// Mirror of core_crypto `CompressedModulusSwitchedLweCiphertext<u64>`
/// (fields: `packed_integers`, `lwe_dimension`).
///
/// tfhe's own type exposes only `extract()`, which unpacks *before* it can be
/// validated — and `unpack()` reserves `initial_len` elements up front from a
/// `TrustedLen` iterator, so an attacker-inflated `initial_len` (unchecked
/// because `safe_deserialize` runs without conformance) is an
/// allocation-abort primitive that `spawn_blocking` cannot catch. Mirroring one
/// level deeper exposes `packed_integers`/`lwe_dimension` through their public
/// accessors so [`decode_block`] can bound every field before unpacking. Both
/// field types are public core_crypto types.
#[derive(Deserialize)]
struct ClassicMsCtMirror {
    packed_integers: PackedIntegers<u64>,
    lwe_dimension: LweDimension,
}

/// Mirror of `high_level_api::booleans::compressed::CompressedFheBool`
/// (fields: `inner`, `tag`).
#[derive(Deserialize)]
struct BoolMirror {
    inner: InnerBoolMirror,
    #[allow(dead_code)]
    tag: Tag,
}

/// Mirror of hl `InnerCompressedFheBool` (variants: `Seeded`, `ModulusSwitched`).
#[derive(Deserialize)]
enum InnerBoolMirror {
    Seeded(#[allow(dead_code)] tfhe::shortint::ciphertext::CompressedCiphertext),
    ModulusSwitched(BlockMirror),
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

/// The small LWE secret key extracted from a [`ClientKey`], as raw binary
/// coefficients. This is secret material — held in a [`Zeroizing`] buffer so
/// it is wiped on drop, same posture as the `ClientKey` it came from.
///
/// Modulus-switched compression keyswitches the block to the *small* key
/// before rounding, so this — not the big/GLWE key — is the key that
/// decrypts the compressed form.
pub struct DirectDecryptKey {
    small_lwe_key: Zeroizing<Vec<u64>>,
    /// Message/carry moduli from the *key's* parameters — the true digit width.
    /// Taken from the key and never from the ciphertext: a hostile ct-server
    /// controls the moduli a block declares, and trusting them enables a
    /// div-by-zero (`space == 0`) or a silent `2·msg·carry` overflow-wrap that
    /// decodes to a wrong-but-valid plaintext. Every block is checked equal to
    /// these before decoding.
    message_modulus: u64,
    carry_modulus: u64,
}

impl DirectDecryptKey {
    /// Extract the small LWE secret key and the message/carry moduli from `ck`.
    ///
    /// Built once at [`crate::keys::KeyStore`] load — not per decrypt — because
    /// it clones the client key (tens of KB): tfhe only exposes the parts
    /// by-value via `into_raw_parts`.
    pub fn from_client_key(ck: &ClientKey) -> Result<Self, DecryptError> {
        let (integer_ck, _, _, _, _, _, _) = ck.clone().into_raw_parts();
        let shortint_ck = integer_ck.into_raw_parts();
        let params = shortint_ck.parameters();
        let message_modulus = params.message_modulus().0;
        let carry_modulus = params.carry_modulus().0;
        match &shortint_ck.atomic_pattern {
            AtomicPatternClientKey::Standard(ap) => Ok(Self {
                small_lwe_key: Zeroizing::new(ap.small_lwe_secret_key().as_ref().to_vec()),
                message_modulus,
                carry_modulus,
            }),
            _ => Err(DecryptError::DirectDecrypt(
                "unsupported atomic pattern (expected Standard)".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt modulus-switched compressed ciphertext `bytes` of type `ty`
/// directly to a big-endian `U256`.
///
/// The bytes must be the engine's stored form: `safe_serialize`d
/// `CompressedFheUintN` / `CompressedFheBool` with the `ModulusSwitched`
/// inner variant.
pub fn decrypt_compressed(
    key: &DirectDecryptKey,
    ty: EncryptionType,
    bytes: &[u8],
) -> Result<U256, DecryptError> {
    // `max_bits` reject-guards a hostile ct-server: tfhe's `Named::NAME` is
    // width-generic (every `CompressedFheUintN` shares one name), so
    // `safe_deserialize` cannot tell a `CompressedFheUint64` from a
    // `CompressedFheUint8` — only Bool↔Uint is caught. [`decode_radix`] rejects
    // any ct whose real block count exceeds the declared type's width so the TEE
    // never signs a wrong-width value. (Type *identity* is bound separately by
    // the handle's type byte, cross-checked at the HTTP layer.)
    let max_bits = ty.bits();
    match ty {
        EncryptionType::Bool => decrypt_bool(key, bytes),
        EncryptionType::U8 => {
            decrypt_uint::<CompressedFheUint8>(key, bytes, "CompressedFheUint8", max_bits)
        }
        EncryptionType::U16 => {
            decrypt_uint::<CompressedFheUint16>(key, bytes, "CompressedFheUint16", max_bits)
        }
        EncryptionType::U32 => {
            decrypt_uint::<CompressedFheUint32>(key, bytes, "CompressedFheUint32", max_bits)
        }
        EncryptionType::U64 => {
            decrypt_uint::<CompressedFheUint64>(key, bytes, "CompressedFheUint64", max_bits)
        }
        EncryptionType::U128 => {
            decrypt_uint::<CompressedFheUint128>(key, bytes, "CompressedFheUint128", max_bits)
        }
        EncryptionType::Address => {
            decrypt_uint::<CompressedFheUint160>(key, bytes, "CompressedFheUint160", max_bits)
        }
    }
}

/// safe_deserialize (tfhe handles header + versionized layout) then re-encode
/// with plain bincode so the local mirrors can read the private fields.
fn to_mirror<T, M>(bytes: &[u8], label: &'static str) -> Result<M, DecryptError>
where
    T: serde::Serialize + serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
    M: serde::de::DeserializeOwned,
{
    let ct: T = safe_deserialize(bytes, CT_SIZE_LIMIT)
        .map_err(|e| DecryptError::Deserialize(format!("{label}: {e}")))?;
    let plain = bincode::serialize(&ct)
        .map_err(|e| DecryptError::DirectDecrypt(format!("{label} re-encode: {e}")))?;
    bincode::deserialize(&plain)
        .map_err(|e| DecryptError::DirectDecrypt(format!("{label} mirror layout: {e}")))
}

fn decrypt_uint<T>(
    key: &DirectDecryptKey,
    bytes: &[u8],
    label: &'static str,
    max_bits: usize,
) -> Result<U256, DecryptError>
where
    T: serde::Serialize + serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
{
    let mirror: UintMirror = to_mirror::<T, _>(bytes, label)?;
    let radix = match &mirror.ciphertext {
        RadixMirror::ModulusSwitched(ms) => &ms.0,
        RadixMirror::Seeded(_) => {
            return Err(DecryptError::DirectDecrypt(
                "seeded compressed ct: not an engine-stored form".into(),
            ))
        }
    };
    decode_radix(key, radix, max_bits)
}

fn decrypt_bool(key: &DirectDecryptKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let mirror: BoolMirror = to_mirror::<CompressedFheBool, _>(bytes, "CompressedFheBool")?;
    match &mirror.inner {
        InnerBoolMirror::ModulusSwitched(block) => {
            let (m, msg_mod) = decode_block(key, block)?;
            Ok(if m % msg_mod != 0 {
                U256::one()
            } else {
                U256::zero()
            })
        }
        InnerBoolMirror::Seeded(_) => Err(DecryptError::DirectDecrypt(
            "seeded compressed bool: not an engine-stored form".into(),
        )),
    }
}

/// Decode a full radix ciphertext into a `U256`.
///
/// Integer-layer compression packs radix blocks in pairs before the modulus
/// switch — `packed = low + msg_mod·high` (see tfhe's
/// `switch_modulus_and_compress_generic_parallelized`) — with an odd trailing
/// block stored unpaired in `last_block`. Digits are little-endian base
/// `msg_mod`, mirroring the `x % msg_mod` / `x / msg_mod` lookup tables the
/// decompression PBS would apply.
fn decode_radix(
    key: &DirectDecryptKey,
    radix: &GenericMirror,
    max_bits: usize,
) -> Result<U256, DecryptError> {
    // Every block's digit width comes from `key` (see [`decode_block`]), so
    // `msg_mod` here is the key's message modulus, not attacker data.
    // `msg_mod >= 2` also guards `bits_per_digit != 0`: a degenerate modulus of
    // 1 is a power of two but would make `next_multiple_of(0)` below panic.
    let msg_mod = key.message_modulus;
    if !msg_mod.is_power_of_two() || msg_mod < 2 {
        return Err(DecryptError::DirectDecrypt(format!(
            "invalid message modulus {msg_mod}"
        )));
    }
    let bits_per_digit = msg_mod.trailing_zeros() as usize;

    let mut digits: Vec<u64> = Vec::with_capacity(2 * radix.paired_blocks.len() + 1);
    for block in &radix.paired_blocks {
        let (m, msg_mod) = decode_block(key, block)?;
        digits.push(m % msg_mod);
        digits.push((m / msg_mod) % msg_mod);
    }
    if let Some(block) = &radix.last_block {
        let (m, msg_mod) = decode_block(key, block)?;
        digits.push(m % msg_mod);
    }
    if digits.is_empty() {
        return Err(DecryptError::DirectDecrypt("empty radix ciphertext".into()));
    }

    // Reject a ciphertext whose real width exceeds the caller-declared type
    // (`uint_type` from ct-server). Without this, a `CompressedFheUint64`
    // relabelled `U8` decodes to its full 64-bit value and the TEE signs a
    // wrong-type result — the exact hostile-ct-server model this path defends.
    let total_bits = bits_per_digit
        .checked_mul(digits.len())
        .ok_or_else(|| DecryptError::DirectDecrypt("digit width overflow".into()))?;
    if total_bits > max_bits.next_multiple_of(bits_per_digit) {
        return Err(DecryptError::WidthExceeded {
            got_bits: total_bits,
            max_bits,
        });
    }

    let mut value = U256::zero();
    for (i, d) in digits.iter().enumerate() {
        value |= U256::from(*d) << (bits_per_digit * i);
    }
    Ok(value)
}

/// Decrypt one compressed shortint block: extract the modulus-switched LWE,
/// take the dot product with the small secret key, and round to the cleartext
/// space. Returns `(m, msg_mod)` where `m` is the raw decoded value in
/// `[0, 2·msg_mod·carry_mod)` (padding bit included in the space).
fn decode_block(key: &DirectDecryptKey, block: &BlockMirror) -> Result<(u64, u64), DecryptError> {
    // 1. Digit width from the key, never the ciphertext. Rejecting a block that
    //    declares different moduli kills both the div-by-zero (`space == 0`) and
    //    the silent `2·msg·carry` overflow-wrap, and — because the two fields
    //    are adjacent same-typed u64s — makes a future mirror field-swap fail
    //    loudly whenever msg != carry (invisible otherwise).
    if block.message_modulus.0 != key.message_modulus || block.carry_modulus.0 != key.carry_modulus
    {
        return Err(DecryptError::ModuliMismatch);
    }

    // 2. Small-key direct decryption is only valid for the KS→PBS order (the
    //    compressed form the engine stores). Assert it rather than relying on
    //    the dimension check to reject a wrong order incidentally.
    if !matches!(
        block.atomic_pattern,
        AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap)
    ) {
        return Err(DecryptError::WrongAtomicPattern);
    }

    let ct = match &block.compressed_modulus_switched_lwe_ciphertext {
        InternalMirror::Classic(c) => c,
        InternalMirror::MultiBit(_) => {
            return Err(DecryptError::DirectDecrypt(
                "multi-bit compressed ct unsupported".into(),
            ))
        }
    };

    // 3. Validate the packed structure BEFORE unpacking. safe_deserialize runs
    //    without conformance, so `initial_len`/`log_modulus`/`packed_coeffs`
    //    are raw attacker data here. `unpack()` reserves `initial_len` elements
    //    up front, so an unchecked `initial_len` forces an uncatchable
    //    allocation abort; these four checks make unpack provably panic- and
    //    abort-free.
    let sk: &[u64] = &key.small_lwe_key;
    let lwe_dim = ct.lwe_dimension.0;
    if lwe_dim != sk.len() {
        return Err(DecryptError::DimensionMismatch {
            ct: lwe_dim,
            key: sk.len(),
        });
    }
    let log_mod = ct.packed_integers.log_modulus().0;
    if !(1..64).contains(&log_mod) {
        return Err(DecryptError::DirectDecrypt(format!(
            "invalid modulus log {log_mod}"
        )));
    }
    // A modulus-switched LWE ct stores exactly `lwe_dimension + 1` coefficients
    // (mask ‖ body); this is what `extract()` asserts internally.
    let initial_len = ct.packed_integers.initial_len();
    if initial_len != lwe_dim + 1 {
        return Err(DecryptError::PackedLenMismatch);
    }
    let expected_packed = initial_len
        .checked_mul(log_mod)
        .map(|bits| bits.div_ceil(u64::BITS as usize))
        .ok_or(DecryptError::PackedLenMismatch)?;
    if ct.packed_integers.packed_coeffs().len() != expected_packed {
        return Err(DecryptError::PackedLenMismatch);
    }

    // 4. Unpack (now safe) and decrypt. The container matches tfhe's
    //    StandardModulusSwitchedLweCiphertext layout: `[mask_0 .. mask_{n-1},
    //    body]`, each coefficient already reduced to `log_mod` bits by unpack().
    let coeffs: Vec<u64> = ct.packed_integers.unpack::<u64>().collect();
    let (body, mask) = coeffs
        .split_last()
        .expect("initial_len >= 1 (== lwe_dim + 1) verified above");

    let modulus_mask = (1u64 << log_mod) - 1;
    let dot = mask
        .iter()
        .zip(sk.iter())
        .map(|(a, s)| a.wrapping_mul(*s))
        .fold(0u64, |acc, x| acc.wrapping_add(x));
    let dec = body.wrapping_sub(dot) & modulus_mask;

    let msg_mod = key.message_modulus;
    let carry_mod = key.carry_modulus;
    // Cleartext space includes the padding bit: 2 · msg · carry levels. Both
    // moduli come from the key, so `space` is a nonzero power of two.
    let space = 2 * msg_mod * carry_mod;
    // Nearest-integer decode: m = round(dec · space / 2^log_mod) mod space.
    let m = (((dec as u128 * space as u128 + (1u128 << (log_mod - 1))) >> log_mod) as u64) % space;
    Ok((m, msg_mod))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use tfhe::core_crypto::prelude::CiphertextModulusLog;
    use tfhe::prelude::{FheDecrypt, FheEncrypt};
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::{
        ConfigBuilder, FheBool, FheUint128, FheUint16, FheUint160, FheUint32, FheUint64, FheUint8,
        ServerKey,
    };

    /// Keys under the engine's compute parameter set, generated once. The
    /// `ServerKey` is needed only to *produce* compressed cts in tests
    /// (`compress()` keyswitches + mod-switches); direct decryption never
    /// touches it.
    fn shared_keys() -> &'static (ClientKey, ServerKey) {
        static K: OnceLock<(ClientKey, ServerKey)> = OnceLock::new();
        K.get_or_init(|| {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS).build();
            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);
            (ck, sk)
        })
    }

    fn direct_key() -> DirectDecryptKey {
        DirectDecryptKey::from_client_key(&shared_keys().0).expect("key extraction")
    }

    fn ser<T>(value: &T) -> Vec<u8>
    where
        T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
    {
        let mut buf = Vec::new();
        safe_serialize(value, &mut buf, CT_SIZE_LIMIT).expect("serialize");
        buf
    }

    /// encrypt → compress → serialize, mirroring engine storage of a result.
    macro_rules! compressed_bytes {
        ($fhety:ty, $v:expr) => {{
            let (ck, sk) = shared_keys();
            tfhe::set_server_key(sk.clone());
            ser(&<$fhety>::encrypt($v, ck).compress())
        }};
    }

    #[test]
    fn u32_round_trips_and_matches_decompress_path() {
        let (ck, sk) = shared_keys();
        tfhe::set_server_key(sk.clone());
        let compressed = FheUint32::encrypt(0xDEAD_BEEFu32, ck).compress();
        let bytes = ser(&compressed);

        let direct = decrypt_compressed(&direct_key(), EncryptionType::U32, &bytes).unwrap();
        assert_eq!(direct, U256::from(0xDEAD_BEEFu32));

        // Cross-check against the reference decompress(PBS)+decrypt path.
        let reference: u32 = compressed.decompress().decrypt(ck);
        assert_eq!(direct, U256::from(reference));
    }

    #[test]
    fn bool_true_false() {
        let key = direct_key();
        let bytes = compressed_bytes!(FheBool, true);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::Bool, &bytes).unwrap(),
            U256::one()
        );
        let bytes = compressed_bytes!(FheBool, false);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::Bool, &bytes).unwrap(),
            U256::zero()
        );
    }

    #[test]
    fn width_boundaries_round_trip() {
        let key = direct_key();

        let bytes = compressed_bytes!(FheUint8, u8::MAX);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U8, &bytes).unwrap(),
            U256::from(u8::MAX)
        );

        let bytes = compressed_bytes!(FheUint64, u64::MAX);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U64, &bytes).unwrap(),
            U256::from(u64::MAX)
        );

        let bytes = compressed_bytes!(FheUint128, u128::MAX);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U128, &bytes).unwrap(),
            U256::from(u128::MAX)
        );

        let bytes = compressed_bytes!(FheUint8, 0u8);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U8, &bytes).unwrap(),
            U256::zero()
        );
    }

    #[test]
    fn address_160_round_trips() {
        let key = direct_key();
        let bytes = compressed_bytes!(FheUint160, 0xFFFF_FFFF_FFFF_FFFFu64);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::Address, &bytes).unwrap(),
            U256::from(0xFFFF_FFFF_FFFF_FFFFu64)
        );
    }

    #[test]
    fn computed_result_round_trips() {
        // Mirror the engine path exactly: FHE op → compress → store bytes.
        let (ck, sk) = shared_keys();
        tfhe::set_server_key(sk.clone());
        let a = FheUint32::encrypt(41u32, ck);
        let b = FheUint32::encrypt(1u32, ck);
        let bytes = ser(&(a + b).compress());
        assert_eq!(
            decrypt_compressed(&direct_key(), EncryptionType::U32, &bytes).unwrap(),
            U256::from(42u32)
        );
    }

    #[test]
    fn seeded_compressed_rejected() {
        let (ck, _) = shared_keys();
        // CompressedFheUint32::encrypt produces the Seeded variant (client-side
        // compressed encryption) — not an engine-stored form.
        let seeded = tfhe::CompressedFheUint32::encrypt(7u32, ck);
        let bytes = ser(&seeded);
        let err = decrypt_compressed(&direct_key(), EncryptionType::U32, &bytes).unwrap_err();
        assert!(matches!(err, DecryptError::DirectDecrypt(_)), "{err}");
    }

    #[test]
    fn plain_expanded_ct_rejected() {
        let (ck, _) = shared_keys();
        let bytes = ser(&FheUint32::encrypt(7u32, ck));
        // Type-name mismatch in safe_deserialize: plain FheUint32 bytes are
        // not a CompressedFheUint32.
        let err = decrypt_compressed(&direct_key(), EncryptionType::U32, &bytes).unwrap_err();
        assert!(matches!(err, DecryptError::Deserialize(_)), "{err}");
    }

    #[test]
    fn garbage_bytes_rejected() {
        let err =
            decrypt_compressed(&direct_key(), EncryptionType::U32, &[0xde, 0xad]).unwrap_err();
        assert!(matches!(err, DecryptError::Deserialize(_)), "{err}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 8, .. proptest::prelude::ProptestConfig::default() })]

        #[test]
        fn proptest_u32_round_trips(v: u32) {
            let bytes = compressed_bytes!(FheUint32, v);
            let got = decrypt_compressed(&direct_key(), EncryptionType::U32, &bytes).unwrap();
            proptest::prop_assert_eq!(got, U256::from(v));
        }
    }

    #[test]
    fn u16_round_trips() {
        let key = direct_key();
        let bytes = compressed_bytes!(FheUint16, 0xBEEFu16);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U16, &bytes).unwrap(),
            U256::from(0xBEEFu16)
        );
    }

    /// The one type whose purpose is a 160-bit address, exercised with bits set
    /// above bit 64 (previously only `0xFFFF_FFFF_FFFF_FFFF` was tested).
    #[test]
    fn address_high_bits_round_trip() {
        let key = direct_key();
        let v = 0x1234_5678_9abc_def0_fedc_ba98_7654_3210u128;
        let bytes = compressed_bytes!(FheUint160, v);
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::Address, &bytes).unwrap(),
            U256::from(v)
        );
    }

    // NOTE on mirror field-swap of message_modulus/carry_modulus (two adjacent
    // same-typed u64s): the only value-level detector is a round-trip under a
    // `message_modulus != carry_modulus` parameter set, but tfhe ships those
    // only behind `#[cfg(tarpaulin)]` and cofhe's params are always msg==carry
    // (so a swap is value-invisible: `space` is commutative and the digit split
    // is identical). The runtime key-vs-ct moduli check in `decode_block` — and
    // its `zero_message_modulus_rejected` / `overflow_modulus_rejected` tests —
    // is the guard: it fails loudly the moment a block's declared moduli differ
    // from the key's, which is exactly what a swap produces if cofhe ever adopts
    // msg != carry.

    /// A genuine `CompressedFheUint64` relabelled `U8`: `Named::NAME` is
    /// width-generic so `safe_deserialize` accepts it, but the width guard must
    /// refuse to hand a 64-bit value back under the narrower type — while the
    /// same bytes still decode under their true type.
    #[test]
    fn wider_type_than_declared_rejected() {
        let key = direct_key();
        let bytes = compressed_bytes!(FheUint64, 0x1234_5678_9abc_def0u64);
        let err = decrypt_compressed(&key, EncryptionType::U8, &bytes).unwrap_err();
        assert!(matches!(err, DecryptError::WidthExceeded { .. }), "{err}");
        assert_eq!(
            decrypt_compressed(&key, EncryptionType::U64, &bytes).unwrap(),
            U256::from(0x1234_5678_9abc_def0u64)
        );
    }

    // --- Adversarial block decoding: a hostile ct-server controls every field
    // below (safe_deserialize runs without conformance). Each must produce a
    // clean `Err`, never a panic and never an allocation abort. ---

    /// Craft a `PackedIntegers<u64>` with arbitrary field values. Its fields are
    /// private and its only public constructor (`pack`) validates, but a
    /// malformed on-the-wire ct decodes straight into these fields unchecked —
    /// so we reproduce that via a bincode round-trip. Serde encodes a struct as
    /// its fields in order and a newtype (`CiphertextModulusLog`) transparently,
    /// so this tuple is byte-identical to the real layout.
    fn craft_packed(
        packed_coeffs: Vec<u64>,
        log_modulus: usize,
        initial_len: usize,
    ) -> PackedIntegers<u64> {
        let bytes = bincode::serialize(&(
            packed_coeffs,
            CiphertextModulusLog(log_modulus),
            initial_len,
        ))
        .unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn craft_block(
        packed: PackedIntegers<u64>,
        lwe_dimension: usize,
        message_modulus: u64,
        carry_modulus: u64,
    ) -> BlockMirror {
        BlockMirror {
            compressed_modulus_switched_lwe_ciphertext: InternalMirror::Classic(
                ClassicMsCtMirror {
                    packed_integers: packed,
                    lwe_dimension: LweDimension(lwe_dimension),
                },
            ),
            degree: 0,
            message_modulus: MessageModulus(message_modulus),
            carry_modulus: CarryModulus(carry_modulus),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
        }
    }

    /// THE abort regression: `initial_len` claims 2^32 coefficients. Without the
    /// pre-unpack guard, `unpack().collect()` reserves ~34 GB → `abort()` (which
    /// `spawn_blocking` cannot catch). Must return `Err` instantly instead.
    #[test]
    fn inflated_initial_len_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 11, 1usize << 32);
        let block = craft_block(packed, n, 4, 4); // valid dimension; only initial_len is hostile
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::PackedLenMismatch), "{err}");
    }

    #[test]
    fn short_packed_coeffs_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        // Correct initial_len/dimension, but far too few packed coeffs — would
        // index out of bounds inside unpack() if it ran.
        let packed = craft_packed(vec![0u64; 4], 11, n + 1);
        let block = craft_block(packed, n, 4, 4);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::PackedLenMismatch), "{err}");
    }

    #[test]
    fn oversized_log_modulus_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 100, n + 1); // log_modulus > 64 → unpack would assert
        let block = craft_block(packed, n, 4, 4);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::DirectDecrypt(_)), "{err}");
    }

    #[test]
    fn wrong_lwe_dimension_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 11, n + 8);
        let block = craft_block(packed, n + 7, 4, 4);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(
            matches!(err, DecryptError::DimensionMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn zero_message_modulus_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 11, n + 1);
        // space = 2·0·carry = 0 → would be a div-by-zero at `% space`.
        let block = craft_block(packed, n, 0, 4);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::ModuliMismatch), "{err}");
    }

    #[test]
    fn overflow_modulus_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 11, n + 1);
        // Huge moduli would overflow-wrap `2·msg·carry` to a nonzero wrong value.
        let block = craft_block(packed, n, 1u64 << 40, 1u64 << 40);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::ModuliMismatch), "{err}");
    }

    #[test]
    fn wrong_pbs_order_rejected() {
        let key = direct_key();
        let n = key.small_lwe_key.len();
        let packed = craft_packed(vec![0u64; 4], 11, n + 1);
        let mut block = craft_block(packed, n, 4, 4);
        block.atomic_pattern = AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch);
        let err = decode_block(&key, &block).unwrap_err();
        assert!(matches!(err, DecryptError::WrongAtomicPattern), "{err}");
    }
}
