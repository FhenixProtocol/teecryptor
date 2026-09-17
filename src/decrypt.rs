//! [`EncryptionType`] (the cofhe wire-type discriminants, shared across the
//! decrypt paths) and the **legacy** plain-decrypt path.
//!
//! The active path is [`crate::direct_decrypt`], which decrypts the engine's
//! stored *compressed* form. The plain path here — decrypting an
//! already-expanded `safe_serialize`d `FheUintN`/`FheBool` with a `ServerKey`-
//! free `ClientKey` decrypt — is unreachable at runtime (the HTTP gate rejects
//! non-compressed ciphertexts) and is compiled only under the
//! `legacy-plain-decrypt` feature, pending removal.

use primitive_types::U256;
#[cfg(feature = "legacy-plain-decrypt")]
use tfhe::integer::bigint::StaticUnsignedBigInt;
#[cfg(feature = "legacy-plain-decrypt")]
use tfhe::prelude::FheDecrypt;
#[cfg(feature = "legacy-plain-decrypt")]
use tfhe::safe_serialization::safe_deserialize;
#[cfg(feature = "legacy-plain-decrypt")]
use tfhe::{ClientKey, FheBool, FheUint128, FheUint16, FheUint160, FheUint32, FheUint64, FheUint8};

use crate::error::DecryptError;

/// Upper bound on a deserialized ciphertext for the legacy plain path, matching
/// cofhe's `safe_serde` cap. The active compressed path uses the much tighter
/// `CT_SIZE_LIMIT` in [`crate::direct_decrypt`].
#[cfg(feature = "legacy-plain-decrypt")]
const LEGACY_CT_SIZE_LIMIT: u64 = 1 << 30; // 1 GiB

/// cofhe's decrypt-supported `EncryptionType` wire variants.
///
/// The discriminant i32 values are **non-contiguous** and must match cofhe's
/// proto exactly. Teecryptor supports widths up to 160 bits (address); the
/// 256-bit and signed-integer proto variants are rejected as unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    /// Encrypted boolean.
    Bool = 0,
    /// Encrypted `u8`.
    U8 = 2,
    /// Encrypted `u16`.
    U16 = 3,
    /// Encrypted `u32`.
    U32 = 4,
    /// Encrypted `u64`.
    U64 = 5,
    /// Encrypted `u128`.
    U128 = 6,
    /// Encrypted 160-bit address (largest supported width).
    Address = 7,
}

impl EncryptionType {
    /// Map a wire `encryption_type` i32 to a supported variant.
    pub fn from_i32(v: i32) -> Result<Self, DecryptError> {
        match v {
            0 => Ok(Self::Bool),
            2 => Ok(Self::U8),
            3 => Ok(Self::U16),
            4 => Ok(Self::U32),
            5 => Ok(Self::U64),
            6 => Ok(Self::U128),
            7 => Ok(Self::Address),
            other => Err(DecryptError::UnsupportedType(other)),
        }
    }

    /// Plaintext width of this type, in bits (`Bool` = 1, `Address` = 160). Used
    /// to reject a ciphertext whose real block count exceeds its declared type.
    pub fn bits(self) -> usize {
        match self {
            Self::Bool => 1,
            Self::U8 => 8,
            Self::U16 => 16,
            Self::U32 => 32,
            Self::U64 => 64,
            Self::U128 => 128,
            Self::Address => 160,
        }
    }

    /// Lowercase type name, for metric label values (`encryption_type`). The
    /// numeric wire discriminant stays the wire/log representation; a name is
    /// what a dashboard query is written against.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Address => "address",
        }
    }

    /// Encode a decrypted `U256` as the type-sized big-endian byte slice cofhe
    /// uses on the wire (`u32` → 4 bytes, `Address` → 20 bytes). These are the
    /// bytes handed to `seal::seal_to_user`.
    pub fn encode(self, value: U256) -> Vec<u8> {
        let width = match self {
            Self::Bool | Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
            Self::U128 => 16,
            Self::Address => 20,
        };
        let buf: [u8; 32] = value.to_big_endian();
        buf[32 - width..].to_vec()
    }
}

/// Decrypt plain `safe_serialize`d ciphertext `bytes` of type `ty` to a
/// big-endian `U256`.
#[cfg(feature = "legacy-plain-decrypt")]
pub fn decrypt(
    client_key: &ClientKey,
    ty: EncryptionType,
    bytes: &[u8],
) -> Result<U256, DecryptError> {
    match ty {
        EncryptionType::Bool => decrypt_bool(client_key, bytes),
        EncryptionType::U8 => decrypt_u8(client_key, bytes),
        EncryptionType::U16 => decrypt_u16(client_key, bytes),
        EncryptionType::U32 => decrypt_u32(client_key, bytes),
        EncryptionType::U64 => decrypt_u64(client_key, bytes),
        EncryptionType::U128 => decrypt_u128(client_key, bytes),
        EncryptionType::Address => decrypt_address(client_key, bytes),
    }
}

#[cfg(feature = "legacy-plain-decrypt")]
fn de_err(label: &'static str) -> impl Fn(String) -> DecryptError {
    move |e| DecryptError::Deserialize(format!("{label}: {e}"))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_bool(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheBool = safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheBool"))?;
    let v: bool = ct.decrypt(ck);
    Ok(if v { U256::one() } else { U256::zero() })
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_u8(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint8 = safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint8"))?;
    let v: u8 = ct.decrypt(ck);
    Ok(U256::from(v))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_u16(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint16 =
        safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint16"))?;
    let v: u16 = ct.decrypt(ck);
    Ok(U256::from(v))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_u32(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint32 =
        safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint32"))?;
    let v: u32 = ct.decrypt(ck);
    Ok(U256::from(v))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_u64(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint64 =
        safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint64"))?;
    let v: u64 = ct.decrypt(ck);
    Ok(U256::from(v))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_u128(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint128 =
        safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint128"))?;
    let v: u128 = ct.decrypt(ck);
    Ok(U256::from(v))
}

#[cfg(feature = "legacy-plain-decrypt")]
fn decrypt_address(ck: &ClientKey, bytes: &[u8]) -> Result<U256, DecryptError> {
    let ct: FheUint160 =
        safe_deserialize(bytes, LEGACY_CT_SIZE_LIMIT).map_err(de_err("FheUint160"))?;
    // FheUint160 decrypts to a 3-limb (192-bit) big integer; the 160-bit value
    // fits in 24 big-endian bytes, left-zero-padded into the 32-byte U256 result.
    let v: StaticUnsignedBigInt<3> = ct.decrypt(ck);
    let mut be = [0u8; 24];
    v.copy_to_be_byte_slice(&mut be);
    Ok(U256::from_big_endian(&be))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_i32_maps_supported_and_rejects_rest() {
        assert_eq!(EncryptionType::from_i32(0).unwrap(), EncryptionType::Bool);
        assert_eq!(
            EncryptionType::from_i32(7).unwrap(),
            EncryptionType::Address
        );
        assert!(EncryptionType::from_i32(1).is_err()); // gap
        assert!(EncryptionType::from_i32(8).is_err()); // u256 unsupported (cap is 160)
        assert!(EncryptionType::from_i32(20).is_err()); // signed Int8
    }

    #[test]
    fn bits_are_the_plaintext_widths() {
        assert_eq!(EncryptionType::Bool.bits(), 1);
        assert_eq!(EncryptionType::U32.bits(), 32);
        assert_eq!(EncryptionType::Address.bits(), 160);
    }

    #[test]
    fn encode_truncates_to_type_width_big_endian() {
        let v = U256::from(0x0011_2233_4455_6677u64);
        assert_eq!(EncryptionType::U8.encode(v), vec![0x77]);
        assert_eq!(EncryptionType::U16.encode(v), vec![0x66, 0x77]);
        assert_eq!(EncryptionType::U32.encode(v), vec![0x44, 0x55, 0x66, 0x77]);
        assert_eq!(EncryptionType::Address.encode(v).len(), 20);
    }
}

#[cfg(all(test, feature = "legacy-plain-decrypt"))]
mod plain_tests {
    use super::*;
    use std::sync::OnceLock;
    use tfhe::prelude::FheEncrypt;
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::{generate_keys, ConfigBuilder};

    /// Generate the test `ClientKey` once and share it across every test in
    /// this module — keygen is the dominant cost in tfhe `cargo test` runs.
    fn shared_client_key() -> &'static ClientKey {
        static K: OnceLock<ClientKey> = OnceLock::new();
        K.get_or_init(|| generate_keys(ConfigBuilder::default().build()).0)
    }

    fn ser<T>(value: &T) -> Vec<u8>
    where
        T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
    {
        let mut buf = Vec::new();
        safe_serialize(value, &mut buf, LEGACY_CT_SIZE_LIMIT).expect("serialize");
        buf
    }

    #[test]
    fn round_trips_all_types() {
        let ck = shared_client_key();

        let bytes = ser(&FheBool::encrypt(true, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::Bool, &bytes).unwrap(),
            U256::one()
        );

        let bytes = ser(&FheUint8::encrypt(42u8, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U8, &bytes).unwrap(),
            U256::from(42u8)
        );

        let bytes = ser(&FheUint16::encrypt(4242u16, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U16, &bytes).unwrap(),
            U256::from(4242u16)
        );

        let bytes = ser(&FheUint32::encrypt(42_000u32, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U32, &bytes).unwrap(),
            U256::from(42_000u32)
        );

        let bytes = ser(&FheUint64::encrypt(42_000_000_000u64, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U64, &bytes).unwrap(),
            U256::from(42_000_000_000u64)
        );

        let bytes = ser(&FheUint128::encrypt(42u128, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U128, &bytes).unwrap(),
            U256::from(42u128)
        );

        let bytes = ser(&FheUint160::encrypt(123u32, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::Address, &bytes).unwrap(),
            U256::from(123u32)
        );
    }

    #[test]
    fn garbage_bytes_rejected() {
        assert!(decrypt(shared_client_key(), EncryptionType::U8, &[0xde, 0xad]).is_err());
    }

    #[test]
    fn bool_false_decrypts_to_zero() {
        let ck = shared_client_key();
        let bytes = ser(&FheBool::encrypt(false, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::Bool, &bytes).unwrap(),
            U256::zero()
        );
    }

    #[test]
    fn width_max_boundaries_round_trip() {
        let ck = shared_client_key();

        let bytes = ser(&FheUint8::encrypt(u8::MAX, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U8, &bytes).unwrap(),
            U256::from(u8::MAX)
        );

        let bytes = ser(&FheUint16::encrypt(u16::MAX, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U16, &bytes).unwrap(),
            U256::from(u16::MAX)
        );

        let bytes = ser(&FheUint32::encrypt(u32::MAX, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U32, &bytes).unwrap(),
            U256::from(u32::MAX)
        );

        let bytes = ser(&FheUint64::encrypt(u64::MAX, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U64, &bytes).unwrap(),
            U256::from(u64::MAX)
        );

        let bytes = ser(&FheUint128::encrypt(u128::MAX, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U128, &bytes).unwrap(),
            U256::from(u128::MAX)
        );
    }

    #[test]
    fn width_zero_round_trip() {
        let ck = shared_client_key();

        let bytes = ser(&FheUint8::encrypt(0u8, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U8, &bytes).unwrap(),
            U256::zero()
        );

        let bytes = ser(&FheUint128::encrypt(0u128, ck));
        assert_eq!(
            decrypt(ck, EncryptionType::U128, &bytes).unwrap(),
            U256::zero()
        );
    }

    // Light proptest: 8 random u32 values round-trip through encrypt+decrypt.
    // Capped low because each iteration runs real tfhe encrypt+decrypt, which is
    // ~tens of ms even with opt-level=3-stripped dev builds. Catches off-by-one
    // and packing bugs without dominating CI.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 8, .. proptest::prelude::ProptestConfig::default() })]

        #[test]
        fn proptest_u32_round_trips(v: u32) {
            let ck = shared_client_key();
            let bytes = ser(&FheUint32::encrypt(v, ck));
            let got = decrypt(ck, EncryptionType::U32, &bytes).unwrap();
            proptest::prop_assert_eq!(got, U256::from(v));
        }
    }
}
