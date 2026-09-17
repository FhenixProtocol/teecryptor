// Copied verbatim from FhenixProtocol/cofhe rust-common/src/signing/signer.rs
// BORROW-NOT-FORK: Phase 2 extracts to a shared crate. Do not modify without intent to upstream.
// Adaptation: keccak256 uses alloy::primitives (already in dep tree) instead of tiny-keccak.

use k256::{
    ecdsa::{RecoveryId, Signature, SigningKey},
    elliptic_curve::scalar::IsHigh,
};

use super::error::SigningError;

/// Offset to convert raw recovery ID (0-3) to EVM-compatible format (27-28).
const EVM_RECOVERY_ID_OFFSET: u8 = 27;

/// Format for the signature's recovery ID (v value).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureVFormat {
    /// Raw k256 recovery ID format (0-3).
    #[default]
    Raw,
    /// EVM-compatible format (27-28), as expected by OpenZeppelin ECDSA.recover.
    Evm,
}

impl SignatureVFormat {
    pub fn convert_v(&self, raw_v: u8) -> u8 {
        match self {
            Self::Raw => raw_v,
            Self::Evm => raw_v + EVM_RECOVERY_ID_OFFSET,
        }
    }
}

impl std::str::FromStr for SignatureVFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "evm" => Self::Evm,
            _ => Self::Raw,
        })
    }
}

/// ECDSA signer for secp256k1 signatures. Produces signatures compatible with
/// EVM ecrecover: BIP-62 low-S normalized, 64-byte sig + 1-byte recovery id.
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e: k256::ecdsa::Error| SigningError::InvalidKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Keccak256 hash. Byte-identical to the rust_common implementation.
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        alloy::primitives::keccak256(data).0
    }

    /// Sign a pre-computed hash with BIP-62 low-S normalization.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<(Signature, RecoveryId), SigningError> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (sig, recid): (Signature, RecoveryId) = self.signing_key.sign_prehash(hash)?;
        let is_y_odd = recid.is_y_odd() ^ bool::from(sig.s().is_high());
        let sig_low = sig.normalize_s().unwrap_or(sig);
        let recid = RecoveryId::new(is_y_odd, recid.is_x_reduced());
        Ok((sig_low, recid))
    }

    /// Sign a prehash and return 130-char hex (64B sig + 1B recovery id).
    pub fn sign_prehash_to_hex_with_format(
        &self,
        hash: &[u8; 32],
        v_format: SignatureVFormat,
    ) -> Result<String, SigningError> {
        let (sig, recid) = self.sign_prehash(hash)?;
        let mut result: Vec<u8> = Vec::with_capacity(65);
        result.extend_from_slice(sig.to_bytes().as_slice());
        result.push(v_format.convert_v(recid.to_byte()));
        Ok(hex::encode(result))
    }
}
