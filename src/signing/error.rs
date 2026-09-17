// Copied verbatim from FhenixProtocol/cofhe rust-common/src/signing/error.rs
// BORROW-NOT-FORK: Phase 2 extracts this to a shared fhenix/tdx-common crate.
// Do not modify without intent to upstream there.

use thiserror::Error;

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Invalid signing key: {0}")]
    InvalidKey(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Failed to read key file: {0}")]
    KeyFileError(String),
    #[error("Failed to decode hex: {0}")]
    HexDecodeError(String),
}

impl From<k256::ecdsa::Error> for SigningError {
    fn from(err: k256::ecdsa::Error) -> Self {
        SigningError::SigningFailed(err.to_string())
    }
}
impl From<hex::FromHexError> for SigningError {
    fn from(err: hex::FromHexError) -> Self {
        SigningError::HexDecodeError(err.to_string())
    }
}
impl From<std::io::Error> for SigningError {
    fn from(err: std::io::Error) -> Self {
        SigningError::KeyFileError(err.to_string())
    }
}
