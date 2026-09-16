//! Crate-wide error types.
//!
//! Phase 1 keeps errors flat and per-module ([`TeecryptorError`] for key load,
//! [`DecryptError`] for the decrypt path, `CtFetchError` in `ct_source`). The
//! HTTP layer maps each to a status + stable error code.
//! [`ErrorResponse`] is the JSON error body returned to callers.

use serde::Serialize;
use thiserror::Error;

/// JSON error body returned by the HTTP layer.
///
/// The body carries the stable error code and nothing else. Internal detail
/// (a parse error, a configured value, an upstream message) stays in the
/// server log. A client acts on the status and the code; a human message would
/// only widen what the service reveals.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Stable, machine-readable error code (e.g. `"ct_not_found"`).
    pub error: &'static str,
    /// v1 only: old v1 clients surface `error_message`, so it repeats the code
    /// there. v2 omits the key, like the dispatcher's v2 routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<&'static str>,
}

/// Top-level error type for the Teecryptor service.
#[derive(Debug, Error)]
pub enum TeecryptorError {
    /// Loading or deserializing the FHE `ClientKey` failed.
    #[error("key load failed: {0}")]
    KeyLoad(String),
}

/// Errors from the decryption path ([`crate::decrypt`]).
///
/// The structural variants below are the security-relevant rejections of a
/// malformed or hostile compressed ciphertext (`safe_deserialize` runs without
/// conformance, so every field is attacker-controlled until [`crate::direct_decrypt`]
/// validates it). They are typed rather than stringly so tests can assert the
/// exact reason and logs/metrics can distinguish them.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// The wire `encryption_type` is not a decrypt-supported variant.
    #[error("unsupported encryption_type: {0}")]
    UnsupportedType(i32),
    /// A ciphertext whose real block count exceeds the handle-declared type.
    #[error("ciphertext wider than declared type: {got_bits} bits > {max_bits}")]
    WidthExceeded {
        /// Real width of the served ciphertext, in bits.
        got_bits: usize,
        /// Maximum width allowed by the declared type, in bits.
        max_bits: usize,
    },
    /// A block declared message/carry moduli that differ from the key's.
    #[error("block moduli do not match the key")]
    ModuliMismatch,
    /// The ciphertext's LWE dimension does not match the key's.
    #[error("LWE dimension mismatch: ct {ct} vs key {key}")]
    DimensionMismatch {
        /// LWE dimension declared by the ciphertext.
        ct: usize,
        /// LWE dimension of the decryption key.
        key: usize,
    },
    /// The packed structure (`initial_len` / `packed_coeffs` length) is
    /// internally inconsistent — rejected before unpacking.
    #[error("packed ciphertext structure is inconsistent")]
    PackedLenMismatch,
    /// The block's atomic pattern is not `Standard(KeyswitchBootstrap)`.
    #[error("unexpected atomic pattern (expected Standard KeyswitchBootstrap)")]
    WrongAtomicPattern,
    /// `safe_deserialize` of the ciphertext bytes failed.
    #[error("deserialize failed: {0}")]
    Deserialize(String),
    /// Direct decryption of a compressed ciphertext failed for another reason
    /// (unsupported form, out-of-range modulus, or an internal mirror-decode
    /// failure).
    #[error("direct decrypt failed: {0}")]
    DirectDecrypt(String),
}
