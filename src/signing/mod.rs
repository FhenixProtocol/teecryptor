//! Response signing for Teecryptor — mirrors the cofhe dispatcher's signing module.
//!
//! BORROW-NOT-FORK: `signer`, `message_builder`, `evm_address`, and `error` are
//! copied verbatim from `FhenixProtocol/cofhe/rust-common/src/signing/` with only
//! the keccak import adapted (alloy::primitives instead of tiny-keccak).
//! Phase 2 extracts these to a shared `fhenix/tdx-common` crate.
//!
//! `service` mirrors `dispatcher/src/signing/service.rs`: same byte layouts
//! for `sign_decrypt` and `sign_sealoutput`, loaded from a Secret Manager secret
//! at boot instead of from a file.

#![allow(missing_docs)]

pub(crate) mod error;
pub(crate) mod evm_address;
pub(crate) mod message_builder;
pub mod service;
pub(crate) mod signer;

pub use error::SigningError;
pub use evm_address::EvmAddress;
pub use message_builder::SigningMessageBuilder;
pub use signer::{SignatureVFormat, Signer};
