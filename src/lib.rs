//! # Teecryptor
//!
//! A TDX-attested TFHE decryption service. A single GCP Confidential Space
//! (Intel TDX) VM decrypts cofhe FHE ciphertexts using an FHE [`ClientKey`]
//! fetched at boot from Secret Manager, gated by image-digest attestation.
//!
//! The crate is split into small modules (boot, HTTP, ct-source client,
//! decryption, key store, error taxonomy) that land incrementally. The single
//! security property the service provides: the FHE secret key is only ever
//! materialized inside the attested image.
//!
//! # Phase 1 MVP
//!
//! `SECURITY-OVERVIEW.md` states the security claim this phase makes and lists
//! what stays out of scope.
//!
//! [`ClientKey`]: https://docs.rs/tfhe/latest/tfhe/struct.ClientKey.html

pub mod boot;
pub mod cofhe_layout;
pub mod commitment;
pub mod cpu;
pub mod ct_source;
pub mod decrypt;
pub mod direct_decrypt;
pub mod error;
pub mod http;
pub mod key_source;
pub mod keys;
pub mod metrics;
pub mod permit;
pub mod seal;
pub mod signing;
pub mod tdx_common;

#[cfg(test)]
mod test_support;
