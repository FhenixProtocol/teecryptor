//! TDX bootstrap modules — **BORROW-NOT-FORK**.
//!
//! Copied verbatim from cofhe `tools/tdx-signer-poc` (PR #706, commit
//! `ccd20d3bba65c975ec0abf73e4f4f363c2183e8e`). Phase 2 extracts these to a
//! public `fhenix/tdx-common` crate; **do not modify the submodules without
//! intent to upstream there.** They are exempt from the crate's stricter
//! `missing_docs` lint to stay byte-for-byte with the source.
#![allow(missing_docs)]

pub mod attestation;
pub mod secrets;
