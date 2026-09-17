//! DEV ONLY: generate a tfhe-rs `ClientKey` and write its `safe_serialize` bytes
//! to stdout. Used by `make keys` to seed a dev Secret Manager version, and to
//! produce a throwaway key for local round-trip tests.
//!
//! This uses `ConfigBuilder::default()` parameters, which are not guaranteed to
//! match cofhe's deployed crypto parameters. Deployed environments take their key
//! from the keygen ceremony, never from this binary.

use std::io::Write;

use anyhow::Result;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{generate_keys, ConfigBuilder};

fn main() -> Result<()> {
    let (client_key, _server_key) = generate_keys(ConfigBuilder::default().build());
    let mut bytes = Vec::new();
    safe_serialize(&client_key, &mut bytes, 1 << 30)?;
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}
