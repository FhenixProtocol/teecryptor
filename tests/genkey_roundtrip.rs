//! End-to-end check: the `genkey` dev binary produces bytes that `KeyStore::load`
//! accepts. Catches regressions where the on-disk format the operator copies
//! into Secret Manager drifts from what the boot path expects.
//!
//! Runs the actual compiled binary (`env!("CARGO_BIN_EXE_genkey")`) so the test
//! exercises the same code path that `make keys` runs.

use std::process::Command;

use teecryptor::keys::KeyStore;
use zeroize::Zeroizing;

#[test]
fn genkey_stdout_loads_into_keystore() {
    let bin = env!("CARGO_BIN_EXE_genkey");
    let out = Command::new(bin)
        .output()
        .expect("failed to invoke genkey binary");
    assert!(
        out.status.success(),
        "genkey exited non-zero: status={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.is_empty(),
        "genkey produced empty stdout — boot would have nothing to deserialize"
    );

    let store =
        KeyStore::load(Zeroizing::new(out.stdout)).expect("KeyStore::load on genkey stdout");
    assert!(
        store.client_key(0).is_some(),
        "zone-0 ClientKey must be populated"
    );
    assert!(
        store.client_key(1).is_none(),
        "non-zero zones must remain unsupported in Phase 1"
    );
}
