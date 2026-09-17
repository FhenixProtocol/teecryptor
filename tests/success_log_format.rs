//! Captures the actual JSON line `log_op_success` writes to stdout, so we can
//! see exactly what lands in GCP Logs Explorer. Uses the same
//! `tracing_subscriber::fmt().json()` subscriber `main.rs` installs, drives a
//! real `/decrypt` through the router, and prints the captured event.
//!
//! Run with: `cargo test --test success_log_format -- --nocapture`

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use teecryptor::ct_source::CtSource;
use teecryptor::http::{router, AppState};
use teecryptor::keys::KeyStore;
use tfhe::prelude::FheEncrypt;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{generate_keys, ClientKey, ConfigBuilder, FheUint32};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

const LIMIT: u64 = 1 << 30;

/// A `MakeWriter` that appends every byte the subscriber emits to a shared buffer.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn key_bytes() -> Vec<u8> {
    let (ck, sk): (ClientKey, _) = generate_keys(ConfigBuilder::default().build());
    tfhe::set_server_key(sk);
    let mut b = Vec::new();
    safe_serialize(&ck, &mut b, LIMIT).unwrap();
    b
}

#[tokio::test]
async fn print_success_log_example() {
    // Install the SAME JSON subscriber main.rs uses, but pointed at a buffer.
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_writer(BufWriter(buf.clone()))
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // ct-server stub returning an expanded FheUint32(42) under our key.
    let kb = key_bytes();
    let ck: ClientKey = tfhe::safe_serialization::safe_deserialize(&kb[..], LIMIT).unwrap();
    let mut ctbytes = Vec::new();
    safe_serialize(
        &FheUint32::encrypt(42u32, &ck).compress(),
        &mut ctbytes,
        LIMIT,
    )
    .unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/GetStoredCt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        })))
        .mount(&server)
        .await;

    let keys = KeyStore::load(Zeroizing::new(kb)).unwrap();
    let ct_source = CtSource::new(&server.uri(), Duration::from_secs(5)).unwrap();
    let state = AppState::new(keys, ct_source, None);
    state.set_ready();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let client = reqwest::Client::new();

    // (1) A successful decrypt → the success log. The handle's committed type
    // byte (index 30) must be 4 (U32) to satisfy the decrypt type cross-check,
    // matching the ciphertext body's `uint_type`.
    let handle = {
        let mut h = [0u8; 32];
        h[30] = 4;
        format!("0x{}", hex::encode(h))
    };
    let ok = client
        .post(format!("http://{addr}/decrypt"))
        .json(&serde_json::json!({ "ct_tempkey": handle, "host_chain_id": 420105u64 }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // (2) A rejected decrypt (non-hex handle) → the failure log.
    let bad = client
        .post(format!("http://{addr}/decrypt"))
        .json(&serde_json::json!({ "ct_tempkey": "nothex!", "host_chain_id": 420105u64 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    // Both terminal log lines are now in the buffer.
    let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let success = captured
        .lines()
        .find(|l| l.contains("completed"))
        .expect("success log line present");
    let failure = captured
        .lines()
        .find(|l| l.contains("invalid handle"))
        .expect("failure log line present");

    // Success line: informative message + structured fields.
    let sj: serde_json::Value = serde_json::from_str(success).unwrap();
    assert_eq!(sj["level"], "INFO");
    assert_eq!(
        sj["fields"]["message"],
        serde_json::json!(format!("decrypt completed: ct {handle} on chain 420105"))
    );
    assert_eq!(sj["fields"]["op"], "decrypt");
    assert_eq!(sj["fields"]["host_chain_id"], 420105);
    assert!(sj["fields"]["request_id"].as_str().is_some());
    assert!(sj["fields"]["duration_ms"].as_u64().is_some());

    // Failure line: logged inline at the failure point (INFO for a rejected 4xx),
    // with request_id + ct handle + a clear message.
    let fj: serde_json::Value = serde_json::from_str(failure).unwrap();
    assert_eq!(fj["level"], "INFO");
    assert_eq!(fj["fields"]["message"], "invalid handle (not hex)");
    assert_eq!(fj["fields"]["ct_tempkey"], "nothex!");
    assert!(fj["fields"]["request_id"].as_str().is_some());

    println!("\n================ SUCCESS log line ================");
    println!("{success}");
    println!("\n================ FAILURE log line (rejected request) ================");
    println!("{failure}");
}
