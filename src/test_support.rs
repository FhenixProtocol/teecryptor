//! Shared `#[cfg(test)]` helpers, so the same fixture isn't hand-rolled in
//! multiple test modules.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a mock that accepts connections and reads requests but **never
/// responds** — for driving timeout paths deterministically.
pub(crate) async fn spawn_hanging_http_mock() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                // Keep reading (and discarding) so the client never sees EOF or
                // a response; its own timeout is the only way out.
                let mut buf = [0u8; 4096];
                while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    url
}

/// Spawn a minimal JSON-RPC mock that answers every request (e.g. `eth_call`)
/// with `result_hex` — a `0x`-prefixed ABI-encoded 32-byte word — over
/// keep-alive connections, echoing each request's `id`. Returns the base URL
/// and a counter of how many requests it served, so a test can prove a cache
/// short-circuited a second lookup.
///
/// Used by both the commitment gate (`getCommitment` → bytes32) and the permit
/// public-path (`isPubliclyAllowed` → bool); an all-zero word doubles as
/// `bytes32(0)` / `false`, a non-zero word as "present" / `true`.
pub(crate) async fn spawn_json_rpc_mock(
    result_hex: impl Into<String>,
) -> (String, Arc<AtomicUsize>) {
    spawn_json_rpc_mock_seq(vec![result_hex.into()]).await
}

/// [`spawn_json_rpc_mock`] with a *changing* answer: the n-th request served
/// gets `results[n]`, and every request past the end repeats the last entry.
/// Lets a test model a chain whose state changed under a long-lived client —
/// e.g. a registry wiped and redeployed with a different commitment.
pub(crate) async fn spawn_json_rpc_mock_seq(results: Vec<String>) -> (String, Arc<AtomicUsize>) {
    assert!(!results.is_empty(), "need at least one canned result");
    let results = Arc::new(results);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let reqs = Arc::new(AtomicUsize::new(0));
    let reqs_srv = reqs.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let reqs_conn = reqs_srv.clone();
            let results = results.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    // `fetch_add` yields the pre-increment count = this
                    // request's index into the canned sequence.
                    let idx = reqs_conn.fetch_add(1, Ordering::SeqCst);
                    let result_hex = &results[idx.min(results.len() - 1)];
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let id = text
                        .split("\"id\":")
                        .nth(1)
                        .and_then(|s| s.split([',', '}']).next())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("1")
                        .to_string();
                    let json =
                        format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":\"{result_hex}\"}}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                        json.len(),
                        json
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, reqs)
}
