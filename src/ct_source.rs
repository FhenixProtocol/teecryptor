//! Client for cofhe ct-server's `POST /GetStoredCt` (cofhe PR #799).
//!
//! Fetches a ciphertext by handle and maps ct-server's wire response into
//! [`FheCiphertext`]. `gzipped` (modulus-switched compressed) is the stored
//! canonical form for EVERY ct class — engine results compress at creation,
//! and zk-verifier re-compresses verified inputs before storing (cofhe
//! `zk-verifier/src/verifier/traits.rs`) — served as-is, commitment-checked
//! as-is, and decrypted directly by [`crate::direct_decrypt`] without
//! decompression. Anything not gzipped (compact or plain) is rejected at the
//! decrypt gate, fail-closed — a legacy non-compressed row surfaces as a
//! warn + 502 rather than being served. (The plain decrypt code is retained,
//! dormant, until the legacy-path cleanup.)

use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

/// A ciphertext fetched from ct-server, ready for decryption.
#[derive(Debug, Clone)]
pub struct FheCiphertext {
    /// The ciphertext handle (stamped from the request — ct-server does not
    /// reliably echo it).
    pub handle: String,
    /// Plain `safe_serialize`d ciphertext bytes (hex-decoded from the wire).
    pub data: Vec<u8>,
    /// cofhe `EncryptionType` discriminant (`uint_type` on the wire).
    pub encryption_type: i32,
    /// Security zone the ciphertext belongs to.
    pub security_zone: i32,
    /// Whether the bytes are a compact ciphertext (expected `false` from ct-server).
    pub compact: bool,
    /// Whether the bytes are a tfhe-compressed ciphertext (expected `false` from ct-server).
    pub gzipped: bool,
}

/// Errors from fetching a ciphertext via `/GetCT`.
#[derive(Debug, Error)]
pub enum CtFetchError {
    /// ct-server returned 404 — no ciphertext for the handle.
    #[error("ciphertext not found")]
    NotFound,
    /// ct-server returned 428 — the ciphertext is a not-yet-ready placeholder.
    #[error("ciphertext not ready")]
    NotReady,
    /// The request exceeded the configured timeout.
    #[error("ct-source request timed out")]
    Timeout,
    /// A transport/connection error talking to ct-server.
    #[error("ct-source transport error: {0}")]
    Transport(String),
    /// ct-server returned an unexpected HTTP status.
    #[error("unexpected ct-source status: {0}")]
    UnexpectedStatus(u16),
    /// The response body could not be parsed (bad JSON or bad hex).
    #[error("malformed ct-source response: {0}")]
    BadResponse(String),
}

#[derive(serde::Serialize)]
struct GetCtRequest<'a> {
    hash: &'a str,
}

#[derive(Deserialize)]
struct GetCtResponse {
    data: String, // "0x"+hex
    uint_type: i32,
    security_zone: i32,
    compact: bool,
    gzipped: bool,
}

/// HTTP client for ct-server's `POST /GetStoredCt` (cofhe PR #799): the bytes
/// exactly as stored, no expansion — the commitment check must run over the
/// same bytes the engine committed to. Same request/response envelope and
/// error semantics as `/GetCT`.
///
/// Deploy-order requirement: ct-server must ship `/GetStoredCt` before this
/// path activates; an older ct-server returns route-miss 404, which maps to
/// `NotFound` — fail-closed, but the error is misleading, so don't roll
/// teecryptor first.
#[derive(Clone)]
pub struct CtSource {
    client: reqwest::Client,
    get_ct_url: String,
    /// ct-server's liveness endpoint. Probed by the health loop, which shares
    /// this client — and therefore its warm connection pool — with `fetch`.
    health_url: String,
}

impl CtSource {
    /// Build a client. `base_url` is ct-server's base (e.g.
    /// `http://ct-server:9450`); `/GetStoredCt` is appended. `timeout` bounds
    /// each request.
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, CtFetchError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| CtFetchError::Transport(e.to_string()))?;
        let base = base_url.trim_end_matches('/');
        let get_ct_url = format!("{base}/GetStoredCt");
        let health_url = format!("{base}/Health");
        Ok(Self {
            client,
            get_ct_url,
            health_url,
        })
    }

    /// Is ct-server answering? `true` only on a 2xx.
    ///
    /// Deliberately coarse: this feeds a gauge, so the one thing it must not do
    /// is turn a slow dependency into a slow probe loop. The client's timeout
    /// bounds it, and any error — transport, timeout, non-2xx — is simply
    /// "down".
    pub async fn probe(&self) -> bool {
        match self.client.get(&self.health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Fetch the ciphertext for `handle`.
    pub async fn fetch(&self, handle: &str) -> Result<FheCiphertext, CtFetchError> {
        let mut resp = self
            .client
            .post(&self.get_ct_url)
            .json(&GetCtRequest { hash: handle })
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    CtFetchError::Timeout
                } else {
                    CtFetchError::Transport(e.to_string())
                }
            })?;

        match resp.status().as_u16() {
            200 => {}
            404 => return Err(CtFetchError::NotFound),
            428 => return Err(CtFetchError::NotReady),
            other => return Err(CtFetchError::UnexpectedStatus(other)),
        }

        // Bound peak memory *before* it is committed. The largest legitimate ct
        // is ~150 KB; its hex-encoded JSON envelope is a few hundred KB. A
        // hostile ct-server could otherwise stream a multi-GB body — and
        // `resp.bytes()` would buffer the whole thing first, so a post-read size
        // check comes too late and a chunked body (no `Content-Length`) dodges
        // any header check entirely. Stream chunk-by-chunk and bail the instant
        // the running total exceeds the cap. The declared-length fast-path just
        // avoids starting an honestly-oversized download.
        const MAX_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB
        if let Some(len) = resp.content_length() {
            if len > MAX_BODY_BYTES as u64 {
                return Err(CtFetchError::BadResponse(format!(
                    "response body {len} bytes exceeds {MAX_BODY_BYTES} cap"
                )));
            }
        }
        let hint = resp
            .content_length()
            .map_or(0, |len| (len as usize).min(MAX_BODY_BYTES));
        let mut raw = Vec::with_capacity(hint);
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| CtFetchError::BadResponse(e.to_string()))?
        {
            if raw.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(CtFetchError::BadResponse(format!(
                    "response body exceeds {MAX_BODY_BYTES}-byte cap"
                )));
            }
            raw.extend_from_slice(&chunk);
        }
        let body: GetCtResponse =
            serde_json::from_slice(&raw).map_err(|e| CtFetchError::BadResponse(e.to_string()))?;

        let hex_str = body.data.strip_prefix("0x").unwrap_or(&body.data);
        let data = hex::decode(hex_str)
            .map_err(|e| CtFetchError::BadResponse(format!("hex data: {e}")))?;

        Ok(FheCiphertext {
            handle: handle.to_string(),
            data,
            encryption_type: body.uint_type,
            security_zone: body.security_zone,
            compact: body.compact,
            gzipped: body.gzipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The probe reports reachability, not correctness: a 2xx from /Health is
    /// up, and every other outcome — wrong status, refused connection, timeout
    /// — is down. It must never propagate an error, because it feeds a gauge.
    #[tokio::test]
    async fn probe_is_true_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/Health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        assert!(source(&server, Duration::from_secs(2)).probe().await);
    }

    #[tokio::test]
    async fn probe_is_false_on_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/Health"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(!source(&server, Duration::from_secs(2)).probe().await);
    }

    #[tokio::test]
    async fn probe_is_false_when_unreachable() {
        // A server that has been shut down: the port refuses the connection,
        // which is the shape of a dependency that is simply gone.
        let server = MockServer::start().await;
        let client = source(&server, Duration::from_secs(2));
        drop(server);
        assert!(!client.probe().await);
    }

    fn source(server: &MockServer, timeout: Duration) -> CtSource {
        CtSource::new(&server.uri(), timeout).expect("client")
    }

    #[tokio::test]
    async fn fetch_ok_parses_response_and_stamps_handle() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hash": "",            // ct-server may not echo it
                "data": "0x2a2b",
                "uint_type": 2,
                "security_zone": 0,
                "compact": false,
                "gzipped": false
            })))
            .mount(&server)
            .await;

        let ct = source(&server, Duration::from_secs(5))
            .fetch("0xdeadbeef")
            .await
            .expect("fetch");
        assert_eq!(ct.handle, "0xdeadbeef"); // stamped from request
        assert_eq!(ct.data, vec![0x2a, 0x2b]);
        assert_eq!(ct.encryption_type, 2);
        assert_eq!(ct.security_zone, 0);
        assert!(!ct.compact && !ct.gzipped);
    }

    #[tokio::test]
    async fn fetch_404_maps_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_secs(5))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::NotFound));
    }

    #[tokio::test]
    async fn fetch_428_maps_to_not_ready() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(428))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_secs(5))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::NotReady));
    }

    #[tokio::test]
    async fn slow_response_maps_to_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_millis(50))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::Timeout));
    }

    #[tokio::test]
    async fn fetch_500_maps_to_unexpected_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_secs(5))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::UnexpectedStatus(500)));
    }

    #[tokio::test]
    async fn oversized_body_rejected() {
        // A response body larger than the cap must be refused (here via the
        // declared-length fast-path; the streaming loop enforces the same bound
        // when no Content-Length is present) rather than buffered whole.
        let server = MockServer::start().await;
        let big = format!("0x{}", "ab".repeat(9 * 1024 * 1024)); // ~18 MiB > 8 MiB cap
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": big,
                "uint_type": 4,
                "security_zone": 0,
                "compact": false,
                "gzipped": true
            })))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_secs(5))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::BadResponse(_)), "{err}");
    }

    #[tokio::test]
    async fn bad_hex_maps_to_bad_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "0xZZ",
                "uint_type": 2,
                "security_zone": 0,
                "compact": false,
                "gzipped": false
            })))
            .mount(&server)
            .await;
        let err = source(&server, Duration::from_secs(5))
            .fetch("h")
            .await
            .unwrap_err();
        assert!(matches!(err, CtFetchError::BadResponse(_)));
    }
}
