// Copied verbatim from FhenixProtocol/cofhe@ccd20d3bba65c975ec0abf73e4f4f363c2183e8e
// tools/tdx-signer-poc/src/attestation.rs (PR #706). BORROW-NOT-FORK: Phase 2
// extracts this to a public fhenix/tdx-common crate. Do not modify without
// intent to upstream there.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct AttestationClient {
    socket_path: PathBuf,
}

impl AttestationClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    pub async fn fetch_token(&self, audience: &str) -> Result<String> {
        let body = serde_json::json!({
            "audience": audience,
            "token_type": "OIDC",
        })
        .to_string();

        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connect to {:?}", self.socket_path))?;

        let request = format!(
            "POST /v1/token HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        stream
            .write_all(request.as_bytes())
            .await
            .context("write attestation request")?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .context("read attestation response")?;

        let response_str =
            std::str::from_utf8(&response).context("attestation response not UTF-8")?;

        let status_line = response_str
            .split("\r\n")
            .next()
            .context("empty response")?;
        if !status_line.contains(" 200 ") {
            anyhow::bail!("teeserver returned: {}", status_line.trim());
        }

        let body_start = response_str
            .find("\r\n\r\n")
            .context("malformed HTTP response (no body separator)")?
            + 4;
        let raw_body = response_str[body_start..].trim();
        Ok(raw_body.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Spawns a tiny HTTP server on a Unix socket that returns `body` for any POST.
    async fn spawn_unix_server(socket: PathBuf, body: &'static str, status: u16) {
        let listener = UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
    }

    #[tokio::test]
    async fn returns_token_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_unix_server(sock.clone(), "eyJhbGciOi.payload.sig", 200).await;
        // Give the listener a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AttestationClient::new(&sock);
        let token = client.fetch_token("//test-audience").await.unwrap();
        assert_eq!(token, "eyJhbGciOi.payload.sig");
    }

    #[tokio::test]
    async fn errors_on_non_200() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_unix_server(sock.clone(), "boom", 500).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AttestationClient::new(&sock);
        assert!(client.fetch_token("//aud").await.is_err());
    }
}
