// Copied verbatim from FhenixProtocol/cofhe@ccd20d3bba65c975ec0abf73e4f4f363c2183e8e
// tools/tdx-signer-poc/src/secrets.rs (PR #706). BORROW-NOT-FORK: Phase 2
// extracts this to a public fhenix/tdx-common crate. Do not modify without
// intent to upstream there.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::Deserialize;
use zeroize::Zeroizing;

pub struct SecretManager {
    base_url: String,
    http: Client,
}

#[derive(Deserialize)]
struct AccessResponse {
    payload: Payload,
}

#[derive(Deserialize)]
struct Payload {
    data: String,
}

impl SecretManager {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: Client::new(),
        }
    }

    pub async fn access(
        &self,
        access_token: &str,
        project_id: &str,
        secret_name: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions/latest:access",
            self.base_url, project_id, secret_name
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("secret manager request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("secret manager {} — {}", status, text);
        }
        let parsed: AccessResponse = resp.json().await.context("parse secret response")?;
        let decoded = STANDARD
            .decode(parsed.payload.data)
            .context("base64 decode")?;
        Ok(Zeroizing::new(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn decodes_base64_payload() {
        let server = MockServer::start().await;
        let raw = b"\x11\x22\x33\x44";
        let encoded = STANDARD.encode(raw);
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/fhenix-tdx-poc/secrets/k1/versions/latest:access",
            ))
            .and(header("authorization", "Bearer sa-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/.../secrets/k1/versions/1",
                "payload": { "data": encoded }
            })))
            .mount(&server)
            .await;

        let sm = SecretManager::new(server.uri());
        let bytes = sm.access("sa-xyz", "fhenix-tdx-poc", "k1").await.unwrap();
        assert_eq!(bytes.as_slice(), raw);
    }

    #[tokio::test]
    async fn errors_on_403() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;
        let sm = SecretManager::new(server.uri());
        assert!(sm.access("t", "p", "n").await.is_err());
    }
}
