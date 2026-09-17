//! Attested auth chain: PER-PARTNER attestation JWT → STS token exchange,
//! yielding one federated Secret-Manager bearer per partner (mirror of the
//! keygen write side). Each partner gates reads behind its OWN attested WIF
//! provider, so there is no shared SA and no impersonation hop — the federated
//! token is the SM bearer as-is. The Secret-Manager / GCS reads those tokens
//! authorize live in the `cofhe-keys` reader, not here.
//!
//! Pulled out of `main.rs` into the library so the orchestration glue (call
//! order, timeout firing, per-partner fault tolerance) is testable end-to-end
//! against `wiremock` + a tempfile `UnixListener`. The **production binary keeps
//! the GCP endpoint URLs as compile-time `const`s** at the call site, so a
//! `setMetadata`-capable operator cannot redirect the STS exchange — the lib
//! taking the endpoints as a parameter changes nothing about that property.

use std::time::Duration;

use anyhow::{Context, Result};
use cofhe_keys::gcp_auth::GcpAuth;
use cofhe_keys::reader::PartnerRef;
use tokio::time::timeout;

use crate::tdx_common::attestation::AttestationClient;

/// Endpoints for the attested auth chain. The prod binary passes compile-time
/// `const` strings; tests pass `wiremock` URIs and a tempfile Unix-socket path.
pub struct Endpoints<'a> {
    /// Path of the Confidential Space launcher Unix socket.
    pub attestation_socket: &'a str,
    /// Base URL of the STS token-exchange endpoint.
    pub sts_url: &'a str,
}

/// Per-call timeouts.
#[derive(Clone, Copy)]
pub struct Timeouts {
    /// Attestation socket round-trip (default: 5s).
    pub attestation: Duration,
    /// STS / metadata per-call (default: 10s).
    pub gcp: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            attestation: Duration::from_secs(5),
            gcp: Duration::from_secs(10),
        }
    }
}

/// One partner's federated Secret-Manager bearer, keyed by its project id.
pub struct PartnerToken {
    /// Partner GCP project id (matches `PartnerRef::project_id`).
    pub project_id: String,
    /// Federated access token authorizing THAT partner's Secret-Manager read.
    pub sm_token: String,
}

/// Per-partner attest(`wip_audience`) → STS → federated token, mirroring the
/// keygen write side. FAULT-TOLERANT: a partner whose attestation or exchange
/// fails or times out is EXCLUDED (warned, pushed to `failed`) rather than fatal
/// — reconstruction survives while >= T partners remain; the reader enforces the
/// threshold downstream.
///
/// Each outbound call is bounded by `timeouts` so a slow/hostile endpoint (or a
/// launcher socket that accepts and never replies) can't wedge boot — under
/// `tee-restart-policy=Never` a hang is a silently dead VM.
pub async fn load_partner_tokens(
    eps: &Endpoints<'_>,
    partners: &[PartnerRef],
    timeouts: &Timeouts,
) -> (Vec<PartnerToken>, Vec<String>) {
    let attest = AttestationClient::new(eps.attestation_socket);
    let auth = GcpAuth::new(eps.sts_url);
    let mut tokens = Vec::with_capacity(partners.len());
    let mut failed = Vec::new();
    for p in partners {
        match partner_token(&attest, &auth, p, timeouts).await {
            Ok(sm_token) => tokens.push(PartnerToken {
                project_id: p.project_id.clone(),
                sm_token,
            }),
            Err(e) => {
                tracing::warn!(
                    partner = %p.project_id,
                    error = %format!("{e:#}"),
                    "partner federation failed; excluding from reconstruction"
                );
                failed.push(p.project_id.clone());
            }
        }
    }
    (tokens, failed)
}

/// One partner's chain: attestation JWT for ITS audience → STS exchange → the
/// federated token. Isolation property: the JWT and token both carry the
/// partner's own `wip_audience`, so a token can never authorize another
/// partner's project.
async fn partner_token(
    attest: &AttestationClient,
    auth: &GcpAuth,
    partner: &PartnerRef,
    timeouts: &Timeouts,
) -> Result<String> {
    let jwt = timeout(
        timeouts.attestation,
        attest.fetch_token(&partner.wip_audience),
    )
    .await
    .context("attestation token fetch timed out")??;

    let federated = timeout(timeouts.gcp, auth.exchange(&partner.wip_audience, &jwt))
        .await
        .context("STS token exchange timed out")??;
    Ok(federated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofhe_keys::reader::PartnerRef;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn partner(project_id: &str, wip_audience: &str) -> PartnerRef {
        PartnerRef {
            project_id: project_id.into(),
            secret_id: "cofhe-tee-fhe-priv".into(),
            wip_audience: wip_audience.into(),
        }
    }

    /// Spawn a tiny HTTP/1.0 server on a Unix socket that returns `body` with the
    /// given status, serving SEQUENTIAL connections (one per partner attestation).
    /// Mirrors the helper in `tdx_common::attestation`.
    async fn spawn_attestation_server(sock: PathBuf, body: &'static str, status: u16) {
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
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

    /// Spawn a Unix listener that accepts but never writes — simulates a hung
    /// launcher socket. The connection stays open until we drop the listener.
    async fn spawn_attestation_blackhole(sock: PathBuf) {
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                std::mem::forget(stream);
            }
        });
    }

    /// Mount an STS mock that answers ONLY requests whose JSON body carries the
    /// given `audience`, returning `token`. Keying off the audience is what proves
    /// each partner's exchange rides ITS OWN attestation audience.
    async fn mount_sts_for_audience(server: &MockServer, audience: &str, token: &str) {
        Mock::given(method("POST"))
            .and(path("/v1/token"))
            .and(body_partial_json(
                serde_json::json!({ "audience": audience }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn per_partner_tokens_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_attestation_server(sock.clone(), "test-jwt", 200).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let gcp = MockServer::start().await;
        mount_sts_for_audience(&gcp, "//aud-1", "fed-1").await;
        mount_sts_for_audience(&gcp, "//aud-2", "fed-2").await;

        let sts_url = format!("{}/v1/token", gcp.uri());
        let eps = Endpoints {
            attestation_socket: sock.to_str().unwrap(),
            sts_url: &sts_url,
        };
        let partners = [partner("p-1", "//aud-1"), partner("p-2", "//aud-2")];
        let (tokens, failed) = load_partner_tokens(&eps, &partners, &Timeouts::default()).await;

        assert!(failed.is_empty(), "no partner should fail: {failed:?}");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].project_id, "p-1");
        assert_eq!(tokens[0].sm_token, "fed-1");
        assert_eq!(tokens[1].project_id, "p-2");
        assert_eq!(tokens[1].sm_token, "fed-2");
    }

    #[tokio::test]
    async fn one_partner_sts_failure_is_excluded_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_attestation_server(sock.clone(), "test-jwt", 200).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let gcp = MockServer::start().await;
        mount_sts_for_audience(&gcp, "//aud-1", "fed-1").await;
        // STS denies partner 2's audience.
        Mock::given(method("POST"))
            .and(path("/v1/token"))
            .and(body_partial_json(
                serde_json::json!({ "audience": "//aud-2" }),
            ))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&gcp)
            .await;

        let sts_url = format!("{}/v1/token", gcp.uri());
        let eps = Endpoints {
            attestation_socket: sock.to_str().unwrap(),
            sts_url: &sts_url,
        };
        let partners = [partner("p-1", "//aud-1"), partner("p-2", "//aud-2")];
        let (tokens, failed) = load_partner_tokens(&eps, &partners, &Timeouts::default()).await;

        assert_eq!(tokens.len(), 1, "the healthy partner survives");
        assert_eq!(tokens[0].project_id, "p-1");
        assert_eq!(tokens[0].sm_token, "fed-1");
        assert_eq!(failed, vec!["p-2".to_string()]);
    }

    #[tokio::test]
    async fn attestation_hang_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_attestation_blackhole(sock.clone()).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Unreachable STS — a hung launcher fails every partner at attestation.
        let sts_url = "http://127.0.0.1:1/v1/token".to_string();
        let eps = Endpoints {
            attestation_socket: sock.to_str().unwrap(),
            sts_url: &sts_url,
        };
        let timeouts = Timeouts {
            attestation: Duration::from_millis(100),
            gcp: Duration::from_secs(10),
        };
        let partners = [partner("p-1", "//aud-1"), partner("p-2", "//aud-2")];
        let (tokens, failed) = load_partner_tokens(&eps, &partners, &timeouts).await;
        assert!(tokens.is_empty(), "a hung launcher yields no tokens");
        assert_eq!(failed, vec!["p-1".to_string(), "p-2".to_string()]);
    }

    #[tokio::test]
    async fn sts_hang_is_excluded_not_wedged() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("teeserver.sock");
        spawn_attestation_server(sock.clone(), "test-jwt", 200).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let gcp = MockServer::start().await;
        // STS responds slowly — past our test timeout.
        Mock::given(method("POST"))
            .and(path("/v1/token"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&gcp)
            .await;
        let sts_url = format!("{}/v1/token", gcp.uri());
        let eps = Endpoints {
            attestation_socket: sock.to_str().unwrap(),
            sts_url: &sts_url,
        };
        let timeouts = Timeouts {
            attestation: Duration::from_secs(5),
            gcp: Duration::from_millis(100),
        };
        let partners = [partner("p-1", "//aud-1")];
        let (tokens, failed) = load_partner_tokens(&eps, &partners, &timeouts).await;
        assert!(tokens.is_empty());
        assert_eq!(failed, vec!["p-1".to_string()]);
    }
}
