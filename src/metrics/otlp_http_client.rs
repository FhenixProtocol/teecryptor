//! Blocking transport for the OTLP push.
//!
//! Blocking on purpose: the stable `PeriodicReader` drives exports with
//! `futures_executor::block_on` on its own plain thread, where an async
//! client has no reactor. Google tokens expire hourly, so each export asks
//! the VM metadata server, which caches and refreshes behind the endpoint.
//!
//! Deliberately standard TLS, like zee-k-verifier's data plane: the metrics
//! channel carries request counts and latencies — no secrets — so it does not
//! ride cofhe-keys' post-quantum-pinned client, which exists for key material.
//!
//! KEEP IN SYNC: `MetadataClient` and `GoogleAuthClient` are duplicated in
//! zee-k-verifier (`zk-verifier/src/otel_push.rs`). The two repos sit on
//! different opentelemetry majors (0.32 here, 0.31 there), whose http types
//! are incompatible, so a shared crate can't carry one impl yet — a fix in
//! either copy almost certainly belongs in the other.

use std::time::Duration;

use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};

/// Per-request budget for one metadata read or OTLP POST.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimal blocking metadata-server client: an access token for the VM's
/// service account, and the VM's zone. `GCE_METADATA_HOST` overrides the host
/// so local mocks keep working.
#[derive(Debug)]
pub(super) struct MetadataClient {
    base: String,
    client: reqwest::blocking::Client,
}

impl MetadataClient {
    pub(super) fn new(host_override: Option<String>) -> Result<Self, HttpError> {
        let host = host_override
            .or_else(|| std::env::var("GCE_METADATA_HOST").ok())
            .unwrap_or_else(|| "metadata.google.internal".to_string());
        Ok(Self {
            base: format!("http://{host}/computeMetadata/v1"),
            client: reqwest::blocking::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()?,
        })
    }

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response, HttpError> {
        Ok(self
            .client
            .get(format!("{}{path}", self.base))
            .header("Metadata-Flavor", "Google")
            .send()?
            .error_for_status()?)
    }

    fn access_token(&self) -> Result<String, HttpError> {
        #[derive(serde::Deserialize)]
        struct Token {
            access_token: String,
        }
        Ok(self
            .get("/instance/service-accounts/default/token")?
            .json::<Token>()?
            .access_token)
    }

    /// The zone, published as `cloud.availability_zone` — the Telemetry API
    /// rejects points without a location. The raw value is
    /// `projects/<num>/zones/<zone>`.
    pub(super) fn zone(&self) -> Result<String, HttpError> {
        let raw = self.get("/instance/zone")?.text()?;
        Ok(raw.rsplit('/').next().unwrap_or(&raw).to_string())
    }

    /// The VM name, published as `service.instance.id` — stable across
    /// container restarts on the same VM (unlike the container's `HOSTNAME`,
    /// which changes every restart).
    pub(super) fn instance_name(&self) -> Result<String, HttpError> {
        Ok(self.get("/instance/name")?.text()?)
    }

    /// The project ID, published as `gcp.project_id`. The Telemetry API
    /// refuses every export whose resource lacks it (`400 Resource is missing
    /// required attribute "gcp.project_id"`): the attribute, not the
    /// credential or an `x-goog-user-project` header, is what routes the
    /// series into a project.
    pub(super) fn project_id(&self) -> Result<String, HttpError> {
        Ok(self.get("/project/project-id")?.text()?)
    }
}

/// Bearer-per-request client for the OTLP exporter.
#[derive(Debug)]
pub(super) struct GoogleAuthClient {
    metadata: MetadataClient,
    inner: reqwest::blocking::Client,
}

impl GoogleAuthClient {
    pub(super) fn new(metadata: MetadataClient) -> Result<Self, HttpError> {
        Ok(Self {
            metadata,
            inner: reqwest::blocking::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()?,
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for GoogleAuthClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // Blocking on purpose — see the module docs.
        let (mut parts, body) = request.into_parts();
        // The destination is the hardcoded Google endpoint
        // (`metrics::GOOGLE_TELEMETRY_ENDPOINT`), never operator input, so the
        // token always rides. The host allow-list that used to live here
        // policed a settable endpoint; it went out with the setting.
        let token = self.metadata.access_token()?;
        parts.headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse()?,
        );
        // The Telemetry API rejects any request over 200 points, wholesale, and
        // the series count grows with label combinations until every export
        // dies (staging hit it ~2h after boot). Split and send sequentially;
        // the first rejected chunk is reported and the rest are skipped.
        let pieces =
            super::otlp_split::split_request(&body, super::otlp_split::MAX_POINTS_PER_REQUEST)?;
        let mut response = None;
        for piece in pieces {
            let resp =
                self.inner
                    .execute(reqwest::blocking::Request::try_from(Request::from_parts(
                        parts.clone(),
                        Bytes::from(piece),
                    ))?)?;
            let ok = resp.status().is_success();
            response = Some(resp);
            if !ok {
                break;
            }
        }
        let response = response.expect("split_request never returns zero pieces");
        let status = response.status();
        let mut builder = http::Response::builder().status(status);
        if let Some(headers) = builder.headers_mut() {
            *headers = response.headers().clone();
        }
        let bytes = response.bytes()?;
        if !status.is_success() {
            // Log the body ourselves, at error level. opentelemetry-otlp
            // deliberately logs it at DEBUG only and propagates just "HTTP
            // export failed with status code: N", so the actionable half —
            // WHICH attribute the API rejected — never reaches an error log.
            // Staging lost 90 minutes to a 400 whose body read `Resource is
            // missing required attribute "gcp.project_id"`.
            tracing::error!(
                status = status.as_u16(),
                body = %String::from_utf8_lossy(&bytes).chars().take(400).collect::<String>(),
                "metrics: the Telemetry API rejected an OTLP export"
            );
        }
        Ok(builder.body(bytes)?)
    }
}
