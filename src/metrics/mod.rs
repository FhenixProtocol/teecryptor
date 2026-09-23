//! Process-wide request metrics, exported in Prometheus text format.
//!
//! One registry, one meter provider, one instrument family per concern:
//!
//! * **transport** ([`Metrics::observe_http`]) — `http_server_requests_total`
//!   and `http_server_request_duration_seconds_{bucket,sum,count}`, labeled by
//!   route template, method and status code. The attribute set follows the
//!   OpenTelemetry HTTP-server semantic conventions, so it lines up with the
//!   load balancer's own view of the same traffic.
//! * **decrypt path** ([`Metrics::observe_decrypt`]) —
//!   `teecryptor_decrypt_requests_total` and
//!   `teecryptor_decrypt_duration_seconds_{bucket,sum,count}`, labeled by route
//!   template, host chain, ACP presence, ciphertext width and outcome. The
//!   domain view: what was asked for, on whose chain, under what permission,
//!   and why it ended that way. Kept a separate
//!   family rather than extra labels on the transport one, which serves routes
//!   (`/healthz`, the poll routes, unmatched paths) that have no chain and no
//!   width to report.
//! * **liveness** — `teecryptor_up`, an observable gauge that always
//!   reports 1. It exists so `platform/metrics-target-down` can alert on
//!   the absence of a series that no amount of quiet traffic explains.
//!
//! Both families share the `http_route` label, so a transport series joins its
//! domain series without a translation table.
//!
//! # Why the names are spelled out, not semconv
//!
//! `http.server.request.duration` is the OpenTelemetry semconv name; the
//! instrument here deliberately says `http_server_request_duration_seconds`
//! instead — the published Prometheus series name, unit suffix and `_total`
//! included. The rule: nothing between this module and PromQL renames
//! anything. The scrape exporter is configured suffix-less, and an OTLP push
//! publishes instrument names verbatim, so the string in the code IS the
//! series name in every query. Every alert in `monitoring/gcp/alerts` is
//! written against these exact strings — renaming "back" to semconv would
//! silently orphan them. Semconv recognition by OTel tooling is the price,
//! and it is paid deliberately.
//!
//! The registry is scraped over `GET /metrics` on a dedicated port — see
//! `metrics_router` in [`crate::http`] and `METRICS_ADDR` in the binary.
//! Counters are process-lifetime; a VM restart resets them (standard
//! Prometheus semantics — `rate()` absorbs it).
//!
//! **Cardinality is bounded by construction.** Every label value is either a
//! compile-time constant, a route template interned by the router, or a
//! bounded projection of a caller-supplied value (see `method_label` in the
//! private `http` submodule). No raw request path, handle or client token ever becomes a label.

mod decrypt;
mod health;
mod http;
mod otlp_http_client;
mod otlp_split;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use prometheus::{Registry, TextEncoder};

pub use decrypt::{DecryptLabels, Outcome};

/// Histogram bucket boundaries in seconds, shared by both families. The SDK's
/// defaults are millisecond-scaled and useless for a second-unit instrument;
/// the top buckets are wide because FHE decrypts legitimately run tens of
/// seconds under load (the CPU gate queues admissions).
const DURATION_BOUNDARIES: [f64; 13] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 40.0,
];

/// How often the push pipeline exports. The Telemetry API floor is 5s.
const EXPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Becomes the `job` label on every pushed series — the name every alert in
/// monitoring/gcp/alerts scopes by.
const SERVICE_NAME: &str = "teecryptor";

pub use health::{Health, COMMITMENT_REGISTRY, CT_SOURCE};

/// Where every real build pushes its metrics. Deliberately a constant, not
/// configuration (decision 2026-09-03): with the endpoint outside the operator
/// override surface, no credentialed request can be redirected by config — the
/// guard that policed a settable endpoint is gone with it. Moving it (a
/// regional endpoint, a collector) is a code change and a new attested image,
/// which is the point.
pub const GOOGLE_TELEMETRY_ENDPOINT: &str = "https://telemetry.googleapis.com/v1/metrics";

/// Where and as whom the OTLP push publishes. The zone, instance name and
/// project id come from the metadata server at build time.
pub struct OtlpSettings {
    /// Full URL, path included — nothing is auto-appended to it. Production
    /// always passes [`GOOGLE_TELEMETRY_ENDPOINT`]; a field rather than an
    /// inlined constant only so tests can point the pipeline at a mock.
    pub endpoint: String,
    /// Environment name, published as `service.namespace`.
    pub env: String,
    /// Metadata-server host override for tests. `None` falls back to the
    /// `GCE_METADATA_HOST` env var, then the GCE default host.
    pub metadata_host: Option<String>,
}

impl OtlpSettings {
    fn resource(&self, zone: String, instance_id: String, project_id: String) -> Resource {
        Resource::builder()
            .with_service_name(SERVICE_NAME)
            .with_attributes([
                KeyValue::new("cloud.availability_zone", zone),
                KeyValue::new("service.namespace", self.env.clone()),
                KeyValue::new("service.instance.id", instance_id),
                // Required by the Telemetry API; without it every export is a 400.
                KeyValue::new("gcp.project_id", project_id),
            ])
            .build()
    }
}

/// The instrument handles plus the prometheus registry they export into. One
/// instance per `AppState`, so the main router (which records) and the metrics
/// router (which renders) share one set of series.
#[derive(Debug)]
pub struct Metrics {
    /// Renders the text exposition; the prometheus exporter feeds it. Always
    /// present: in push mode it backs the IAP-only debug surface.
    registry: Registry,
    /// Keeps the reader/export pipeline alive: dropping the provider shuts the
    /// exporter down and freezes the registry's series.
    _provider: SdkMeterProvider,
    /// Keeps the heartbeat callback registered for the process lifetime.
    _heartbeat: opentelemetry::metrics::ObservableGauge<u64>,
    /// Kept so dependency health can be attached after construction: the probe
    /// targets are known later in boot than the instruments are.
    meter: Meter,
    /// Present once [`Metrics::with_health`] has run. `None` in tests and in
    /// any deployment with nothing to probe.
    _health: Option<health::Instruments>,
    http: http::Instruments,
    decrypt: decrypt::Instruments,
}

impl Metrics {
    /// Build the registry → prometheus exporter → meter-provider pipeline and
    /// register the instruments.
    ///
    /// `served_chain_ids` bounds the `host_chain_id` label to the chains this
    /// deployment is configured for — see `ChainLabels` in the private `decrypt`
    /// submodule.
    ///
    /// Scope/target info series are disabled: they add an `otel_scope_name`
    /// label to every sample plus `otel_scope_info`/`target_info` gauges, and
    /// carry no signal for a single-binary service — dropping them keeps the
    /// exposition to exactly the documented series.
    ///
    /// # Panics
    ///
    /// Panics if the exporter cannot register against the fresh registry —
    /// impossible short of a bug, and this runs once at boot where the service
    /// fails closed anyway.
    pub fn new(served_chain_ids: impl IntoIterator<Item = u64>) -> Self {
        Self::build(served_chain_ids, None).expect("infallible without a push exporter")
    }

    /// Like [`Metrics::new`], but pushing: the instruments also feed a periodic
    /// OTLP exporter to `settings.endpoint`. The scrape registry is still built.
    /// Runs on a plain thread — construction reads the metadata server with a
    /// blocking client, which async contexts refuse.
    pub fn with_otlp(
        served_chain_ids: impl IntoIterator<Item = u64> + Send + 'static,
        settings: OtlpSettings,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        std::thread::spawn(move || Self::build(served_chain_ids, Some(&settings)))
            .join()
            .map_err(|_| "metrics pipeline builder thread panicked")?
    }

    fn build(
        served_chain_ids: impl IntoIterator<Item = u64>,
        otlp: Option<&OtlpSettings>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // The text exposition is always built. In push mode it is not a
        // scrape target — the push is the collection path — but an operator
        // reading counters over an IAP tunnel is the only in-VM view when a
        // push looks wrong, and the exporter's own errors cannot show which
        // series were being sent. See the Dockerfile's EXPOSE note.
        let registry = Registry::new();
        // The instruments spell their full published names (`_total`, unit
        // suffix included) so the push path publishes them verbatim; this
        // exporter must therefore not append its own suffixes on top.
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .without_units()
            .without_counter_suffixes()
            .with_resource_selector(opentelemetry_prometheus::ResourceSelector::None)
            .build()
            .expect("register prometheus exporter on a fresh registry");
        let mut builder = SdkMeterProvider::builder().with_reader(exporter);
        if let Some(settings) = otlp {
            let metadata = otlp_http_client::MetadataClient::new(settings.metadata_host.clone())?;
            let zone = metadata.zone()?;
            let instance_id = metadata.instance_name()?;
            let project_id = metadata.project_id()?;
            let otlp_exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(settings.endpoint.clone())
                .with_http_client(otlp_http_client::GoogleAuthClient::new(metadata)?)
                .build()?;
            let reader = PeriodicReader::builder(otlp_exporter)
                .with_interval(EXPORT_INTERVAL)
                .build();
            builder = builder.with_reader(reader).with_resource(settings.resource(
                zone,
                instance_id,
                project_id,
            ));
        }
        let provider = builder.build();
        let meter = provider.meter(SERVICE_NAME);
        // Liveness heartbeat: always 1, re-reported on every export
        // regardless of traffic. `platform/metrics-target-down` alerts on its
        // absence — the one series whose disappearance means "not reporting"
        // rather than "idle". Held in the struct so the callback registration
        // outlives this scope.
        let heartbeat = meter
            .u64_observable_gauge("teecryptor_up")
            .with_description("1 while the process runs and the metrics pipeline reports")
            .with_callback(|observer| observer.observe(1, &[]))
            .build();
        let http = http::Instruments::new(&meter);
        let decrypt = decrypt::Instruments::new(&meter, served_chain_ids);
        Ok(Self {
            registry,
            _provider: provider,
            _heartbeat: heartbeat,
            meter,
            _health: None,
            http,
            decrypt,
        })
    }

    /// Record one served response on the transport instruments. `route` is the
    /// matched route template, `None` when no route matched — see
    /// `http::Instruments::observe` for why it is never a raw path.
    pub fn observe_http(
        &self,
        route: Option<&str>,
        method: &Method,
        status: StatusCode,
        elapsed: Duration,
    ) {
        self.http.observe(route, method, status, elapsed);
    }

    /// Record one decrypt-path response. Called for the routes that run the
    /// decrypt path (`DECRYPT_ROUTES` in [`crate::http`]) and only those: every
    /// other route has no chain, width or outcome to report.
    pub fn observe_decrypt(
        &self,
        route: &str,
        labels: &DecryptLabels,
        outcome: Option<Outcome>,
        status: StatusCode,
        elapsed: Duration,
    ) {
        self.decrypt
            .observe(route, labels, outcome, status, elapsed);
    }

    /// Register the dependency-health families against `health`.
    ///
    /// Separate from construction because the probe targets — which chains,
    /// whether the commitment gate is on — are resolved later in boot than the
    /// request instruments, and registering an observable gauge needs the
    /// meter this type already owns.
    #[must_use]
    pub fn with_health(mut self, health: std::sync::Arc<Health>) -> Self {
        self._health = Some(health::Instruments::new(&self.meter, health));
        self
    }

    /// Render the Prometheus text exposition (`text/plain; version=0.0.4`,
    /// [`prometheus::TEXT_FORMAT`]) for the `/metrics` handler.
    ///
    /// `None` only when the encoder fails, which is logged. The handler turns
    /// `None` into a 503.
    pub fn render(&self) -> Option<String> {
        match TextEncoder::new().encode_to_string(&self.registry.gather()) {
            Ok(text) => Some(text),
            Err(e) => {
                tracing::error!(error = %e, "metrics: text exposition failed to encode");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push mode keeps the text exposition — it is the IAP-only debug view,
    /// not a scrape target. Hermetic: the metadata host rides `OtlpSettings`,
    /// so no process-wide env var is touched, and the pipeline is dropped
    /// (shutting the reader down) before the mock server goes away.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_mode_still_renders_the_debug_exposition() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path(
            "/computeMetadata/v1/instance/zone",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_string("projects/1/zones/test-zone"),
        )
        .mount(&server)
        .await;
        wiremock::Mock::given(wiremock::matchers::path(
            "/computeMetadata/v1/instance/name",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("teecryptor-test-0"))
        .mount(&server)
        .await;
        wiremock::Mock::given(wiremock::matchers::path(
            "/computeMetadata/v1/project/project-id",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("test-project"))
        .mount(&server)
        .await;
        let metrics = Metrics::with_otlp(
            [],
            OtlpSettings {
                endpoint: format!("{}/v1/metrics", server.uri()),
                env: "test".into(),
                metadata_host: Some(server.uri().trim_start_matches("http://").to_string()),
            },
        )
        .expect("push pipeline builds against the mocked metadata server");

        let text = metrics
            .render()
            .expect("push mode still renders the debug exposition");
        assert!(
            text.contains("teecryptor_up 1"),
            "the heartbeat should be in the debug exposition:\n{text}"
        );
        drop(metrics);
    }

    /// The push pipeline's identity: `service.name` becomes the `job` label
    /// every alert scopes by, the zone the required `location`, and the
    /// project id the attribute the Telemetry API refuses to ingest without.
    #[test]
    fn otlp_settings_resource_carries_the_prometheus_target_identity() {
        let resource = OtlpSettings {
            endpoint: "https://example.invalid/v1/metrics".into(),
            env: "testnet".into(),
            metadata_host: None,
        }
        .resource(
            "europe-west4-b".into(),
            "teecryptor-abcd".into(),
            "fhenix-testnet".into(),
        );
        for (key, want) in [
            ("service.name", "teecryptor"),
            ("cloud.availability_zone", "europe-west4-b"),
            ("service.namespace", "testnet"),
            ("service.instance.id", "teecryptor-abcd"),
            ("gcp.project_id", "fhenix-testnet"),
        ] {
            assert_eq!(
                resource
                    .get(&opentelemetry::Key::from(key.to_string()))
                    .map(|v| v.to_string()),
                Some(want.to_string()),
                "{key}"
            );
        }
    }

    /// Pins the exporter's wire format: series names (unit + `_total`
    /// suffixing), sanitized semconv label keys, and the absence of the
    /// scope/target info noise. The scrape contract lives entirely in this
    /// exposition, so a bridge behavior change must fail here, not in
    /// production PromQL.
    #[test]
    fn observe_http_renders_documented_series() {
        let m = Metrics::new([]);
        m.observe_http(
            Some("/decrypt"),
            &Method::POST,
            StatusCode::OK,
            Duration::from_millis(42),
        );
        m.observe_http(
            None,
            &Method::GET,
            StatusCode::NOT_FOUND,
            Duration::from_millis(1),
        );

        let text = m.render().expect("encode text exposition");
        for needle in [
            "http_server_requests_total{",
            "teecryptor_up 1",
            "http_request_method=\"POST\"",
            "http_route=\"/decrypt\"",
            "http_response_status_code=\"200\"",
            "http_route=\"unmatched\"",
            "http_response_status_code=\"404\"",
            "http_server_request_duration_seconds_bucket{",
            "http_server_request_duration_seconds_count{",
            "le=\"40\"",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert!(
            !text.contains("otel_scope") && !text.contains("target_info"),
            "scope/target info should be disabled:\n{text}"
        );
    }

    /// Pins the decrypt family's wire format: series names, label keys, and the
    /// duration histogram appearing only for a request that ran a decrypt.
    #[test]
    fn observe_decrypt_renders_documented_series() {
        let m = Metrics::new([420105]);
        let served = DecryptLabels::default();
        served.set_host_chain_id(420105);
        served.set_acp_presented(true);
        served.set_encryption_type(crate::decrypt::EncryptionType::U32);
        m.observe_decrypt(
            "/v2/decrypt",
            &served,
            None,
            StatusCode::OK,
            Duration::from_millis(42),
        );

        let shed = DecryptLabels::default();
        shed.set_host_chain_id(420105);
        shed.set_acp_presented(false);
        m.observe_decrypt(
            "/v2/decrypt",
            &shed,
            Some(Outcome::new("ct_not_ready")),
            StatusCode::NO_CONTENT,
            Duration::from_millis(1),
        );

        let text = m.render().expect("encode text exposition");
        for needle in [
            "teecryptor_decrypt_requests_total{",
            "http_route=\"/v2/decrypt\"",
            "host_chain_id=\"420105\"",
            "acp=\"present\"",
            "acp=\"absent\"",
            "encryption_type=\"u32\"",
            "outcome=\"ok\"",
            "encryption_type=\"unknown\"",
            "outcome=\"ct_not_ready\"",
            "teecryptor_decrypt_duration_seconds_bucket{",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("teecryptor_decrypt_duration_seconds_count{"))
                .count(),
            1,
            "only the request that ran a decrypt belongs in the histogram:\n{text}"
        );
    }
}
