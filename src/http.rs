//! axum HTTP layer: `POST /decrypt`, `GET /healthz`, and v2 async API.
//!
//! An internal request id (uuid v4) is generated per request and logged.
//! For the v2 routes the request id is also returned to the caller — backed
//! by an in-memory LRU (1 000 entries) for the poll route.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use alloy::primitives::U256;

use crate::commitment::{
    fetch_commitment, refresh_commitment, CommitmentConfig, CommitmentError, FetchedCommitment,
};
use crate::ct_source::{CtFetchError, CtSource};
#[cfg(feature = "legacy-plain-decrypt")]
use crate::decrypt::decrypt;
use crate::decrypt::EncryptionType;
use crate::error::ErrorResponse;
use crate::keys::KeyStore;
use crate::metrics::{DecryptLabels, Metrics, Outcome};
use crate::permit::{
    verify_publicly_allowed, verify_via_taskmanager, AcpData, AcpError, ChainsVerifierConfig,
};
use crate::seal::{seal_to_user, SealError};
use crate::signing::signer::SignatureVFormat;
use tokio::sync::Semaphore;

/// Cached result for the v2 decrypt poll route, keyed by request_id (UUID).
#[derive(Clone)]
struct V2CachedResult {
    decrypted: Vec<u8>,
    signature: String,
    encryption_type: i32,
    submitted_at: String, // ISO 8601
    completed_at: String, // ISO 8601
}

/// Cached result for the v2 sealoutput poll route, keyed by request_id (UUID).
#[derive(Clone)]
struct V2SealCachedResult {
    sealed_data: Vec<u8>,
    ephemeral_public_key: Vec<u8>,
    nonce: Vec<u8>,
    signature: String,
    encryption_type: i32,
    submitted_at: String, // ISO 8601
    completed_at: String, // ISO 8601
}

/// Shared application state (cheap to clone — an `Arc` inside).
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    keys: KeyStore,
    ct_source: CtSource,
    ready: AtomicBool,
    /// `Some` when ACP verification is enabled. Boot sets this from env;
    /// `with_acp_verifier` is the only way to flip it on (consumes self).
    acp_verifier: Option<ChainsVerifierConfig>,
    /// `Some` when on-chain commitment enforcement is enabled. Boot sets this
    /// from env; `with_commitment_verifier` is the only way to flip it on.
    commitment_verifier: Option<CommitmentConfig>,
    /// `Some` when a signer was built at boot — in the real path always, from the
    /// reconstructed FHE-priv secret's `decrypt_signer_priv`; `None` only in tests
    /// that construct an unsigned `AppState` (mock mints a throwaway signer).
    signer: Option<crate::signing::service::SigningService>,
    /// v2 decrypt poll cache — recent results keyed by request_id, evicted LRU after 1000.
    v2_cache: std::sync::Mutex<LruCache<String, V2CachedResult>>,
    /// v2 sealoutput poll cache — recent results keyed by request_id, evicted LRU after 1000.
    v2_seal_cache: std::sync::Mutex<LruCache<String, V2SealCachedResult>>,
    /// Wait-only CPU gate — bounds concurrent tfhe decrypts to ≈ core count.
    decrypt_sem: Arc<Semaphore>,
    /// Admission cap — bounds total in-flight requests; overflow sheds with 204
    /// (retryable). Held across the whole request, so it caps total in-flight
    /// (incl. the GetCT / ACP-RPC I/O), not just the CPU stage.
    admit_sem: Arc<Semaphore>,
    /// Per-response metrics — recorded by the [`track_metrics`] router layer,
    /// rendered by [`metrics_router`]'s `/metrics` handler.
    metrics: Metrics,
}

impl AppState {
    /// Build state with ACP verification **disabled**. Starts **not ready**;
    /// call [`AppState::set_ready`] once the boot sequence has fully completed.
    pub fn new(
        keys: KeyStore,
        ct_source: CtSource,
        signer: Option<crate::signing::service::SigningService>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                keys,
                ct_source,
                ready: AtomicBool::new(false),
                acp_verifier: None,
                commitment_verifier: None,
                signer,
                v2_cache: std::sync::Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())),
                v2_seal_cache: std::sync::Mutex::new(LruCache::new(
                    NonZeroUsize::new(1000).unwrap(),
                )),
                decrypt_sem: Arc::new(Semaphore::new(
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1),
                )),
                admit_sem: Arc::new(Semaphore::new(1000)),
                metrics: Metrics::new([]),
            }),
        }
    }

    /// Rebuild `Inner` with a mutation applied. `Inner` isn't `Clone` (it holds
    /// semaphores + caches), so each boot-time builder unwraps the sole `Arc`
    /// and reconstructs it. `try_unwrap` only succeeds before the state is
    /// cloned into the router — which is exactly what pins these builders to
    /// boot time. `#[track_caller]` makes the panic point at the offending
    /// `with_*` caller.
    #[track_caller]
    fn rebuild(self, f: impl FnOnce(Inner) -> Inner) -> Self {
        let prev = Arc::try_unwrap(self.inner)
            .unwrap_or_else(|_| panic!("AppState builder called after clone — boot-time only"));
        Self {
            inner: Arc::new(f(prev)),
        }
    }

    /// Enable ACP verification. Boot-time only (see the private `rebuild`).
    pub fn with_acp_verifier(self, cfg: ChainsVerifierConfig) -> Self {
        self.rebuild(|prev| Inner {
            acp_verifier: Some(cfg),
            ..prev
        })
    }

    /// Install the real metrics pipeline. Boot-time only, and built exactly
    /// once, last: the served-chain set bounds the `host_chain_id` label, and
    /// a discarded push pipeline blocks on drop to flush over the network.
    pub fn with_metrics(self, metrics: Metrics) -> Self {
        self.rebuild(|prev| Inner { metrics, ..prev })
    }

    /// Enable on-chain commitment enforcement. Boot-time only.
    pub fn with_commitment_verifier(self, cfg: CommitmentConfig) -> Self {
        self.rebuild(|prev| Inner {
            commitment_verifier: Some(cfg),
            ..prev
        })
    }

    /// Override the CPU-gate (`decrypt`, ≈ core count) and admission-cap
    /// (`admit`, max in-flight before the 204 backstop) sizes. Boot-time only;
    /// both values are clamped to ≥ 1.
    pub fn with_concurrency(self, decrypt: usize, admit: usize) -> Self {
        self.rebuild(|prev| Inner {
            decrypt_sem: Arc::new(Semaphore::new(decrypt.max(1))),
            admit_sem: Arc::new(Semaphore::new(admit.max(1))),
            ..prev
        })
    }

    /// Flip the healthcheck to ready.
    pub fn set_ready(&self) {
        self.inner.ready.store(true, Ordering::SeqCst);
    }

    fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::SeqCst)
    }

    fn acp_verifier(&self) -> Option<&ChainsVerifierConfig> {
        self.inner.acp_verifier.as_ref()
    }

    fn commitment_verifier(&self) -> Option<&CommitmentConfig> {
        self.inner.commitment_verifier.as_ref()
    }

    fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }
}

// ---------- v2 handlers -------------------------------------------------------

async fn handle_decrypt_v2_submit(
    State(state): State<AppState>,
    Extension(labels): Extension<Arc<DecryptLabels>>,
    headers: HeaderMap,
    Json(req): Json<DecryptRequest>,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let v_format = parse_v_format(&headers);
    let now = chrono::Utc::now().to_rfc3339();
    let started = Instant::now();
    labels.set_host_chain_id(req.host_chain_id);
    labels.set_acp_presented(req.acp.is_some());

    let (pt, ty) = match fetch_decrypt(
        &state,
        &req.ct_tempkey,
        req.host_chain_id,
        req.acp.as_ref(),
        &Uuid::parse_str(&request_id).unwrap(),
        ApiVersion::V2,
        &labels,
    )
    .await
    {
        Ok(out) => out,
        Err(resp) => return resp,
    };

    let decrypted = pt.to_big_endian().to_vec();

    let signature = match resolve_signature(
        state.inner.signer.as_ref().map(|svc| {
            svc.sign_decrypt(&pt, ty as i32, req.host_chain_id, &req.ct_tempkey, v_format)
        }),
        &request_id,
    ) {
        Ok(sig) => sig,
        Err(resp) => return resp,
    };

    if let Ok(mut cache) = state.inner.v2_cache.lock() {
        cache.put(
            request_id.clone(),
            V2CachedResult {
                decrypted: decrypted.clone(),
                signature: signature.clone(),
                encryption_type: ty as i32,
                submitted_at: now.clone(),
                completed_at: now,
            },
        );
    }

    log_op_success(
        "decrypt",
        &request_id,
        &req.ct_tempkey,
        ty as i32,
        req.host_chain_id,
        started,
    );

    (
        StatusCode::OK,
        Json(V2DecryptSubmitResponse {
            request_id,
            decrypted: Some(decrypted),
            signature: Some(signature),
            encryption_type: Some(ty as i32),
        }),
    )
        .into_response()
}

async fn handle_decrypt_v2_status(
    State(state): State<AppState>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Response {
    let result = state
        .inner
        .v2_cache
        .lock()
        .ok()
        .and_then(|mut c| c.get(&request_id).cloned());

    match result {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(r) => (
            StatusCode::OK,
            Json(V2DecryptStatusResponse {
                request_id,
                status: RequestStatusHttp::Completed,
                submitted_at: r.submitted_at,
                completed_at: Some(r.completed_at),
                is_succeed: Some(true),
                decrypted: Some(r.decrypted),
                signature: Some(r.signature),
                encryption_type: Some(r.encryption_type),
                error_message: None,
            }),
        )
            .into_response(),
    }
}

async fn handle_sealoutput_v2_submit(
    State(state): State<AppState>,
    Extension(labels): Extension<Arc<DecryptLabels>>,
    headers: HeaderMap,
    Json(req): Json<SealOutputRequest>,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let v_format = parse_v_format(&headers);
    let now = chrono::Utc::now().to_rfc3339();
    let started = Instant::now();
    labels.set_host_chain_id(req.host_chain_id);
    labels.set_acp_presented(req.acp.is_some());

    // sealoutput requires an ACP (the sealingKey must come from somewhere).
    let Some(ref acp) = req.acp else {
        tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealoutput requires an ACP");
        return err(
            StatusCode::BAD_REQUEST,
            "acp_required",
            Some("sealoutput requires an ACP with a sealingKey".into()),
        );
    };

    let (pt_u256, ty) = match fetch_decrypt(
        &state,
        &req.ct_tempkey,
        req.host_chain_id,
        Some(acp),
        &Uuid::parse_str(&request_id).unwrap(),
        ApiVersion::V2,
        &labels,
    )
    .await
    {
        Ok(out) => out,
        Err(resp) => return resp,
    };

    let sealing_hex = acp.sealing_key.trim_start_matches("0x");
    let recipient_pk = match hex::decode(sealing_hex) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey not hex: {e}");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some(format!("sealingKey hex: {e}")),
            );
        }
    };

    let plaintext = zeroize::Zeroizing::new(ty.encode(pt_u256));

    let sealed_result = match seal_to_user(&recipient_pk, &plaintext) {
        Ok(s) => s,
        Err(SealError::BadKeyLength(n)) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey wrong length: {n} bytes");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some(format!("sealingKey must be 32 bytes, got {n}")),
            );
        }
        Err(SealError::DegenerateKey) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey is degenerate");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some("sealingKey is the all-zero / degenerate Curve25519 point".into()),
            );
        }
        Err(SealError::EncryptFailed(e)) => {
            tracing::error!(%request_id, ct_tempkey = %req.ct_tempkey, "seal (crypto_box) failed: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "seal_failed", None);
        }
    };

    let signature = match resolve_signature(
        state.inner.signer.as_ref().map(|svc| {
            svc.sign_sealoutput(
                &sealed_result.data,
                &sealed_result.public_key,
                &sealed_result.nonce,
                ty as i32,
                req.host_chain_id,
                &req.ct_tempkey,
                v_format,
            )
        }),
        &request_id,
    ) {
        Ok(sig) => sig,
        Err(resp) => return resp,
    };

    if let Ok(mut cache) = state.inner.v2_seal_cache.lock() {
        cache.put(
            request_id.clone(),
            V2SealCachedResult {
                sealed_data: sealed_result.data.clone(),
                ephemeral_public_key: sealed_result.public_key.clone(),
                nonce: sealed_result.nonce.clone(),
                signature: signature.clone(),
                encryption_type: ty as i32,
                submitted_at: now.clone(),
                completed_at: now,
            },
        );
    }

    log_op_success(
        "sealoutput",
        &request_id,
        &req.ct_tempkey,
        ty as i32,
        req.host_chain_id,
        started,
    );

    (
        StatusCode::OK,
        Json(V2SealOutputSubmitResponse {
            request_id,
            sealed_data: Some(sealed_result.data),
            ephemeral_public_key: Some(sealed_result.public_key),
            nonce: Some(sealed_result.nonce),
            signature: Some(signature),
            encryption_type: Some(ty as i32),
        }),
    )
        .into_response()
}

async fn handle_sealoutput_v2_status(
    State(state): State<AppState>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Response {
    let result = state
        .inner
        .v2_seal_cache
        .lock()
        .ok()
        .and_then(|mut c| c.get(&request_id).cloned());

    match result {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(r) => (
            StatusCode::OK,
            Json(V2SealOutputStatusResponse {
                request_id,
                status: RequestStatusHttp::Completed,
                submitted_at: r.submitted_at,
                completed_at: Some(r.completed_at),
                is_succeed: Some(true),
                sealed: Some(UserSealedResponse {
                    data: r.sealed_data,
                    public_key: r.ephemeral_public_key,
                    nonce: r.nonce,
                }),
                signature: Some(r.signature),
                encryption_type: Some(r.encryption_type),
                error_message: None,
            }),
        )
            .into_response(),
    }
}

async fn handle_signer_address(State(state): State<AppState>) -> impl IntoResponse {
    let address = state
        .inner
        .signer
        .as_ref()
        .map(|s| s.evm_address().to_string())
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());
    Json(SignerAddressResponse { address })
}

/// Build the axum router. The CORS layer wraps every route so the browser
/// preflight (`OPTIONS`) is answered for all endpoints, not just the v2 ones.
/// The metrics layer sits outermost (added last) so it observes every
/// response — including preflights answered inside the CORS layer and the
/// 404/405/422 responses axum generates without reaching any handler.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/decrypt", post(handle_decrypt))
        .route("/sealoutput", post(handle_sealoutput))
        .route("/v2/decrypt", post(handle_decrypt_v2_submit))
        .route("/v2/decrypt/{request_id}", get(handle_decrypt_v2_status))
        .route("/v2/sealoutput", post(handle_sealoutput_v2_submit))
        .route(
            "/v2/sealoutput/{request_id}",
            get(handle_sealoutput_v2_status),
        )
        .route("/signerAddress", get(handle_signer_address))
        .layer(cors_layer())
        .layer(middleware::from_fn_with_state(state.clone(), track_metrics))
        .with_state(state)
}

/// Build the single-route router for the dedicated metrics port
/// (`METRICS_ADDR`). Deliberately NOT a route on the main router: the load
/// balancer fronts only the main port with no path matchers, so a `/metrics`
/// route there would be publicly routable — on its own port the scrape
/// surface is reachable only through the VM firewall (compute/main.tf).
pub fn metrics_router(state: &AppState) -> Router {
    Router::new()
        .route("/metrics", get(handle_metrics))
        .with_state(state.clone())
}

/// `GET /metrics` — the Prometheus text exposition of [`Metrics`].
async fn handle_metrics(State(state): State<AppState>) -> Response {
    match state.metrics().render() {
        Some(text) => (
            [(
                CONTENT_TYPE,
                HeaderValue::from_static(prometheus::TEXT_FORMAT),
            )],
            text,
        )
            .into_response(),
        // Push mode has no registry (and an encoder failure logs, then lands
        // here too): there is no exposition to serve, honestly a 503.
        None => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_scrape_surface",
            Some("metrics are pushed over OTLP; no text exposition exists".to_string()),
        ),
    }
}

/// Per-response metrics hook — the outermost layer of [`router`], so it sees
/// every response the service emits exactly once, by construction: matched
/// handlers, axum's own rejections (404 unmatched, 405, 422 malformed body),
/// CORS preflights, and the bodyless retryable 204s. Recording inside the
/// handlers instead would structurally miss the axum-generated ones — which is
/// why the response funnels only *label* a response ([`Outcome`]) and leave the
/// recording here.
async fn track_metrics(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    // The matched route TEMPLATE (`/v2/decrypt/{request_id}`), never the raw
    // path — request ids and scanner junk would mint unbounded label
    // cardinality. Absent only when no route matched (the 404 fallback).
    // Cloned (an `Arc<str>` bump) because `next.run` consumes the request.
    let matched = req.extensions().get::<MatchedPath>().cloned();
    let method = req.method().clone();
    // The sink the decrypt handlers write their labels into. Inserted for every
    // request so the extractor can never fail, read back below once the
    // response is in hand.
    let labels = Arc::new(DecryptLabels::default());
    req.extensions_mut().insert(Arc::clone(&labels));

    let resp = next.run(req).await;

    let route = matched.as_ref().map(MatchedPath::as_str);
    let elapsed = started.elapsed();
    let metrics = state.metrics();
    metrics.observe_http(route, &method, resp.status(), elapsed);
    if let Some(route) = route.filter(|r| DECRYPT_ROUTES.contains(r)) {
        // `Outcome` is absent exactly when no API funnel produced the response:
        // a success, or a request axum rejected before the handler ran.
        metrics.observe_decrypt(
            route,
            &labels,
            resp.extensions().get::<Outcome>().copied(),
            resp.status(),
            elapsed,
        );
    }
    resp
}

/// The routes that run the decrypt path, and so carry the decrypt-family
/// labels. A route belongs here when its handler calls [`fetch_decrypt`] — the
/// v2 poll routes only read the result cache. Pinned by
/// `metrics_cover_every_decrypt_route`.
const DECRYPT_ROUTES: [&str; 4] = ["/decrypt", "/sealoutput", "/v2/decrypt", "/v2/sealoutput"];

/// CORS layer matching cofhe's dispatcher
/// (`threshold-network/crates/dispatcher/src/transport/http`): any origin, the
/// GET/POST methods these routes use, and the two headers CofheSDK sends —
/// `content-type` (JSON body) and `x-signature-v-format` (the EVM-vs-raw
/// signature selector the SDK sets, e.g. `"evm"`). CofheSDK calls Teecryptor
/// cross-origin from a browser, so the preflight must pass.
///
/// Any origin is safe: no credentials are involved (auth is the ACP in the
/// request body, not a cookie), and CORS is not a server-side trust boundary
/// here (non-browser clients ignore it entirely and ACP verification runs
/// regardless of origin). The header name is inlined rather than shared with
/// `parse_v_format` to keep this change self-contained.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            CONTENT_TYPE,
            HeaderName::from_static("x-signature-v-format"),
        ])
        // Expose the retry-reason header so a browser CofheSDK can read *why* a
        // 204 is retryable (ct not ready vs. commitment pending vs. overloaded).
        .expose_headers([HeaderName::from_static(RETRY_REASON_HEADER)])
}

// ---------- /decrypt ---------------------------------------------------------

#[derive(Deserialize)]
struct DecryptRequest {
    ct_tempkey: String,
    /// Caller's host chain id (per cofhe convention). Required — axum returns
    /// 422 if missing from JSON.
    host_chain_id: u64,
    /// Optional ACP (see [`AcpData`]). When ACL enforcement is enabled
    /// and this is absent, `/decrypt` takes the public-allowance path
    /// (`isPubliclyAllowed`) and returns 403 if the handle isn't publicly
    /// decryptable.
    #[serde(default)]
    acp: Option<AcpData>,
}

#[derive(Serialize)]
struct DecryptResponse {
    /// 32-byte big-endian representation of the U256 plaintext (JSON array of
    /// integers — matches dispatcher wire format).
    decrypted: Vec<u8>,
    /// 130-char hex signature, or `""` when signing is disabled.
    signature: String,
    encryption_type: i32,
    /// Never `skip_serializing_if`: old v1 clients assert `error_message` is a
    /// string or `null`, and an omitted key reads as `undefined` — which fails
    /// that check on the *success* path.
    error_message: Option<String>,
}

// ---------- /sealoutput ------------------------------------------------------

/// JSON body for `/sealoutput`. Wire-identical to cofhe's dispatcher shape.
#[derive(Deserialize)]
struct SealOutputRequest {
    /// Ciphertext handle — dispatcher field name.
    ct_tempkey: String,
    /// Required — axum returns 422 if missing.
    host_chain_id: u64,
    /// Required for sealoutput — the ACP's `sealingKey` is the recipient
    /// pubkey we seal to. Even when REQUIRE_PERMIT=false (no cryptographic
    /// verification), we still need a `sealingKey` to know where to seal.
    #[serde(default)]
    acp: Option<AcpData>,
}

/// Inner sealed-bytes shape inside the response. Matches cofhe's
/// `UserSealedHttpResponse` byte-for-byte.
#[derive(Serialize)]
struct UserSealedResponse {
    data: Vec<u8>,
    public_key: Vec<u8>,
    nonce: Vec<u8>,
}

/// Top-level response shape for `/sealoutput`. Matches cofhe's
/// `SealOutputHttpResponse`.
#[derive(Serialize)]
struct SealOutputResponse {
    sealed: Option<UserSealedResponse>,
    signature: String,
    encryption_type: i32,
    /// Never `skip_serializing_if` — see [`DecryptResponse::error_message`].
    error_message: Option<String>,
}

// ---------- v2 response types ------------------------------------------------

/// Status of a v2 request.
// `Processing` is part of the dispatcher wire protocol; we always respond
// `Completed` because Teecryptor decrypts synchronously, but the variant must
// exist so the serialised string set matches the spec.
#[allow(dead_code)]
#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RequestStatusHttp {
    Processing,
    Completed,
}

/// v2 decrypt submit response (200 OK — always inline for synchronous service).
#[derive(Serialize)]
struct V2DecryptSubmitResponse {
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypted: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_type: Option<i32>,
}

/// v2 decrypt poll response.
#[derive(Serialize)]
struct V2DecryptStatusResponse {
    request_id: String,
    status: RequestStatusHttp,
    submitted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_succeed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypted: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_type: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

/// v2 sealoutput submit response.
#[derive(Serialize)]
struct V2SealOutputSubmitResponse {
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ephemeral_public_key: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_type: Option<i32>,
}

/// v2 sealoutput poll response.
#[derive(Serialize)]
struct V2SealOutputStatusResponse {
    request_id: String,
    status: RequestStatusHttp,
    submitted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_succeed: Option<bool>,
    // Nested `sealed` object — byte-for-byte cofhe's `SealOutputStatusHttpResponse`
    // (the v2 *status* shape nests; the submit shape stays flat, also matching the
    // dispatcher). CofheSDK ignores the submit body, polls this endpoint, and reads
    // `statusResponse.sealed.{data,public_key,nonce}` — so this nesting is what makes
    // `cofhejs/@cofhe-sdk unseal` work against Teecryptor as a dispatcher drop-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed: Option<UserSealedResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_type: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

/// GET /signerAddress response.
#[derive(Serialize)]
struct SignerAddressResponse {
    address: String,
}

// ---------- helpers ----------------------------------------------------------

async fn handle_healthz(State(state): State<AppState>) -> StatusCode {
    if state.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// One INFO line per successfully served decrypt/sealoutput — the operational
/// heartbeat (mirrors cofhe dispatcher's per-request success log). The message
/// itself names the op, ct handle, and chain; those (plus the request id, type,
/// and latency) are also emitted as structured fields, so ops can filter on
/// `jsonPayload.fields.op` in Cloud Logging. Emitted from the handlers that do
/// the crypto work (the v1 routes and the v2 *submit* routes), so it fires
/// exactly once per real operation; the v2 poll routes are cache reads and stay
/// silent.
///
/// Logs only non-sensitive request metadata — the public ct handle, type, chain,
/// and timing. NEVER the decrypted plaintext or the sealed bytes.
fn log_op_success(
    op: &'static str,
    request_id: &str,
    ct_tempkey: &str,
    encryption_type: i32,
    host_chain_id: u64,
    started: Instant,
) {
    let duration_ms = started.elapsed().as_millis() as u64;
    tracing::info!(
        op = %op,
        request_id = %request_id,
        ct_tempkey = %ct_tempkey,
        encryption_type,
        host_chain_id,
        duration_ms,
        "{op} completed: ct {ct_tempkey} on chain {host_chain_id}"
    );
}

/// Which API generation a request arrived on. Only affects how retryable
/// conditions are encoded — see [`ApiVersion::retryable`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApiVersion {
    V1,
    V2,
}

impl ApiVersion {
    /// Encode a retryable condition (overload / ct-not-ready / commitment-pending).
    ///
    /// v2 → bodyless `204` + the `x-cofhe-retry-reason` header: the only status
    /// CofheSDK's v2 submit retries on, and it never calls `.json()` on it, so
    /// the body must stay empty (see [`retryable_204`]).
    ///
    /// v1 → status + JSON body. Old v1 clients have no retry loop and can't
    /// survive an empty body (`204` is 2xx, so they parse it and die), but they
    /// do read `error_message`; the per-reason status and detail live on
    /// [`RetryReason`].
    fn retryable(self, reason: RetryReason) -> Response {
        match self {
            ApiVersion::V2 => retryable_204(reason),
            ApiVersion::V1 => err(
                reason.v1_status(),
                reason.as_str(),
                Some(reason.v1_details().to_string()),
            ),
        }
    }
}

fn err(status: StatusCode, error: &'static str, details: Option<String>) -> Response {
    // Mirror cofhe's dispatcher: clients read `error_message`. Keep our stable
    // machine `error` code alongside it, and fall back to that code when there's
    // no extra detail so the field is never empty.
    let error_message = details.unwrap_or_else(|| error.to_string());
    let mut resp = (
        status,
        Json(ErrorResponse {
            error,
            error_message,
        }),
    )
        .into_response();
    // Every error in the API leaves through this funnel, so labeling it here
    // labels them all — the metric's `outcome` vocabulary is exactly the error
    // codes clients receive. Extensions never reach the wire.
    resp.extensions_mut().insert(Outcome::new(error));
    resp
}

/// Resolve the `signature` field for a response.
///
/// A signing failure returns 500, never `""`: clients only check that `signature`
/// is a string, so `""` passes and then throws inside viem's `parseSignature` —
/// a server fault surfacing as an opaque client crash.
///
/// `None` (no signer) yields `""` but is unreachable in a running service: boot
/// bails without a signer, and mock mints a throwaway. Only tests reach it.
// Err is an axum Response; same shape fetch_decrypt uses.
#[allow(clippy::result_large_err)]
fn resolve_signature<E: std::fmt::Display>(
    signed: Option<Result<String, E>>,
    request_id: &str,
) -> Result<String, Response> {
    match signed {
        None => Ok(String::new()),
        Some(Ok(sig)) => Ok(sig),
        Some(Err(e)) => {
            tracing::error!(%request_id, "signing failed: {e}");
            Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing_failed",
                None,
            ))
        }
    }
}

/// Parse the `x-signature-v-format` request header into a [`SignatureVFormat`].
/// - `"evm"` → recovery id + 27 (EVM format, for `ecrecover`).
/// - anything else / absent → raw (0-3, default).
fn parse_v_format(headers: &HeaderMap) -> SignatureVFormat {
    headers
        .get("x-signature-v-format")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default()
}

/// Convert a validated hex handle into a `U256` for the on-chain ABI calls.
/// `valid_handle` already guaranteed it's hex; here we only bound it to 32
/// bytes (64 hex chars) — anything longer can't fit a `U256`. Returns the
/// error response to short-circuit with on failure. Shared by the ACP and
/// commitment gates so the conversion happens exactly once per request.
// `Err(Response)` mirrors the file-wide "short-circuit with an HTTP response"
// idiom (see `fetch_decrypt`); boxing it here just for this sync helper would
// be inconsistent with the rest of the module.
#[allow(clippy::result_large_err)]
fn handle_to_u256(handle: &str, request_id: &Uuid) -> Result<U256, Response> {
    let handle_hex = handle.strip_prefix("0x").unwrap_or(handle);
    if handle_hex.len() > 64 {
        tracing::info!(%request_id, ct_tempkey = %handle, "handle exceeds 32 bytes (not a U256)");
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Some("handle exceeds 32 bytes (cannot be a U256)".into()),
        ));
    }
    let padded = format!("{handle_hex:0>64}");
    U256::from_str_radix(&padded, 16).map_err(|_| {
        tracing::info!(%request_id, ct_tempkey = %handle, "handle not parseable as U256");
        err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Some("handle is not parseable as U256".into()),
        )
    })
}

/// Machine-readable reason attached to a retryable `204` via the
/// [`RETRY_REASON_HEADER`] response header, so a future CofheSDK release can
/// tell the retry causes apart. Today's SDK ignores it and simply re-submits —
/// the header is purely additive and backward-compatible.
#[derive(Clone, Copy)]
enum RetryReason {
    /// Admission cap hit — the server is shedding load.
    Overloaded,
    /// Ciphertext not yet available from ct-server.
    CtNotReady,
    /// No on-chain commitment for the handle (yet).
    CommitmentPending,
}

impl RetryReason {
    fn as_str(self) -> &'static str {
        match self {
            RetryReason::Overloaded => "overloaded",
            RetryReason::CtNotReady => "ct_not_ready",
            RetryReason::CommitmentPending => "commitment_pending",
        }
    }

    /// v1 clients have no retry loop and crash on a bodyless `204`, so on v1 a
    /// retryable condition is served as an ordinary error response instead (see
    /// [`ApiVersion::retryable`]). Overload is a genuine "busy" → `503`; the
    /// "not produced yet" reasons map to `428 Precondition Required`.
    fn v1_status(self) -> StatusCode {
        match self {
            RetryReason::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            RetryReason::CtNotReady | RetryReason::CommitmentPending => {
                StatusCode::PRECONDITION_REQUIRED
            }
        }
    }

    /// Human-readable `error_message` for the v1 JSON body (old clients surface it).
    fn v1_details(self) -> &'static str {
        match self {
            RetryReason::Overloaded => "server is at its in-flight capacity; retry shortly",
            RetryReason::CtNotReady => "CT not ready",
            RetryReason::CommitmentPending => "commitment not yet posted on-chain; retry shortly",
        }
    }
}

/// Response-header name explaining why a `204` is retryable. Exposed via CORS
/// (see [`cors_layer`]) so a browser CofheSDK can read it.
const RETRY_REASON_HEADER: &str = "x-cofhe-retry-reason";

/// Build a retryable `204 No Content` carrying the retry-reason header. The
/// CofheSDK treats a submit-phase 204 as "retry" (re-submits ~1s, up to a
/// 5-min budget); the header lets a future release distinguish the cause.
fn retryable_204(reason: RetryReason) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        HeaderName::from_static(RETRY_REASON_HEADER),
        HeaderValue::from_static(reason.as_str()),
    );
    // The status alone cannot tell overload from ct-not-ready from
    // commitment-pending; the metric label is what separates them.
    resp.extensions_mut().insert(Outcome::new(reason.as_str()));
    resp
}

/// Run ACP verification for one request. Returns `Some(response)` to
/// short-circuit the handler with an error; `None` means the ACP checked
/// out and the handler can continue. Takes the pre-parsed `handle_u256` (see
/// [`handle_to_u256`]) plus raw fields so `/decrypt` and `/sealoutput` can both
/// call it with their own request shapes.
async fn enforce_acp(
    cfg: &ChainsVerifierConfig,
    handle_u256: U256,
    handle: &str,
    host_chain_id: u64,
    acp: Option<&AcpData>,
    request_id: &Uuid,
) -> Option<Response> {
    // ACP present -> isAllowedWithPermission. No ACP -> isPubliclyAllowed
    // (the public-decrypt path). Denial maps to 401 for a presented-but-rejected
    // ACP, 403 for a handle that simply isn't publicly decryptable.
    let (result, denied) = match acp {
        Some(acp) => (
            verify_via_taskmanager(cfg, acp, handle_u256, host_chain_id).await,
            (StatusCode::UNAUTHORIZED, "acp_denied"),
        ),
        None => (
            verify_publicly_allowed(cfg, handle_u256, host_chain_id).await,
            (StatusCode::FORBIDDEN, "not_publicly_allowed"),
        ),
    };

    match result {
        Ok(()) => None,
        Err(AcpError::Denied) => {
            // Distinguish the with-ACP path (ACL rejected a presented ACP)
            // from the public path (handle isn't publicly decryptable). Log the
            // ACP's non-secret identity and scope fields so a denial is
            // traceable to a caller/permission without leaking the sealing key
            // or signatures — with ACP, "denied" is most often a scope miss, so
            // the scope shape is the first thing worth seeing.
            match acp {
                Some(p) => tracing::info!(
                    %request_id,
                    ct_tempkey = %handle,
                    host_chain_id,
                    issuer = %p.issuer,
                    recipient = %p.recipient,
                    scope = p.scope,
                    contracts = p.contracts.len(),
                    handles = p.handles.len(),
                    revoker_contract = %p.revoker_contract,
                    revoker_data = %p.revoker_data,
                    "acp denied: ACL returned false for isAllowedWithPermission"
                ),
                None => tracing::info!(
                    %request_id,
                    ct_tempkey = %handle,
                    host_chain_id,
                    "acp denied: handle not publicly decryptable (isPubliclyAllowed=false)"
                ),
            }
            Some(err(denied.0, denied.1, None))
        }
        Err(e @ AcpError::UnknownChain(_)) => {
            tracing::info!(%request_id, ct_tempkey = %handle, "acp rejected: {e}");
            Some(err(
                StatusCode::BAD_REQUEST,
                "unknown_chain",
                Some(format!("host_chain_id {host_chain_id} is not configured")),
            ))
        }
        Err(e @ AcpError::Expired) => {
            tracing::info!(%request_id, ct_tempkey = %handle, "acp rejected: {e}");
            Some(err(StatusCode::UNAUTHORIZED, "acp_expired", None))
        }
        Err(e @ AcpError::BadSignature) => {
            tracing::info!(%request_id, ct_tempkey = %handle, "acp rejected: {e}");
            Some(err(StatusCode::UNAUTHORIZED, "acp_invalid", None))
        }
        Err(e @ AcpError::Malformed(_)) => {
            tracing::info!(%request_id, ct_tempkey = %handle, "acp rejected: {e}");
            Some(err(StatusCode::BAD_REQUEST, "acp_malformed", None))
        }
        Err(e @ AcpError::Timeout(_)) => {
            tracing::warn!(%request_id, ct_tempkey = %handle, "acp verifier timeout: {e}");
            Some(err(
                StatusCode::GATEWAY_TIMEOUT,
                "acp_verifier_timeout",
                None,
            ))
        }
        Err(e @ (AcpError::Transport(_) | AcpError::Misconfigured(_))) => {
            tracing::warn!(%request_id, ct_tempkey = %handle, "acp verifier error: {e}");
            Some(err(StatusCode::BAD_GATEWAY, "acp_verifier_error", None))
        }
    }
}

/// Run commitment verification for one request. On success returns
/// `Some(`[`FetchedCommitment`]`)` so the caller can compare the on-chain commit
/// hash against the fetched ciphertext (see
/// [`crate::commitment::calc_commitment`]) and, if that comparison fails on a
/// *cached* hash, re-read the registry before refusing. Returns
/// `Ok(None)` when the gate is in **warn-only** mode and the check failed: the
/// failure is logged and the decrypt is allowed to proceed with no integrity
/// comparison. `Err(response)` short-circuits the handler (enforce mode only).
///
/// A missing commitment (enforce mode) is surfaced as a **retryable** condition
/// — the same class as "ct not ready" — encoded per API version (see
/// [`ApiVersion::retryable`]): v2 gets the bodyless `204` +
/// `x-cofhe-retry-reason: commitment_pending`, v1 gets `428` + a JSON body.
/// Today's SDK just re-submits, which is exactly the bounded retry we want for
/// a commitment that's still propagating.
///
/// Every failure logs exactly one line with stable `gate`/`reason` fields —
/// that pair is the alerting contract (log-based metrics key off it), so treat
/// the values as append-only. Warn-only allows add `mode = "warn_only"`.
#[allow(clippy::result_large_err)] // same short-circuit idiom as handle_to_u256
async fn enforce_commitment(
    cfg: &CommitmentConfig,
    handle_u256: U256,
    handle: &str,
    host_chain_id: u64,
    request_id: &Uuid,
    api: ApiVersion,
) -> Result<Option<FetchedCommitment>, Response> {
    match fetch_commitment(cfg, handle_u256, host_chain_id).await {
        Ok(fetched) => Ok(Some(fetched)),
        Err(CommitmentError::NotFound) => {
            if cfg.warn_only() {
                tracing::warn!(
                    %request_id, ct_tempkey = %handle, host_chain_id,
                    gate = "commitment", reason = "not_found", mode = "warn_only",
                    "commitment not found on-chain, but COMMITMENT_WARN_ONLY is set — allowing decrypt"
                );
                return Ok(None);
            }
            tracing::info!(
                %request_id,
                ct_tempkey = %handle,
                host_chain_id,
                gate = "commitment",
                reason = "not_found",
                "commitment not found on-chain; returning retryable commitment_pending"
            );
            Err(api.retryable(RetryReason::CommitmentPending))
        }
        Err(e @ CommitmentError::Timeout(_)) => {
            if cfg.warn_only() {
                tracing::warn!(
                    %request_id, ct_tempkey = %handle, host_chain_id,
                    gate = "commitment", reason = "timeout", mode = "warn_only",
                    "commitment verifier timeout, but COMMITMENT_WARN_ONLY is set — allowing decrypt: {e}"
                );
                return Ok(None);
            }
            tracing::warn!(
                %request_id,
                ct_tempkey = %handle,
                host_chain_id,
                gate = "commitment",
                reason = "timeout",
                "commitment verifier timeout: {e}"
            );
            Err(err(
                StatusCode::GATEWAY_TIMEOUT,
                "commitment_verifier_timeout",
                None,
            ))
        }
        Err(e @ (CommitmentError::Transport(_) | CommitmentError::Misconfigured(_))) => {
            if cfg.warn_only() {
                tracing::warn!(
                    %request_id, ct_tempkey = %handle, host_chain_id,
                    gate = "commitment", reason = "transport", mode = "warn_only",
                    "commitment verifier error, but COMMITMENT_WARN_ONLY is set — allowing decrypt: {e}"
                );
                return Ok(None);
            }
            tracing::warn!(
                %request_id,
                ct_tempkey = %handle,
                host_chain_id,
                gate = "commitment",
                reason = "transport",
                "commitment verifier error: {e}"
            );
            Err(err(
                StatusCode::BAD_GATEWAY,
                "commitment_verifier_error",
                None,
            ))
        }
    }
}

/// Commitment INTEGRITY check: the bytes ct-server served must hash
/// (`keccak256(data)`, v2 — see [`crate::commitment::calc_commitment`]) to the
/// commit hash the registry gave us, or we're being asked to decrypt a
/// ciphertext the engine never committed to → terminal 502, not retryable (a
/// mismatch is an upstream integrity failure, not a propagation delay).
///
/// One wrinkle: the expectation may have come from the local cache, which can
/// outlive the registry that populated it (an environment redeploy under a
/// long-lived process). So a mismatch against a *cached* hash is not yet a
/// verdict — re-read the registry once past the cache (which also repairs the
/// cached entry) and judge on what the chain says now. A rescue logs
/// `reason = "stale_cache_refreshed"`; only a fresh on-chain hash that still
/// disagrees refuses (or, in warn-only mode, warns and allows).
///
/// If the re-read finds no commitment at all, the cached hash cannot belong to
/// the registry we're talking to: [`refresh_commitment`] has dropped it and this
/// becomes the ordinary retryable commitment-pending path.
///
/// Every failure logs exactly one line with stable `gate`/`reason` fields — the
/// same append-only alerting contract as [`enforce_commitment`].
#[allow(clippy::result_large_err)] // same short-circuit idiom as handle_to_u256
#[allow(clippy::too_many_arguments)] // per-request context, all of it logged
async fn enforce_commitment_integrity(
    cfg: Option<&CommitmentConfig>,
    fetched: FetchedCommitment,
    ct_data: &[u8],
    handle_u256: U256,
    handle: &str,
    host_chain_id: u64,
    request_id: &Uuid,
    api: ApiVersion,
) -> Result<(), Response> {
    let warn_only = cfg.is_some_and(|c| c.warn_only());
    let actual = crate::commitment::calc_commitment(ct_data);
    let mut expected = fetched.hash;

    if actual != expected && fetched.from_cache {
        if let Some(cfg) = cfg {
            match refresh_commitment(cfg, handle_u256, host_chain_id).await {
                Ok(fresh) => {
                    if fresh == actual {
                        tracing::info!(
                            %request_id,
                            ct_tempkey = %handle,
                            host_chain_id,
                            gate = "commitment",
                            reason = "stale_cache_refreshed",
                            stale = %expected,
                            fresh = %fresh,
                            "cached commitment was stale (registry redeployed?); re-read matches the fetched ciphertext — allowing decrypt"
                        );
                        return Ok(());
                    }
                    expected = fresh;
                }
                Err(CommitmentError::NotFound) => {
                    if warn_only {
                        tracing::warn!(
                            %request_id, ct_tempkey = %handle, host_chain_id,
                            gate = "commitment", reason = "not_found", mode = "warn_only",
                            "cached commitment mismatched and the re-read found none on-chain, but COMMITMENT_WARN_ONLY is set — allowing decrypt"
                        );
                        return Ok(());
                    }
                    tracing::info!(
                        %request_id,
                        ct_tempkey = %handle,
                        host_chain_id,
                        gate = "commitment",
                        reason = "not_found",
                        "cached commitment mismatched and the re-read found none on-chain (stale entry evicted); returning retryable commitment_pending"
                    );
                    return Err(api.retryable(RetryReason::CommitmentPending));
                }
                // Couldn't reach the registry to second-guess the cache — fall
                // through and judge on the cached hash (fail closed).
                Err(e) => {
                    tracing::warn!(
                        %request_id,
                        ct_tempkey = %handle,
                        host_chain_id,
                        gate = "commitment",
                        reason = "refresh_failed",
                        "cached commitment mismatched but the re-read failed: {e}"
                    );
                }
            }
        }
    }

    if actual == expected {
        return Ok(());
    }

    if warn_only {
        tracing::warn!(
            %request_id,
            ct_tempkey = %handle,
            host_chain_id,
            gate = "commitment",
            reason = "mismatch",
            mode = "warn_only",
            expected = %expected,
            actual = %actual,
            "on-chain commitment does not match fetched ciphertext bytes, but COMMITMENT_WARN_ONLY is set — allowing decrypt"
        );
        return Ok(());
    }

    tracing::warn!(
        %request_id,
        ct_tempkey = %handle,
        host_chain_id,
        gate = "commitment",
        reason = "mismatch",
        expected = %expected,
        actual = %actual,
        "on-chain commitment does not match fetched ciphertext bytes; refusing to decrypt"
    );
    Err(err(StatusCode::BAD_GATEWAY, "commitment_mismatch", None))
}

fn valid_handle(h: &str) -> bool {
    let s = h.strip_prefix("0x").unwrap_or(h);
    // Handles are short hashes (~32 bytes = 64 hex); bound the length so a caller
    // can't send a multi-MB "handle".
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Common path for `/decrypt` and `/sealoutput`: validate handle, enforce
/// ACP (if configured), fetch ciphertext, validate envelope, decrypt to
/// a `U256`. Returns the decrypted value + the encryption type so the
/// caller can render its response shape.
///
/// On any failure, returns `Err(Response)` — the handler short-circuits with
/// that response. The error mapping (HTTP status + stable error code) is the
/// single source of truth for both endpoints.
async fn fetch_decrypt(
    state: &AppState,
    ct_tempkey: &str,
    host_chain_id: u64,
    acp: Option<&AcpData>,
    request_id: &Uuid,
    api: ApiVersion,
    labels: &DecryptLabels,
) -> Result<(primitive_types::U256, EncryptionType), Response> {
    // Overload backstop — a retryable "busy, come back" condition, so it's
    // encoded per API version (see `ApiVersion::retryable`). On submit the
    // CofheSDK (@cofhe/sdk) v2 client treats the bodyless 204 as *retryable*
    // and silently re-submits (~1s interval, up to a ~5-min budget); it also
    // retries 404 but on a much shorter default budget (~10s, caller-tunable
    // via `.set404RetryTimeout`), and treats 503/429/5xx as FATAL — it gives up
    // immediately and ignores Retry-After. So v2 sheds with the 204 that keeps
    // the client polling; old v1 clients have no retry loop and can't survive an
    // empty body, so v1 sheds with 503 + a JSON body instead. This is the same
    // retryable class as the ct-not-ready and commitment-pending paths.
    let _admit = match state.inner.admit_sem.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            tracing::warn!(%request_id, "in-flight cap reached; shedding (retryable)");
            return Err(api.retryable(RetryReason::Overloaded));
        }
    };
    // `_admit` is held for the whole request; it drops (frees a slot) on return.

    if !valid_handle(ct_tempkey) {
        tracing::info!(%request_id, ct_tempkey = %ct_tempkey, "invalid handle (not hex)");
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            Some("handle must be non-empty hex".into()),
        ));
    }

    // Auth/eligibility gates. The ACP (ACL) check and the commitment check
    // are both on-chain reads on (potentially) different chains, so run them
    // CONCURRENTLY — their latency overlaps instead of summing. The handle is
    // parsed to U256 once and shared by both.
    //
    // Each gate runs only when its verifier was configured at boot; when a gate
    // is disabled, the corresponding request field is intentionally ignored
    // (defense in depth: a deployment that doesn't gate shouldn't surprise the
    // operator by partially honoring an ACP/commitment).
    //
    // Known tradeoff: `join!` waits for BOTH gates, so a request the ACP
    // gate terminally denies still pays (and waits for) the commitment RPC.
    // A select-based short-circuit would save that RPC on the denial path, but
    // denials aren't the path we optimize — keep the sad path simple.
    //
    // Parse the handle to a U256 once; the ACP/commitment gates and the
    // type/zone cross-check below all read from it (`handle_to_u256` is pure, so
    // this is the single conversion per request).
    let handle_u256 = match handle_to_u256(ct_tempkey, request_id) {
        Ok(v) => v,
        Err(resp) => return Err(resp),
    };
    let handle_bytes = handle_u256.to_be_bytes::<32>();

    // `expected_commit` is Some exactly when the commitment gate is enabled —
    // it carries the on-chain commit hash (and whether it was cached) to the
    // post-fetch integrity comparison below. REQUIRE_COMMITMENT is the single
    // switch: gate on means existence AND integrity are both enforced, no
    // partial mode.
    let mut expected_commit: Option<FetchedCommitment> = None;
    if state.acp_verifier().is_some() || state.commitment_verifier().is_some() {
        let acp_fut = async {
            match state.acp_verifier() {
                Some(cfg) => {
                    enforce_acp(cfg, handle_u256, ct_tempkey, host_chain_id, acp, request_id).await
                }
                None => None,
            }
        };
        let commit_fut = async {
            match state.commitment_verifier() {
                Some(cfg) => {
                    // Returns Some(hash) to integrity-check, or None when a
                    // warn-only failure should skip the check and proceed.
                    enforce_commitment(cfg, handle_u256, ct_tempkey, host_chain_id, request_id, api)
                        .await
                }
                None => Ok(None),
            }
        };
        let (acp_resp, commit_res) = tokio::join!(acp_fut, commit_fut);
        // Precedence: a terminal ACP rejection wins over a retryable
        // commitment-pending, so the client isn't told to keep retrying (up to
        // 5 min) a request that is permanently unauthorized.
        if let Some(resp) = acp_resp {
            return Err(resp);
        }
        expected_commit = match commit_res {
            Ok(hash) => hash,
            Err(resp) => return Err(resp),
        };
    }

    let ct = match state.inner.ct_source.fetch(ct_tempkey).await {
        Ok(ct) => ct,
        Err(CtFetchError::NotFound) => {
            tracing::info!(%request_id, ct_tempkey = %ct_tempkey, "ciphertext not found");
            return Err(err(StatusCode::NOT_FOUND, "ct_not_found", None));
        }
        // "ct not ready" is the normal transient state for a freshly-computed
        // handle (available once the engine finishes and its commitment is
        // posted on-chain), so it must be retryable, never fatal. The CofheSDK
        // v2 client polls on the bodyless 204; old v1 clients can't, so v1 gets
        // 428 + a JSON body. Encoded per API version (see `ApiVersion::retryable`).
        Err(CtFetchError::NotReady) => {
            tracing::info!(%request_id, ct_tempkey = %ct_tempkey, "ciphertext not ready");
            return Err(api.retryable(RetryReason::CtNotReady));
        }
        Err(CtFetchError::Timeout) => {
            tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "ct-source timeout");
            return Err(err(StatusCode::GATEWAY_TIMEOUT, "ct_source_timeout", None));
        }
        Err(e) => {
            tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "ct-source error: {e}");
            return Err(err(StatusCode::BAD_GATEWAY, "ct_source_error", None));
        }
    };

    if ct.security_zone != 0 {
        tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "unsupported security zone {}", ct.security_zone);
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_security_zone",
            Some(format!("got {}, only 0 supported", ct.security_zone)),
        ));
    }

    // Modulus-switched compressed (`gzipped`) is the stored canonical form
    // for EVERY ct class (engine results compress at creation; zk-verifier
    // re-compresses verified inputs). Anything else is a legacy/anomalous row
    // whose commitment cannot be trusted to correspond to a canonical store —
    // reject, fail-closed. Compressed cts are decrypted directly (see
    // `direct_decrypt`), never decompressed: a decompress is a PBS whose
    // output bytes depend on the FFT backend of the machine running it, so
    // re-expanded bytes can never be checked against the on-chain commitment.
    if ct.compact || !ct.gzipped {
        tracing::warn!(
            %request_id,
            ct_tempkey = %ct_tempkey,
            compact = ct.compact,
            gzipped = ct.gzipped,
            "ct-server served a non-compressed ciphertext; rejecting"
        );
        return Err(err(StatusCode::BAD_GATEWAY, "ct_source_error", None));
    }

    // Commitment INTEGRITY check (see `enforce_commitment_integrity`): the bytes
    // ct-server just served must hash to the registry's commit hash. The check
    // is over the bytes *as served* — plain (expanded-once by the committer) or
    // gzipped (the engine's stored compressed form) — never over bytes
    // re-derived locally. The keccak of even a large expanded ct is single-digit
    // ms — negligible next to the FHE decrypt, so it runs inline rather than on
    // the CPU gate.
    if let Some(fetched) = expected_commit {
        enforce_commitment_integrity(
            state.commitment_verifier(),
            fetched,
            &ct.data,
            handle_u256,
            ct_tempkey,
            host_chain_id,
            request_id,
            api,
        )
        .await?;
    }

    // Validate the zone is supported; we re-fetch the key inside the gated
    // closure below (a borrow of state can't cross into a 'static spawn_blocking).
    if state.inner.keys.client_key(ct.security_zone).is_none() {
        tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "unsupported security zone {}", ct.security_zone);
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_security_zone",
            Some(format!("got {}, only 0 supported", ct.security_zone)),
        ));
    }

    let ty = match EncryptionType::from_i32(ct.encryption_type) {
        Ok(t) => t,
        Err(_) => {
            tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "unsupported encryption type {}", ct.encryption_type);
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_type",
                Some(format!("encryption_type {}", ct.encryption_type)),
            ));
        }
    };

    // Bind the ct-server-declared type AND zone to the handle's committed
    // metadata bytes (cofhe's `adjust_hash_for_metadata` layout — see
    // `crate::cofhe_layout`). ct-server's `uint_type`/`security_zone` are NOT
    // trusted: tfhe's width-generic `Named::NAME` lets a hostile server relabel
    // wider bytes under a narrower type (e.g. a real `CompressedFheUint64` as
    // `U8`), and the commitment preimage covers the zone but not the type. The
    // handle is the on-chain identifier, so cross-checking against it is what
    // stops the TEE from signing a durable wrong-type/wrong-zone result.
    let handle_type = crate::cofhe_layout::handle_type(&handle_bytes) as i32;
    if handle_type != ct.encryption_type {
        tracing::warn!(
            %request_id,
            ct_tempkey = %ct_tempkey,
            gate = "type",
            handle_type,
            declared = ct.encryption_type,
            "ct-server type disagrees with the handle's committed type byte; refusing to decrypt"
        );
        return Err(err(StatusCode::BAD_GATEWAY, "ct_type_mismatch", None));
    }
    let handle_zone = crate::cofhe_layout::handle_zone(&handle_bytes) as i32;
    if handle_zone != ct.security_zone {
        tracing::warn!(
            %request_id,
            ct_tempkey = %ct_tempkey,
            gate = "zone",
            handle_zone,
            declared = ct.security_zone,
            "ct-server zone disagrees with the handle's committed zone byte; refusing to decrypt"
        );
        return Err(err(StatusCode::BAD_GATEWAY, "ct_zone_mismatch", None));
    }

    // Both metadata gates passed, so the width is now a verified fact and can
    // be attributed to the request. Recorded before the decrypt runs, so an
    // internal decrypt failure is still attributed to the width that caused it.
    labels.set_encryption_type(ty);

    let zone = ct.security_zone;
    let gzipped = ct.gzipped;
    let data = ct.data; // move owned bytes into the closure
    let inner = state.inner.clone(); // Arc<Inner>: Send + Sync, holds the key
    let decrypt_result = crate::cpu::run_gated(&state.inner.decrypt_sem, move || {
        if gzipped {
            // Engine-stored compressed form: decrypt directly with the small
            // LWE secret key — integer-only, ~µs, no PBS/ServerKey. The key
            // was derived once at KeyStore::load.
            let dk = inner
                .keys
                .direct_key(zone)
                .expect("zone validated as supported above");
            crate::direct_decrypt::decrypt_compressed(dk, ty, &data)
        } else {
            // Unreachable: the non-compressed rejection above returns 502 before
            // we get here. The plain path is compiled only under the
            // `legacy-plain-decrypt` feature, pending removal.
            #[cfg(feature = "legacy-plain-decrypt")]
            {
                let ck = inner
                    .keys
                    .client_key(zone)
                    .expect("zone validated as supported above");
                decrypt(ck, ty, &data)
            }
            #[cfg(not(feature = "legacy-plain-decrypt"))]
            {
                Err(crate::error::DecryptError::DirectDecrypt(
                    "non-compressed ciphertext (legacy plain path disabled)".into(),
                ))
            }
        }
    })
    .await;

    match decrypt_result {
        Ok(Ok(pt)) => Ok((pt, ty)),
        Ok(Err(e)) => {
            // safe_deserialize error on bytes ct-server returned — an upstream
            // payload (502) condition, not an internal fault. No detail leaked.
            tracing::warn!(%request_id, ct_tempkey = %ct_tempkey, "decrypt failed (bad ct payload): {e}");
            Err(err(StatusCode::BAD_GATEWAY, "ct_source_error", None))
        }
        Err(join_err) => {
            tracing::error!(%request_id, ct_tempkey = %ct_tempkey, "decrypt task panicked: {join_err}");
            Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                None,
            ))
        }
    }
}

async fn handle_decrypt(
    State(state): State<AppState>,
    Extension(labels): Extension<Arc<DecryptLabels>>,
    headers: HeaderMap,
    Json(req): Json<DecryptRequest>,
) -> Response {
    let request_id = Uuid::new_v4();
    let v_format = parse_v_format(&headers);
    let started = Instant::now();
    labels.set_host_chain_id(req.host_chain_id);
    labels.set_acp_presented(req.acp.is_some());

    let (pt, ty) = match fetch_decrypt(
        &state,
        &req.ct_tempkey,
        req.host_chain_id,
        req.acp.as_ref(),
        &request_id,
        ApiVersion::V1,
        &labels,
    )
    .await
    {
        Ok(out) => out,
        Err(resp) => return resp,
    };

    // 32-byte big-endian representation of the U256 plaintext.
    let decrypted = pt.to_big_endian().to_vec();

    let signature = match resolve_signature(
        state.inner.signer.as_ref().map(|svc| {
            svc.sign_decrypt(&pt, ty as i32, req.host_chain_id, &req.ct_tempkey, v_format)
        }),
        &request_id.to_string(),
    ) {
        Ok(sig) => sig,
        Err(resp) => return resp,
    };

    log_op_success(
        "decrypt",
        &request_id.to_string(),
        &req.ct_tempkey,
        ty as i32,
        req.host_chain_id,
        started,
    );

    (
        StatusCode::OK,
        Json(DecryptResponse {
            decrypted,
            signature,
            encryption_type: ty as i32,
            error_message: None,
        }),
    )
        .into_response()
}

async fn handle_sealoutput(
    State(state): State<AppState>,
    Extension(labels): Extension<Arc<DecryptLabels>>,
    headers: HeaderMap,
    Json(req): Json<SealOutputRequest>,
) -> Response {
    let request_id = Uuid::new_v4();
    let v_format = parse_v_format(&headers);
    let started = Instant::now();
    labels.set_host_chain_id(req.host_chain_id);
    labels.set_acp_presented(req.acp.is_some());

    // sealoutput requires an ACP (the sealingKey must come from somewhere).
    let Some(ref acp) = req.acp else {
        tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealoutput requires an ACP");
        return err(
            StatusCode::BAD_REQUEST,
            "acp_required",
            Some("sealoutput requires an ACP with a sealingKey".into()),
        );
    };

    let (pt_u256, ty) = match fetch_decrypt(
        &state,
        &req.ct_tempkey,
        req.host_chain_id,
        Some(acp),
        &request_id,
        ApiVersion::V1,
        &labels,
    )
    .await
    {
        Ok(out) => out,
        Err(resp) => return resp,
    };

    // Extract the recipient pubkey bytes from the ACP's sealingKey field.
    // hex_decode strips an optional "0x" prefix; reject any non-hex up front.
    let sealing_hex = acp.sealing_key.trim_start_matches("0x");
    let recipient_pk = match hex::decode(sealing_hex) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey not hex: {e}");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some(format!("sealingKey hex: {e}")),
            );
        }
    };

    // Render the decrypted value as cofhe-wire-format bytes (type-sized BE)
    // and hand them to the sealer. Wrap in Zeroizing so the plaintext is
    // scrubbed once sealing completes — TDX-encrypted RAM already protects
    // it, but defense in depth.
    let plaintext = zeroize::Zeroizing::new(ty.encode(pt_u256));

    let sealed_result = match seal_to_user(&recipient_pk, &plaintext) {
        Ok(s) => s,
        Err(SealError::BadKeyLength(n)) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey wrong length: {n} bytes");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some(format!("sealingKey must be 32 bytes, got {n}")),
            );
        }
        Err(SealError::DegenerateKey) => {
            tracing::info!(%request_id, ct_tempkey = %req.ct_tempkey, "sealingKey is degenerate");
            return err(
                StatusCode::BAD_REQUEST,
                "acp_malformed",
                Some("sealingKey is the all-zero / degenerate Curve25519 point".into()),
            );
        }
        Err(SealError::EncryptFailed(e)) => {
            tracing::error!(%request_id, ct_tempkey = %req.ct_tempkey, "seal (crypto_box) failed: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "seal_failed", None);
        }
    };

    let signature = match resolve_signature(
        state.inner.signer.as_ref().map(|svc| {
            svc.sign_sealoutput(
                &sealed_result.data,
                &sealed_result.public_key,
                &sealed_result.nonce,
                ty as i32,
                req.host_chain_id,
                &req.ct_tempkey,
                v_format,
            )
        }),
        &request_id.to_string(),
    ) {
        Ok(sig) => sig,
        Err(resp) => return resp,
    };

    log_op_success(
        "sealoutput",
        &request_id.to_string(),
        &req.ct_tempkey,
        ty as i32,
        req.host_chain_id,
        started,
    );

    (
        StatusCode::OK,
        Json(SealOutputResponse {
            sealed: Some(UserSealedResponse {
                data: sealed_result.data,
                public_key: sealed_result.public_key,
                nonce: sealed_result.nonce,
            }),
            signature,
            encryption_type: ty as i32,
            error_message: None,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tfhe::prelude::FheEncrypt;
    use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
    use tfhe::{generate_keys, ClientKey, ConfigBuilder, FheUint32};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zeroize::Zeroizing;

    const LIMIT: u64 = 1 << 30;

    /// Generate the test ClientKey once (key-gen is the slow part); each test
    /// reloads it cheaply.
    fn shared_key_bytes() -> &'static [u8] {
        static B: OnceLock<Vec<u8>> = OnceLock::new();
        B.get_or_init(|| {
            let (ck, _sk) = generate_keys(ConfigBuilder::default().build());
            let mut b = Vec::new();
            safe_serialize(&ck, &mut b, LIMIT).unwrap();
            b
        })
    }

    fn client_key() -> ClientKey {
        safe_deserialize(shared_key_bytes(), LIMIT).unwrap()
    }

    fn keystore() -> KeyStore {
        KeyStore::load(Zeroizing::new(shared_key_bytes().to_vec())).unwrap()
    }

    fn ct_source(url: &str) -> CtSource {
        CtSource::new(url, Duration::from_secs(5)).unwrap()
    }

    async fn spawn(state: AppState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        format!("http://{addr}")
    }

    async fn mock_get_ct(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    /// A 32-byte handle whose committed type byte (index 30, `& 0x7f`) is `ty`,
    /// matching cofhe's `adjust_hash_for_metadata` layout so it satisfies the
    /// decrypt-path type cross-check. Zone byte (index 31) left 0.
    fn typed_handle(ty: u8) -> String {
        let mut h = [0u8; 32];
        h[30] = ty & 0x7f;
        format!("0x{}", hex::encode(h))
    }

    /// Serialized modulus-switched compressed FheUint32 of `v` under the
    /// shared test key — the stored canonical form (`res.compress()`), the
    /// exact bytes `/GetStoredCt` serves, so tests can compute the commit
    /// hash the engine would have posted for them. The ServerKey (needed only
    /// to *produce* the compressed ct, never to decrypt it) is generated once.
    fn u32_ct_bytes(v: u32) -> Vec<u8> {
        static SK: OnceLock<tfhe::ServerKey> = OnceLock::new();
        let sk = SK.get_or_init(|| tfhe::ServerKey::new(&client_key()));
        tfhe::set_server_key(sk.clone());
        let mut buf = Vec::new();
        safe_serialize(
            &FheUint32::encrypt(v, &client_key()).compress(),
            &mut buf,
            LIMIT,
        )
        .unwrap();
        buf
    }

    /// Build a `/GetStoredCt` JSON body holding a compressed FheUint32 of
    /// `v`, encrypted under the shared test key (so `keystore()` round-trips it).
    fn u32_ct_body(v: u32) -> serde_json::Value {
        serde_json::json!({
            "data": format!("0x{}", hex::encode(u32_ct_bytes(v))),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        })
    }

    // -------- commitment gate ------------------------------------------------

    const CT_PRESENT_B32: &str =
        "0x00000000000000000000000000000000000000000000000000000000000000ab";
    const CT_ABSENT_B32: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    fn commitment_verifier_with(rpc_url: String, timeout: Duration) -> CommitmentConfig {
        CommitmentConfig::new(
            rpc_url,
            alloy::primitives::address!("00000000000000000000000000000000000000cc"),
            crate::commitment::parse_version(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
            timeout,
            std::num::NonZeroUsize::new(1024).unwrap(),
            Duration::from_secs(3600),
        )
        .expect("valid rpc_url")
    }

    fn commitment_verifier(rpc_url: String) -> CommitmentConfig {
        commitment_verifier_with(rpc_url, Duration::from_secs(5))
    }

    #[tokio::test]
    async fn v2_decrypt_commitment_absent_returns_204_with_reason() {
        // Commitment enforcement ON, registry returns bytes32(0) → the handle
        // has no commitment → retryable 204 carrying the reason header so a
        // future SDK can distinguish it from ct-not-ready. Asserted on the v2
        // route: the bodyless 204 (and its reason header) is the v2 encoding of
        // a retryable condition; v1's degradation to 428 + body is covered by
        // `v1_ct_not_ready_is_428_with_json_body` (same `ApiVersion::retryable`).
        let (rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_ABSENT_B32).await;
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": "0xabc", "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204, "absent commitment should be retryable 204");
        assert_eq!(
            r.headers()
                .get("x-cofhe-retry-reason")
                .and_then(|v| v.to_str().ok()),
            Some("commitment_pending"),
            "204 must carry the machine-readable retry reason"
        );
    }

    #[tokio::test]
    async fn decrypt_commitment_hash_match_allows_decrypt() {
        // The registry answers with the REAL commit hash of the ciphertext
        // ct-server serves (keccak256(data), the engine's v2 formula)
        // → both the existence and the integrity check pass → 200.
        // NB: encryption is randomized, so serialize once and reuse the bytes
        // for both the /GetCT body and the expected hash.
        let ct_bytes = u32_ct_bytes(42);
        let commit = crate::commitment::calc_commitment(&ct_bytes);
        let (rpc, _) =
            crate::test_support::spawn_json_rpc_mock(format!("0x{}", hex::encode(commit))).await;
        let ct = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ct_bytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&ct.uri()), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            200,
            "matching commitment should pass the gate and decrypt"
        );
    }

    #[tokio::test]
    async fn decrypt_commitment_hash_mismatch_502() {
        // Commitment EXISTS on-chain but doesn't hash-match the bytes
        // ct-server served → terminal 502 commitment_mismatch (integrity
        // failure, not a propagation delay — the client must not retry).
        let (rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_PRESENT_B32).await;
        let ct = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&ct.uri()), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 502, "hash mismatch must refuse the decrypt");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "commitment_mismatch");
    }

    #[tokio::test]
    async fn decrypt_stale_cached_commitment_is_refreshed_and_allows_decrypt() {
        // The incident this guards: the cache holds a hash from a registry that
        // has since been wiped and redeployed, so every decrypt of an
        // already-seen handle 502s forever even though the fresh chain has the
        // right value. The registry answers a wrong hash once (populating the
        // cache), then the REAL commit hash — modelling the redeploy. The first
        // request legitimately 502s; the second must NOT trust the cached hash:
        // it re-reads the registry, sees the fresh value match, and decrypts.
        let ct_bytes = u32_ct_bytes(42);
        let commit = crate::commitment::calc_commitment(&ct_bytes);
        let (rpc, reqs) = crate::test_support::spawn_json_rpc_mock_seq(vec![
            CT_PRESENT_B32.to_string(),
            format!("0x{}", hex::encode(commit)),
        ])
        .await;
        let ct = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ct_bytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&ct.uri()), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let body =
            serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID });

        let first = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            first.status(),
            502,
            "pre-reset registry answer genuinely mismatches → refuse"
        );

        let second = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            200,
            "a mismatch against a CACHED hash must trigger a re-read, not a refusal"
        );
        assert_eq!(
            reqs.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "second request should serve from cache, then re-read exactly once on mismatch"
        );
    }

    #[tokio::test]
    async fn decrypt_warm_cache_mismatch_still_refuses_when_chain_agrees() {
        // The revalidation must not become a way to launder a real integrity
        // failure: the registry keeps answering the same present-but-wrong hash,
        // so the re-read confirms the mismatch and the second request is refused
        // exactly like the first.
        let (rpc, reqs) = crate::test_support::spawn_json_rpc_mock(CT_PRESENT_B32).await;
        let ct = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&ct.uri()), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let body =
            serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID });

        for _ in 0..2 {
            let r = reqwest::Client::new()
                .post(format!("{base}/decrypt"))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 502, "a chain-confirmed mismatch must refuse");
            let b: serde_json::Value = r.json().await.unwrap();
            assert_eq!(b["error"], "commitment_mismatch");
        }
        assert_eq!(
            reqs.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one initial read, then one revalidation read on the cached mismatch"
        );
    }

    #[tokio::test]
    async fn decrypt_commitment_warn_only_allows_mismatch() {
        // COMMITMENT_WARN_ONLY (gradual rollout): the on-chain commitment does
        // NOT match the served bytes (registry returns a present-but-wrong
        // hash), yet the gate logs a warn and ALLOWS the decrypt → 200. Same ct
        // as the match test so the decrypt itself succeeds; only the registry
        // answer is deliberately wrong.
        let ct_bytes = u32_ct_bytes(42);
        let (rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_PRESENT_B32).await;
        let ct = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ct_bytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&ct.uri()), None)
            .with_commitment_verifier(commitment_verifier(rpc).with_warn_only(true));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            // type/zone-consistent handle (same as the match test): warn-only is
            // scoped to the commitment gate, so only the commitment is wrong here
            // — the handle_type/handle_zone cross-checks (#48) must still pass.
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            200,
            "warn-only mode must allow the decrypt despite a commitment mismatch"
        );
    }

    #[tokio::test]
    async fn decrypt_commitment_timeout_504() {
        // Registry accepts the connection but never answers → bounded by
        // COMMITMENT_TIMEOUT_MS → 504 commitment_verifier_timeout. Status is
        // SDK contract: 5xx is fatal (no retry), which is what we want for a
        // wedged registry.
        let rpc = crate::test_support::spawn_hanging_http_mock().await;
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_commitment_verifier(commitment_verifier_with(rpc, Duration::from_millis(200)));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 504, "registry timeout must map to 504");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "commitment_verifier_timeout");
    }

    #[tokio::test]
    async fn decrypt_commitment_transport_error_502() {
        // Registry RPC unreachable (refused port) → 502
        // commitment_verifier_error. Also SDK contract: fatal, no retry.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_commitment_verifier(commitment_verifier("http://127.0.0.1:1".into()));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 502, "unreachable registry must map to 502");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "commitment_verifier_error");
    }

    #[tokio::test]
    async fn v2_sealoutput_commitment_absent_returns_204_with_reason() {
        // /sealoutput shares fetch_decrypt with /decrypt; this guards against
        // the two paths ever diverging on the commitment gate. Asserted on the
        // v2 route (bodyless 204 + reason header) for the same reason as
        // `v2_decrypt_commitment_absent_returns_204_with_reason`.
        use dryoc::dryocbox::KeyPair;
        use dryoc::types::Bytes;
        let caller = KeyPair::gen();
        let sealing_key_hex = format!("0x{}", hex::encode(Bytes::as_slice(&caller.public_key)));

        let (rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_ABSENT_B32).await;
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_commitment_verifier(commitment_verifier(rpc));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/v2/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": TEST_CHAIN_ID,
                "acp": acp_with_sealing_key(&sealing_key_hex),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            204,
            "sealoutput must enforce the commitment gate"
        );
        assert_eq!(
            r.headers()
                .get("x-cofhe-retry-reason")
                .and_then(|v| v.to_str().ok()),
            Some("commitment_pending"),
        );
    }

    #[tokio::test]
    async fn acp_denial_precedes_commitment_204() {
        // Both gates ON and both would reject: the no-ACP public path gets
        // isPubliclyAllowed=false (→ 403), and the commitment is absent (→ 204).
        // They run concurrently; the terminal ACP denial must WIN, so the
        // client isn't told to retry (for 5 min) a permanently-unauthorized
        // request.
        let (acp_rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_ABSENT_B32).await; // false
        let (commit_rpc, _) = crate::test_support::spawn_json_rpc_mock(CT_ABSENT_B32).await; // absent
        let mut chains = std::collections::HashMap::new();
        chains.insert(
            TEST_CHAIN_ID,
            crate::permit::ChainConfig::new(
                acp_rpc,
                alloy::primitives::address!("00000000000000000000000000000000000000aa"),
                Duration::from_secs(5),
            )
            .expect("valid rpc_url"),
        );
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(ChainsVerifierConfig { chains })
            .with_commitment_verifier(commitment_verifier(commit_rpc));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            403,
            "acp denial (not_publicly_allowed) must take precedence over the commitment 204"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_decrypts_all_succeed_through_gate() {
        // Only 2 CPU permits, but 8 concurrent requests — all must succeed
        // (wait-only gate; nothing is rejected).
        let server = mock_get_ct(u32_ct_body(42)).await;
        let state =
            AppState::new(keystore(), ct_source(&server.uri()), None).with_concurrency(2, 1000);
        state.set_ready();
        let base = spawn(state).await;

        let client = reqwest::Client::new();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let client = client.clone();
            let base = base.clone();
            handles.push(tokio::spawn(async move {
                client
                    .post(format!("{base}/decrypt"))
                    .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
                    .send()
                    .await
                    .unwrap()
                    .status()
            }));
        }
        for h in handles {
            assert_eq!(
                h.await.unwrap().as_u16(),
                200,
                "gated decrypt should succeed"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admission_cap_sheds_with_204() {
        // Delay /GetCT so request #1 holds the single admit permit while #2 arrives.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(u32_ct_body(7))
                    .set_delay(Duration::from_millis(2000)),
            )
            .mount(&server)
            .await;

        // admit = 1: only one request may be in flight; the second is shed.
        let state =
            AppState::new(keystore(), ct_source(&server.uri()), None).with_concurrency(2, 1);
        state.set_ready();
        let base = spawn(state).await;
        let client = reqwest::Client::new();

        // Request #1 holds the admit permit during the 2s ct fetch.
        let base1 = base.clone();
        let c1 = client.clone();
        let r1 = tokio::spawn(async move {
            c1.post(format!("{base1}/decrypt"))
                .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
                .send()
                .await
                .unwrap()
                .status()
        });

        // Let #1 acquire the admit permit and enter the (2s) ct fetch.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // v2 sheds with a bodyless 204 — the only status CofheSDK retries on —
        // carrying the machine-readable retry reason.
        let r2 = client
            .post(format!("{base}/v2/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": "0x02", "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status().as_u16(), 204, "v2 overflow must shed with 204");
        assert_eq!(
            r2.headers()
                .get("x-cofhe-retry-reason")
                .and_then(|v| v.to_str().ok()),
            Some("overloaded"),
            "shed 204 must carry its machine-readable retry reason"
        );
        // Read the body only after the header check — `.text()` consumes `r2`.
        assert_eq!(r2.text().await.unwrap(), "", "v2 204 must carry no body");

        // v1 sheds with 503 + a JSON body — a bodyless 204 would crash old clients.
        let r3 = client
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": "0x03", "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r3.status().as_u16(), 503, "v1 overflow must shed with 503");
        let b3: serde_json::Value = r3.json().await.expect("v1 shed must return a JSON body");
        assert_eq!(b3["error"], "overloaded");
        assert!(b3["error_message"].as_str().is_some_and(|s| !s.is_empty()));

        // #1 still succeeds once ct-source responds.
        assert_eq!(r1.await.unwrap().as_u16(), 200);
    }

    #[tokio::test]
    async fn healthz_reflects_readiness() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        let base = spawn(state.clone()).await;
        let c = reqwest::Client::new();
        assert_eq!(
            c.get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        state.set_ready();
        assert_eq!(
            c.get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }

    #[tokio::test]
    async fn decrypt_happy_path() {
        let ctbytes = u32_ct_bytes(42);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;

        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        // decrypted is a 32-byte big-endian array; last 4 bytes = u32(42) = [0,0,0,42]
        let decrypted: Vec<u8> = serde_json::from_value(body["decrypted"].clone()).unwrap();
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[28..], &[0u8, 0, 0, 42]);
        assert_eq!(body["encryption_type"], 4);
        assert_eq!(body["signature"], ""); // no signer configured

        // Must be PRESENT and null, not omitted — old v1 clients reject `undefined`
        // here, on the success path.
        assert!(
            body.get("error_message").is_some(),
            "error_message key must be present on success; got {body}"
        );
        assert!(body["error_message"].is_null());
    }

    /// With a signer configured, a 200 must carry a real signature — `""` passes
    /// the client's type check and then throws inside viem.
    #[tokio::test]
    async fn signed_responses_are_never_empty_on_v1_and_v2() {
        // #48 serves/accepts only the compressed (gzipped) form and binds the
        // type to the handle's byte 30, so use the compressed fixture and a
        // type-4 handle; the signature-non-emptiness assertion is unchanged.
        let server = mock_get_ct(u32_ct_body(42)).await;

        let signer =
            crate::signing::service::SigningService::from_bytes(zeroize::Zeroizing::new(vec![
                7u8;
                32
            ]))
            .expect("signer");
        let state = AppState::new(keystore(), ct_source(&server.uri()), Some(signer));
        state.set_ready();
        let base = spawn(state).await;

        for route in ["/decrypt", "/v2/decrypt"] {
            let r = reqwest::Client::new()
                .post(format!("{base}{route}"))
                .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "{route}");
            let body: serde_json::Value = r.json().await.unwrap();
            let sig = body["signature"].as_str().expect("signature is a string");
            assert_eq!(
                sig.len(),
                130,
                "{route}: expected 65-byte hex sig, got {sig:?}"
            );
        }
    }

    #[tokio::test]
    async fn decrypt_bad_handle_400() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": "nothex!", "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[tokio::test]
    async fn decrypt_ct_not_found_404() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn decrypt_wrong_zone_422() {
        let ctbytes = u32_ct_bytes(1);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 1, "compact": false, "gzipped": false
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
    }

    /// Helper: spin up an axum server pointed at `server`'s `/GetCT` URI, set
    /// ready, and POST `/decrypt` once. Returns the status code so tests stay
    /// focused on the error-mapping assertion.
    async fn post_decrypt_status(server_uri: &str, timeout: Duration) -> reqwest::StatusCode {
        post_decrypt_status_h(server_uri, timeout, &typed_handle(4)).await
    }

    /// As [`post_decrypt_status`] but with an explicit handle, so type-specific
    /// tests can pass a handle whose committed type byte matches their body's
    /// `uint_type` (otherwise the type cross-check short-circuits first).
    async fn post_decrypt_status_h(
        server_uri: &str,
        timeout: Duration,
        handle: &str,
    ) -> reqwest::StatusCode {
        let state = AppState::new(
            keystore(),
            CtSource::new(server_uri, timeout).unwrap(),
            None,
        );
        state.set_ready();
        let base = spawn(state).await;
        reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": handle, "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Body that gets a `/sealoutput` request past the "ACP required" gate so
    /// it reaches the ct-fetch. The sealingKey is only used *after* the fetch.
    fn not_ready_seal_body() -> serde_json::Value {
        serde_json::json!({
            "ct_tempkey": "0xabc",
            "host_chain_id": 420105u64,
            "acp": {
                "issuer": "0x0000000000000000000000000000000000000001",
                "expiration": 10_000_000_000u64,
                "recipient": "0x0000000000000000000000000000000000000000",
                "validatorId": 0,
                "validatorContract": "0x0000000000000000000000000000000000000000",
                "issuerSignature": format!("0x{}", "00".repeat(65)),
                "recipientSignature": "",
                "sealingKey": format!("0x{}", "11".repeat(32)),
            }
        })
    }

    /// Spawn a service whose ct-server always answers "not ready" (428), then
    /// POST `body` to `route`.
    async fn post_ct_not_ready(route: &str, body: serde_json::Value) -> reqwest::Response {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(428))
            .mount(&server)
            .await;
        let state = AppState::new(
            keystore(),
            CtSource::new(&server.uri(), Duration::from_secs(5)).unwrap(),
            None,
        );
        state.set_ready();
        let base = spawn(state).await;
        reqwest::Client::new()
            .post(format!("{base}{route}"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    fn not_ready_decrypt_body() -> serde_json::Value {
        serde_json::json!({ "ct_tempkey": "0xabc", "host_chain_id": 420105u64 })
    }

    #[tokio::test]
    async fn v2_ct_not_ready_is_bodyless_204() {
        // CofheSDK never calls .json() on a 204, so the body must stay empty.
        for (route, body) in [
            ("/v2/decrypt", not_ready_decrypt_body()),
            ("/v2/sealoutput", not_ready_seal_body()),
        ] {
            let r = post_ct_not_ready(route, body).await;
            assert_eq!(r.status(), 204, "{route}");
            assert_eq!(
                r.text().await.unwrap(),
                "",
                "{route}: 204 must carry no body"
            );
        }
    }

    #[tokio::test]
    async fn v1_ct_not_ready_is_428_with_json_body() {
        // v1 must NOT get the bodyless 204: tnDecryptV1 treats 204 as ok (it's 2xx)
        // and dies on JSON.parse(""); tnSealOutputV1 calls .json() unconditionally.
        // Both read `error_message`, so 428 + a body degrades cleanly.
        for (route, body) in [
            ("/decrypt", not_ready_decrypt_body()),
            ("/sealoutput", not_ready_seal_body()),
        ] {
            let r = post_ct_not_ready(route, body).await;
            assert_eq!(r.status(), 428, "{route}");
            let b: serde_json::Value = r
                .json()
                .await
                .unwrap_or_else(|e| panic!("{route}: v1 must return a JSON body: {e}"));
            assert_eq!(b["error"], "ct_not_ready", "{route}");
            assert!(
                b["error_message"].as_str().is_some_and(|s| !s.is_empty()),
                "{route}: old v1 clients read error_message; got {b}"
            );
        }
    }

    #[tokio::test]
    async fn decrypt_ct_source_timeout_504() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
            .mount(&server)
            .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_millis(50)).await,
            504
        );
    }

    #[tokio::test]
    async fn decrypt_ct_source_transport_error_502() {
        // Port 1 is reserved (tcpmux) and refuses connections — reqwest surfaces
        // a transport error which the handler maps to 502.
        assert_eq!(
            post_decrypt_status("http://127.0.0.1:1", Duration::from_secs(1)).await,
            502
        );
    }

    #[tokio::test]
    async fn decrypt_ct_source_unexpected_status_502() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_secs(5)).await,
            502
        );
    }

    #[tokio::test]
    async fn decrypt_compact_true_rejected_502() {
        let ctbytes = u32_ct_bytes(1);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": true, "gzipped": false
        }))
        .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_secs(5)).await,
            502
        );
    }

    #[tokio::test]
    async fn decrypt_gzipped_direct_decrypts_200() {
        // Engine-stored compressed form: accepted and decrypted directly
        // (no decompress/PBS) — the stored bytes are the committed bytes.
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(u32_ct_bytes(42))),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;

        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        let decrypted: Vec<u8> = serde_json::from_value(body["decrypted"].clone()).unwrap();
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[28..], &[0u8, 0, 0, 42]);
    }

    #[tokio::test]
    async fn decrypt_type_byte_mismatch_rejected_502() {
        // A genuine CompressedFheUint32 (body uint_type=4) served under a handle
        // whose committed type byte says U8: the width-generic wire name can't
        // catch it, so the handle/type cross-check must. The same bytes under a
        // U32 handle decrypt fine.
        let server = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        let client = reqwest::Client::new();

        let bad = client
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(2), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            bad.status(),
            502,
            "U32 bytes under a U8-typed handle must be rejected"
        );

        let good = client
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            good.status(),
            200,
            "U32 bytes under a U32-typed handle decrypt"
        );
    }

    #[tokio::test]
    async fn decrypt_non_compressed_rejected_502() {
        // Everything in cofhe is stored compressed; a plain (non-gzipped) ct
        // is a legacy/anomalous row — rejected at the form gate, before any
        // decrypt work.
        let ck = client_key();
        let mut ctbytes = Vec::new();
        safe_serialize(&FheUint32::encrypt(1u32, &ck), &mut ctbytes, LIMIT).unwrap();
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": false
        }))
        .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_secs(5)).await,
            502
        );
    }

    #[tokio::test]
    async fn decrypt_gzipped_with_plain_bytes_rejected_502() {
        // gzipped flag with non-compressed payload: direct decrypt fails to
        // deserialize — an upstream payload fault, mapped to 502.
        let ck = client_key();
        let mut ctbytes = Vec::new();
        safe_serialize(&FheUint32::encrypt(1u32, &ck), &mut ctbytes, LIMIT).unwrap();
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_secs(5)).await,
            502
        );
    }

    #[tokio::test]
    async fn decrypt_unsupported_type_422() {
        // uint_type=1 is a gap in cofhe's enum (skipped between Bool=0 and U8=2).
        let server = mock_get_ct(serde_json::json!({
            "data": "0xdeadbeef",
            "uint_type": 1, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        assert_eq!(
            post_decrypt_status(&server.uri(), Duration::from_secs(5)).await,
            422
        );
    }

    #[tokio::test]
    async fn decrypt_bad_payload_maps_to_502() {
        // Valid envelope but the bytes aren't a `safe_serialize`d FheUint8 —
        // decrypt's safe_deserialize fails. Handler maps that to 502 (upstream
        // payload), not 500 (internal fault), since the bad bytes came from
        // ct-server.
        let server = mock_get_ct(serde_json::json!({
            "data": "0xdeadbeef",
            "uint_type": 2, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        // Handle type byte = 2 (U8) so the payload actually reaches decrypt and
        // fails at deserialize, rather than being rejected by the type gate.
        assert_eq!(
            post_decrypt_status_h(&server.uri(), Duration::from_secs(5), &typed_handle(2)).await,
            502
        );
    }

    // -------- ACP gate ----------------------------------------------------

    /// Default test chain id used by all ACP-gate tests in this module.
    /// Picked to match cofhe's localfhenix chain id (also used in their mock
    /// HTTP examples).
    const TEST_CHAIN_ID: u64 = 420105;

    /// Build a [`ChainsVerifierConfig`] with one chain pointed at an
    /// unreachable host. Used by tests where the ACP check should fail
    /// BEFORE any RPC call lands (missing ACP, missing chain id, malformed
    /// handle).
    fn acp_verifier_unreachable() -> ChainsVerifierConfig {
        let mut chains = std::collections::HashMap::new();
        chains.insert(
            TEST_CHAIN_ID,
            crate::permit::ChainConfig::new(
                "http://127.0.0.1:1".into(),
                alloy::primitives::address!("00000000000000000000000000000000000000aa"),
                Duration::from_millis(500),
            )
            .expect("valid rpc_url"),
        );
        ChainsVerifierConfig { chains }
    }

    #[tokio::test]
    async fn decrypt_acl_on_no_chain_id_422() {
        // ACL enforcement ON, request lacks host_chain_id → axum returns 422
        // (Unprocessable Entity) because host_chain_id is a required field.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;
        // Body lacks host_chain_id — axum rejects with 422.
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4) }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
    }

    #[tokio::test]
    async fn decrypt_acp_without_chain_id_422() {
        // A ACP is present but host_chain_id is missing → axum returns 422
        // because host_chain_id is required in the request struct.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "acp": {
                    "issuer": "0x0000000000000000000000000000000000000001",
                    "expiration": 10_000_000_000u64,
                    "recipient": "0x0000000000000000000000000000000000000000",
                    "validatorId": 0,
                    "validatorContract": "0x0000000000000000000000000000000000000000",
                    "issuerSignature": "00",
                    "recipientSignature": "",
                    "sealingKey": "0x"
                }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
    }

    #[tokio::test]
    async fn decrypt_no_acp_takes_public_path() {
        // ACL ON, no ACP, valid host_chain_id → isPubliclyAllowed path. The
        // configured RPC is unreachable, so we expect a verifier error (502/504)
        // — proving we *attempted* the public-allowance contract call rather
        // than rejecting the no-ACP request outright (the old 401 behavior).
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert!(
            r.status() == 502 || r.status() == 504,
            "expected a verifier error (RPC unreachable), got {}",
            r.status()
        );
    }

    #[tokio::test]
    async fn decrypt_no_acp_verifier_ignores_acp_field() {
        // When AppState was built WITHOUT a verifier, the ACP field on the
        // request is silently ignored — defense in depth so a misconfigured
        // deployment doesn't half-honor ACPs.
        let ctbytes = u32_ct_bytes(42);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        // A bogus ACP travels alongside the ct_tempkey. Should be ignored.
        // issuerSignature / recipientSignature must be valid hex (even empty) so
        // AcpData deserializes; the bad addresses/issuer are only checked if
        // the verifier is actually consulted (which it isn't here).
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": { "issuer": "garbage", "expiration": 0, "recipient": "garbage",
                            "validatorId": 0, "validatorContract": "garbage",
                            "issuerSignature": "deadbeef", "recipientSignature": "",
                            "sealingKey": "" }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn decrypt_acp_required_rpc_unreachable_502() {
        // ACP + chain_id present, but the verifier's RPC URL doesn't accept
        // connections → handler maps to 502 acp_verifier_error.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": {
                    "issuer": "0x0000000000000000000000000000000000000001",
                    "expiration": 10_000_000_000u64,
                    "recipient": "0x0000000000000000000000000000000000000000",
                    "validatorId": 0,
                    "validatorContract": "0x0000000000000000000000000000000000000000",
                    // Length-correct (65-byte) garbage signature — passes parsing,
                    // fails verification (but verification happens on the contract
                    // side, which we'll never reach because the RPC is dead).
                    "issuerSignature": format!("0x{}", "00".repeat(65)),
                    "recipientSignature": "",
                    "sealingKey": "0x"
                }
            }))
            .send()
            .await
            .unwrap();
        // 502 or 504 depending on whether the OS rejects the connect or it times
        // out; both are valid mappings of "verifier unreachable".
        let s = r.status().as_u16();
        assert!(s == 502 || s == 504, "expected 502 or 504, got {s}");
    }

    #[tokio::test]
    async fn decrypt_unknown_chain_id_400() {
        // Verifier configured for TEST_CHAIN_ID only. Caller sends a different
        // chain id → handler short-circuits with 400 unknown_chain BEFORE any
        // RPC call lands. This is the dispatcher-style chain dispatch in action.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 999_999u64, // not in the config
                "acp": {
                    "issuer": "0x0000000000000000000000000000000000000001",
                    "expiration": 10_000_000_000u64,
                    "recipient": "0x0000000000000000000000000000000000000000",
                    "validatorId": 0,
                    "validatorContract": "0x0000000000000000000000000000000000000000",
                    "issuerSignature": format!("0x{}", "00".repeat(65)),
                    "recipientSignature": "",
                    "sealingKey": "0x"
                }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "unknown_chain");
        // Dispatcher-compat: the human reason is also carried in `error_message`.
        assert!(body["error_message"]
            .as_str()
            .unwrap()
            .contains("host_chain_id"));
    }

    // -------- /sealoutput --------------------------------------------------

    /// Build a minimal `acp` JSON object with the given `sealingKey` hex
    /// string. Used by tests that don't enable ACP cryptographic
    /// verification — only the `sealingKey` field's structural validity
    /// matters here.
    fn acp_with_sealing_key(sealing_key_hex: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": "0x0000000000000000000000000000000000000001",
            "expiration": 10_000_000_000u64,
            "recipient": "0x0000000000000000000000000000000000000000",
            "validatorId": 0,
            "validatorContract": "0x0000000000000000000000000000000000000000",
            "issuerSignature": "0x",
            "recipientSignature": "",
            "sealingKey": sealing_key_hex
        })
    }

    #[tokio::test]
    async fn sealoutput_happy_path_round_trips_to_caller_keypair() {
        use dryoc::dryocbox::{DryocBox, KeyPair, Nonce, PublicKey};
        use dryoc::types::Bytes;

        // 1) Caller generates an X25519 keypair off-line.
        let caller = KeyPair::gen();
        let sealing_key_hex = format!("0x{}", hex::encode(Bytes::as_slice(&caller.public_key)));

        // 2) Teecryptor's ClientKey encrypts u32=42 — this is what ct-server
        //    will hand back.
        let ctbytes = u32_ct_bytes(42);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;

        // 3) Spin up Teecryptor without an ACP verifier (so the ACP
        //    body's signature isn't checked — only sealingKey is used).
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        // 4) Call /sealoutput.
        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": acp_with_sealing_key(&sealing_key_hex),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["encryption_type"], 4);
        assert_eq!(body["signature"], ""); // no signer configured

        // Present-and-null on success — see decrypt_happy_path.
        assert!(body.get("error_message").is_some());
        assert!(body["error_message"].is_null());

        let sealed = &body["sealed"];

        // 5) Open the sealed box using the caller's secret key + the ephemeral
        //    public key Teecryptor returned, verify plaintext = 4-byte BE u32.
        let sealed_bytes: Vec<u8> = serde_json::from_value(sealed["data"].clone()).unwrap();
        let eph_pk_bytes: Vec<u8> = serde_json::from_value(sealed["public_key"].clone()).unwrap();
        let nonce_bytes: Vec<u8> = serde_json::from_value(sealed["nonce"].clone()).unwrap();

        let dryocbox = DryocBox::from_bytes(&sealed_bytes).expect("parse sealed");
        let eph_pk = PublicKey::try_from(eph_pk_bytes.as_slice()).expect("eph pk len");
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce len");
        let recovered = dryocbox
            .decrypt_to_vec(&nonce, &eph_pk, &caller.secret_key)
            .expect("decrypt");

        assert_eq!(recovered, [0u8, 0, 0, 42], "u32=42 → 4-byte BE");
    }

    /// Parity lock: CofheSDK's `unseal` ignores the submit body, polls
    /// `/v2/sealoutput/{id}`, and reads `statusResponse.sealed.{data,public_key,
    /// nonce}` (nested). This pins that the v2 *status* response nests `sealed`
    /// (matching cofhe's `SealOutputStatusHttpResponse`) rather than the old flat
    /// `sealed_data/...` — the shape that makes Teecryptor a dispatcher drop-in.
    #[tokio::test]
    async fn v2_sealoutput_status_nests_sealed_for_sdk_parity() {
        use dryoc::dryocbox::{DryocBox, KeyPair, Nonce, PublicKey};
        use dryoc::types::Bytes;

        let caller = KeyPair::gen();
        let sealing_key_hex = format!("0x{}", hex::encode(Bytes::as_slice(&caller.public_key)));

        let ctbytes = u32_ct_bytes(42);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;

        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        let http = reqwest::Client::new();

        // 1) Submit — the SDK reads ONLY request_id from this response.
        let submit: serde_json::Value = http
            .post(format!("{base}/v2/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": acp_with_sealing_key(&sealing_key_hex),
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let request_id = submit["request_id"].as_str().expect("request_id present");

        // 2) Poll the status endpoint — COMPLETED with a NESTED `sealed` object.
        let body: serde_json::Value = http
            .get(format!("{base}/v2/sealoutput/{request_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["status"], "COMPLETED");
        assert_eq!(body["is_succeed"], true);
        assert!(
            body.get("sealed_data").is_none(),
            "must NOT be flat (old shape) — SDK reads nested `sealed`"
        );
        let sealed = &body["sealed"];
        assert!(sealed.is_object(), "`sealed` must be a nested object");

        // 3) Round-trip the nested bytes to prove they are the real sealed box.
        let sealed_bytes: Vec<u8> = serde_json::from_value(sealed["data"].clone()).unwrap();
        let eph_pk_bytes: Vec<u8> = serde_json::from_value(sealed["public_key"].clone()).unwrap();
        let nonce_bytes: Vec<u8> = serde_json::from_value(sealed["nonce"].clone()).unwrap();
        let dryocbox = DryocBox::from_bytes(&sealed_bytes).expect("parse sealed");
        let eph_pk = PublicKey::try_from(eph_pk_bytes.as_slice()).expect("eph pk len");
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce len");
        let recovered = dryocbox
            .decrypt_to_vec(&nonce, &eph_pk, &caller.secret_key)
            .expect("decrypt");
        assert_eq!(recovered, [0u8, 0, 0, 42], "u32=42 → 4-byte BE");
    }

    #[tokio::test]
    async fn sealoutput_bad_sealing_key_length_400() {
        // ACP with a 4-byte sealingKey instead of 32 — sealer rejects.
        // We expect 400 acp_malformed BEFORE any decrypt work happens.
        let ctbytes = u32_ct_bytes(1);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": acp_with_sealing_key("0xdeadbeef")
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "acp_malformed");
    }

    #[tokio::test]
    async fn sealoutput_zero_sealing_key_400() {
        // ACP with the all-zero sealingKey — sealer rejects as degenerate.
        let ctbytes = u32_ct_bytes(1);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": acp_with_sealing_key(&format!("0x{}", "00".repeat(32)))
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"], "acp_malformed");
    }

    #[tokio::test]
    async fn sealoutput_missing_acp_400() {
        // No ACP at all → handler returns 400 acp_required.
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        assert!(s == 400 || s == 422, "expected 400 or 422, got {s}");
    }

    #[tokio::test]
    async fn sealoutput_accepts_ct_tempkey() {
        // Canonical field name ct_tempkey works correctly.
        use dryoc::dryocbox::KeyPair;
        use dryoc::types::Bytes;
        let caller = KeyPair::gen();
        let sealing_key_hex = format!("0x{}", hex::encode(Bytes::as_slice(&caller.public_key)));

        let ctbytes = u32_ct_bytes(7);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": 420105u64,
                "acp": acp_with_sealing_key(&sealing_key_hex),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn sealoutput_missing_chain_id_422() {
        // host_chain_id is now required in SealOutputRequest; axum returns 422
        // (Unprocessable Entity) when it's missing from the JSON body.
        use dryoc::dryocbox::KeyPair;
        use dryoc::types::Bytes;
        let caller = KeyPair::gen();
        let sealing_key_hex = format!("0x{}", hex::encode(Bytes::as_slice(&caller.public_key)));

        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/sealoutput"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "acp": acp_with_sealing_key(&sealing_key_hex)
                // no host_chain_id
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
    }

    // -------- v2 decrypt -----------------------------------------------------

    #[tokio::test]
    async fn v2_decrypt_returns_200_with_result_inline() {
        let ctbytes = u32_ct_bytes(42);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert!(
            body["request_id"].as_str().is_some(),
            "request_id must be present"
        );
        assert!(body["decrypted"].is_array(), "decrypted must be array");
        assert_eq!(body["encryption_type"], 4);
        assert_eq!(body["signature"], "");
    }

    #[tokio::test]
    async fn v2_decrypt_poll_returns_completed() {
        let ctbytes = u32_ct_bytes(99);
        let server = mock_get_ct(serde_json::json!({
            "data": format!("0x{}", hex::encode(&ctbytes)),
            "uint_type": 4, "security_zone": 0, "compact": false, "gzipped": true
        }))
        .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;

        let submit: serde_json::Value = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let req_id = submit["request_id"].as_str().unwrap().to_string();

        let poll: serde_json::Value = reqwest::Client::new()
            .get(format!("{base}/v2/decrypt/{req_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(poll["status"], "COMPLETED");
        assert_eq!(poll["is_succeed"], true);
        assert!(poll["decrypted"].is_array());
    }

    #[tokio::test]
    async fn v2_decrypt_poll_404_for_unknown_id() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v2/decrypt/nonexistent-id"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    // -------- CORS ----------------------------------------------------------

    /// A browser preflight (`OPTIONS` + `Access-Control-Request-Method`) to the
    /// v2 sealoutput route must come back with an `access-control-allow-origin`
    /// header — without it Chrome blocks the real POST (the bug CofheSDK hit
    /// calling from `http://localhost:3000`). Pins that the router carries a
    /// CORS layer that answers the preflight.
    #[tokio::test]
    async fn cors_preflight_on_v2_sealoutput_allows_origin() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("{base}/v2/sealoutput"))
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type")
            .send()
            .await
            .unwrap();
        assert!(
            r.status().is_success(),
            "preflight should succeed, got {}",
            r.status()
        );
        assert!(
            r.headers().contains_key("access-control-allow-origin"),
            "preflight must carry access-control-allow-origin"
        );
    }

    /// The actual (non-preflight) response must also carry the allow-origin
    /// header, otherwise the browser withholds the body from JS. Exercised via
    /// the `/decrypt` happy path with an `Origin` set.
    #[tokio::test]
    async fn cors_actual_response_carries_allow_origin() {
        let server = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .header("Origin", "http://localhost:3000")
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(
            r.headers().contains_key("access-control-allow-origin"),
            "actual response must carry access-control-allow-origin"
        );
    }

    #[tokio::test]
    async fn signer_address_without_signer_returns_zero_address() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r: serde_json::Value = reqwest::Client::new()
            .get(format!("{base}/signerAddress"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(r["address"], "0x0000000000000000000000000000000000000000");
    }

    // -------- metrics --------------------------------------------------------

    const HTTP_REQUESTS: &str = "http_server_requests_total{";
    const DECRYPT_REQUESTS: &str = "teecryptor_decrypt_requests_total{";
    const DECRYPT_DURATION: &str = "teecryptor_decrypt_duration_seconds_count{";

    /// Find the `series` sample whose labels contain all `needles`. Matches on
    /// substrings, not label order — the exporter's label ordering is not part
    /// of the contract.
    fn sample<'a>(text: &'a str, series: &str, needles: &[&str]) -> Option<&'a str> {
        text.lines()
            .find(|l| l.starts_with(series) && needles.iter().all(|n| l.contains(n)))
    }

    /// A successful response is recorded on BOTH instruments — the counter
    /// sample and the duration histogram share the same label set.
    #[tokio::test]
    async fn metrics_count_success_on_both_instruments() {
        let server = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);

        let text = state.metrics().render().unwrap();
        let line = sample(
            &text,
            HTTP_REQUESTS,
            &[
                r#"http_route="/decrypt""#,
                r#"http_request_method="POST""#,
                r#"http_response_status_code="200""#,
            ],
        )
        .unwrap_or_else(|| panic!("no counter sample for the 200 in:\n{text}"));
        assert!(line.ends_with(" 1"), "expected count 1: {line}");
        assert!(
            text.lines().any(|l| {
                l.starts_with("http_server_request_duration_seconds_bucket{")
                    && l.contains(r#"http_route="/decrypt""#)
            }),
            "no duration bucket for /decrypt in:\n{text}"
        );
    }

    /// An error response through the `err()` funnel lands in the counter
    /// with its status code.
    #[tokio::test]
    async fn metrics_count_error_response() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": "nothex!", "host_chain_id": 420105u64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                HTTP_REQUESTS,
                &[
                    r#"http_route="/decrypt""#,
                    r#"http_response_status_code="400""#,
                ],
            )
            .is_some(),
            "no counter sample for the 400 in:\n{text}"
        );
    }

    /// A 404 on an unroutable path proves the layer wraps axum's fallback:
    /// `MatchedPath` is absent there, and the route label degrades to
    /// `unmatched` instead of echoing the raw (unbounded) path.
    #[tokio::test]
    async fn metrics_count_unmatched_404_without_leaking_path() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .get(format!("{base}/nope/0xdeadbeef"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                HTTP_REQUESTS,
                &[
                    r#"http_route="unmatched""#,
                    r#"http_response_status_code="404""#,
                ],
            )
            .is_some(),
            "no counter sample for the unmatched 404 in:\n{text}"
        );
        assert!(
            !text.contains("0xdeadbeef"),
            "raw path leaked into a label:\n{text}"
        );
    }

    /// A route with a path parameter is labeled by its TEMPLATE, not by the
    /// concrete request id — the one place where the raw path would otherwise
    /// mint a series per caller.
    #[tokio::test]
    async fn metrics_label_route_by_template_not_request_id() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        reqwest::Client::new()
            .get(format!("{base}/v2/decrypt/junk-id"))
            .send()
            .await
            .unwrap();

        let text = state.metrics().render().unwrap();
        assert!(
            text.contains(r#"http_route="/v2/decrypt/{request_id}""#),
            "route template missing in:\n{text}"
        );
        assert!(
            !text.contains("junk-id"),
            "request id leaked into a label:\n{text}"
        );
    }

    /// The bodyless retryable 204 is produced by `retryable_204`, not by a
    /// handler success or the `err()` funnel — exactly the class of response
    /// a handler-level hook would miss. It must land in the counter like any
    /// other status.
    #[tokio::test]
    async fn metrics_count_v2_retryable_204() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(428))
            .mount(&server)
            .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&not_ready_decrypt_body())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                HTTP_REQUESTS,
                &[
                    r#"http_route="/v2/decrypt""#,
                    r#"http_response_status_code="204""#,
                ],
            )
            .is_some(),
            "no counter sample for the retryable 204 in:\n{text}"
        );
    }

    /// The scrape surface must NOT exist on the main router — it is served
    /// only from the dedicated metrics port, which the LB never fronts. A
    /// `/metrics` route sneaking onto the main router would be publicly
    /// routable through the LB.
    #[tokio::test]
    async fn metrics_endpoint_absent_from_main_router() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    // -------- decrypt-path metrics -------------------------------------------

    /// The width is labeled from the VERIFIED type, and a served response is
    /// `outcome="ok"`. The duration histogram takes the sample too: this
    /// request ran a real FHE decrypt.
    #[tokio::test]
    async fn metrics_decrypt_labels_verified_width_on_success() {
        let server = mock_get_ct(u32_ct_body(42)).await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                DECRYPT_REQUESTS,
                &[
                    r#"http_route="/decrypt""#,
                    r#"encryption_type="u32""#,
                    r#"outcome="ok""#,
                ],
            )
            .is_some(),
            "no decrypt sample for the served u32 in:\n{text}"
        );
        assert!(
            sample(&text, DECRYPT_DURATION, &[r#"encryption_type="u32""#]).is_some(),
            "a request that ran a decrypt belongs in the histogram:\n{text}"
        );
    }

    /// The reason a `204` is retryable is invisible in the status code — every
    /// shed looks alike. The outcome label is what separates them, and it comes
    /// from the same `RetryReason` the response header carries.
    #[tokio::test]
    async fn metrics_decrypt_outcome_separates_retryable_204s() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/GetStoredCt"))
            .respond_with(ResponseTemplate::new(428))
            .mount(&server)
            .await;
        let state = AppState::new(keystore(), ct_source(&server.uri()), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&not_ready_decrypt_body())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                DECRYPT_REQUESTS,
                &[
                    r#"http_route="/v2/decrypt""#,
                    r#"outcome="ct_not_ready""#,
                    r#"encryption_type="unknown""#,
                ],
            )
            .is_some(),
            "the 204 must be labeled with its retry reason in:\n{text}"
        );
        assert!(
            sample(&text, DECRYPT_DURATION, &[]).is_none(),
            "no decrypt ran, so nothing belongs in the histogram:\n{text}"
        );
    }

    /// Which gate a decrypt went through: an ACP means
    /// `isAllowedWithPermission`, none means the public-allowance path. The
    /// outcome label already splits the two DENIALS (`acp_denied` vs
    /// `not_publicly_allowed`); this is what tells the two SUCCESS paths apart.
    #[tokio::test]
    async fn metrics_decrypt_labels_the_acp_presence() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;
        let client = reqwest::Client::new();

        client
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID
            }))
            .send()
            .await
            .unwrap();
        client
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({
                "ct_tempkey": typed_handle(4),
                "host_chain_id": TEST_CHAIN_ID,
                "acp": acp_with_sealing_key("0x")
            }))
            .send()
            .await
            .unwrap();

        let text = state.metrics().render().unwrap();
        for value in ["absent", "present"] {
            assert!(
                sample(&text, DECRYPT_REQUESTS, &[&format!(r#"acp="{value}""#)]).is_some(),
                "no decrypt sample with acp=\"{value}\" in:\n{text}"
            );
        }
    }

    /// A chain this deployment serves is labeled by its id; the label survives
    /// a request that fails at the ACP gate, before any ciphertext is fetched.
    #[tokio::test]
    async fn metrics_decrypt_labels_a_served_chain_by_id() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state.clone()).await;

        reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID }))
            .send()
            .await
            .unwrap();

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                DECRYPT_REQUESTS,
                &[r#"host_chain_id="420105""#, r#"encryption_type="unknown""#],
            )
            .is_some(),
            "the served chain must be labeled by its id in:\n{text}"
        );
    }

    /// A chain id outside the configured set never reaches the exposition: it
    /// is caller-supplied, so it would be an unbounded label value.
    #[tokio::test]
    async fn metrics_decrypt_collapses_an_unserved_chain() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None)
            .with_acp_verifier(acp_verifier_unreachable())
            .with_metrics(Metrics::new([TEST_CHAIN_ID]));
        state.set_ready();
        let base = spawn(state.clone()).await;

        reqwest::Client::new()
            .post(format!("{base}/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4), "host_chain_id": 999999999u64 }))
            .send()
            .await
            .unwrap();

        let text = state.metrics().render().unwrap();
        assert!(
            sample(&text, DECRYPT_REQUESTS, &[r#"host_chain_id="other""#]).is_some(),
            "an unserved chain must collapse to \"other\" in:\n{text}"
        );
        assert!(
            !text.contains("999999999"),
            "a caller-supplied chain id leaked into a label:\n{text}"
        );
    }

    /// A body axum itself refuses never reaches the error funnel, so it has no
    /// error code — it is still counted, as `outcome="rejected"` with nothing
    /// the request never established.
    #[tokio::test]
    async fn metrics_decrypt_outcome_rejected_for_a_refused_body() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        // host_chain_id missing → axum rejects with 422 before the handler runs.
        let r = reqwest::Client::new()
            .post(format!("{base}/v2/decrypt"))
            .json(&serde_json::json!({ "ct_tempkey": typed_handle(4) }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);

        let text = state.metrics().render().unwrap();
        assert!(
            sample(
                &text,
                DECRYPT_REQUESTS,
                &[
                    r#"http_route="/v2/decrypt""#,
                    r#"outcome="rejected""#,
                    r#"host_chain_id="unknown""#,
                ],
            )
            .is_some(),
            "an axum-refused body must still be counted in:\n{text}"
        );
    }

    /// `DECRYPT_ROUTES` must stay in sync with the handlers that call
    /// `fetch_decrypt`: drive one request to each and assert every route
    /// reports a decrypt sample (bodies are junk — any status is fine, the
    /// route matched either way).
    #[tokio::test]
    async fn metrics_cover_every_decrypt_route() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;
        let client = reqwest::Client::new();

        for route in DECRYPT_ROUTES {
            client
                .post(format!("{base}{route}"))
                .json(&serde_json::json!({
                    "ct_tempkey": typed_handle(4), "host_chain_id": TEST_CHAIN_ID
                }))
                .send()
                .await
                .unwrap();
        }

        let text = state.metrics().render().unwrap();
        for route in DECRYPT_ROUTES {
            assert!(
                sample(
                    &text,
                    DECRYPT_REQUESTS,
                    &[&format!(r#"http_route="{route}""#)]
                )
                .is_some(),
                "{route} reports no decrypt sample — keep DECRYPT_ROUTES in sync \
                 with the handlers that call fetch_decrypt:\n{text}"
            );
        }
    }

    /// The decrypt family covers the decrypt path only. A route with no chain
    /// and no ciphertext must not mint `unknown`-labeled series.
    #[tokio::test]
    async fn metrics_decrypt_family_skips_other_routes() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;

        reqwest::Client::new()
            .get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap();

        let text = state.metrics().render().unwrap();
        assert!(
            sample(&text, HTTP_REQUESTS, &[r#"http_route="/healthz""#]).is_some(),
            "the transport family must still count it:\n{text}"
        );
        assert!(
            sample(&text, DECRYPT_REQUESTS, &[]).is_none(),
            "/healthz must not appear in the decrypt family:\n{text}"
        );
    }

    /// The metrics router serves the classic Prometheus text exposition with
    /// the samples recorded by the main router's layer.
    #[tokio::test]
    async fn metrics_router_serves_prometheus_text() {
        let state = AppState::new(keystore(), ct_source("http://127.0.0.1:1"), None);
        state.set_ready();
        let base = spawn(state.clone()).await;
        // One real response through the main router so the exposition is
        // non-empty (its own 404 is a fine sample).
        reqwest::Client::new()
            .get(format!("{base}/nope"))
            .send()
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics_app = metrics_router(&state);
        tokio::spawn(async move { axum::serve(listener, metrics_app).await.unwrap() });

        let r = reqwest::Client::new()
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers()[CONTENT_TYPE].to_str().unwrap(),
            prometheus::TEXT_FORMAT
        );
        let text = r.text().await.unwrap();
        assert!(
            sample(
                &text,
                HTTP_REQUESTS,
                &[r#"http_response_status_code="404""#]
            )
            .is_some(),
            "scraped exposition missing the recorded 404 in:\n{text}"
        );
    }
}
