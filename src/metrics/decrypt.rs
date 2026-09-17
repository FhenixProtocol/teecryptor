//! Decrypt-path instruments: the domain view of the requests the transport
//! family counts by status code.
//!
//! Four of the five labels are things only the request itself can know — the
//! caller's chain, whether it presented an ACP, the ciphertext's width, and why
//! the response ended the way it did. They reach the instruments by two
//! carriers, each matched to when the fact becomes knowable:
//!
//! * [`DecryptLabels`] — a request-scoped sink the metrics layer puts in the
//!   request extensions. The handler writes the chain id and the ACP presence,
//!   `fetch_decrypt` writes the width once it is verified. An early return
//!   keeps whatever was already written.
//! * [`Outcome`] — written to the *response* extensions by the two response
//!   funnels (`err` and `retryable_204`). Because every error path in the API
//!   goes through one of them, the label needs no call-site changes, and its
//!   vocabulary is exactly the machine error codes clients already receive.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use axum::http::StatusCode;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::{KeyValue, StringValue};

use crate::decrypt::EncryptionType;

use super::DURATION_BOUNDARIES;

/// `outcome` for a response that carries a result.
const OK: &str = "ok";
/// `outcome` for a response no API funnel produced — axum rejected the request
/// itself (malformed body, method not allowed), so there is no error code.
const REJECTED: &str = "rejected";
/// `host_chain_id` for a chain id outside the set this deployment serves. The
/// value is caller-supplied, so it can never become a label verbatim.
const OTHER_CHAIN: &str = "other";
/// `host_chain_id` / `acp` / `encryption_type` for a request that ended before
/// it established one.
const UNKNOWN: &str = "unknown";
/// `acp` for a request that carried an ACP.
const ACP_PRESENT: &str = "present";
/// `acp` for a request that carried none.
const ACP_ABSENT: &str = "absent";

/// Why a response ended the way it did, as a bounded label value: `&'static
/// str` because every code is a compile-time constant of the API.
///
/// Set by the response funnels in [`crate::http`]; read back by the metrics
/// layer. Response extensions never reach the wire.
#[derive(Clone, Copy, Debug)]
pub struct Outcome(&'static str);

impl Outcome {
    /// Label a response with the machine error code it carries.
    pub fn new(code: &'static str) -> Self {
        Self(code)
    }
}

/// Request-scoped sink for the labels the request itself discovers.
///
/// Each field is written at exactly one point in the decrypt path, so the first
/// write wins and no lock is needed. Reads happen once, from the metrics layer,
/// after the handler has returned.
#[derive(Debug, Default)]
pub struct DecryptLabels {
    host_chain_id: OnceLock<u64>,
    acp_presented: OnceLock<bool>,
    encryption_type: OnceLock<EncryptionType>,
}

impl DecryptLabels {
    /// Record the caller's host chain id — at handler entry, ahead of every
    /// early return, so even a rejected request is attributed to its chain.
    pub fn set_host_chain_id(&self, chain_id: u64) {
        self.host_chain_id.get_or_init(|| chain_id);
    }

    /// Record whether the caller presented an ACP — at handler entry, next to
    /// the chain id, since it decides which gate the request goes through.
    ///
    /// On `/decrypt` and `/v2/decrypt`, absent means the public-allowance path
    /// (`isPubliclyAllowed`) instead of `isAllowedWithPermission`. On the
    /// sealoutput routes there is no such path: absent is always a 400, since
    /// the ACP is where the sealing key comes from.
    pub fn set_acp_presented(&self, presented: bool) {
        self.acp_presented.get_or_init(|| presented);
    }

    /// Record the ciphertext's width. Called only once the declared type has
    /// been cross-checked against the handle's committed metadata: an
    /// unverified type is ct-server's claim, not a fact.
    pub fn set_encryption_type(&self, ty: EncryptionType) {
        self.encryption_type.get_or_init(|| ty);
    }
}

#[derive(Debug)]
pub(super) struct Instruments {
    /// `teecryptor_decrypt_requests_total` — one count per decrypt-path response.
    requests: Counter<u64>,
    /// `teecryptor_decrypt_duration_seconds` — latency of the requests that reached a
    /// real FHE decrypt, in seconds.
    duration: Histogram<f64>,
    chains: ChainLabels,
}

impl Instruments {
    pub(super) fn new(meter: &Meter, served_chain_ids: impl IntoIterator<Item = u64>) -> Self {
        Self {
            requests: meter
                .u64_counter("teecryptor_decrypt_requests_total")
                .with_description(
                    "Decrypt-path responses, by route, host chain, ACP presence, \
                     ciphertext width and outcome.",
                )
                .build(),
            duration: meter
                .f64_histogram("teecryptor_decrypt_duration_seconds")
                .with_unit("s")
                .with_description(
                    "End-to-end latency of requests that ran an FHE decrypt, in seconds.",
                )
                .with_boundaries(DURATION_BOUNDARIES.to_vec())
                .build(),
            chains: ChainLabels::new(served_chain_ids),
        }
    }

    /// Record one decrypt-path response. `route` is the matched route template
    /// — it doubles as the operation label (`/v2/decrypt` is a v2 decrypt) and
    /// as the join key with the transport family.
    ///
    /// The duration is recorded only when the width is known, which is exactly
    /// when the FHE decrypt ran: a request rejected at the gate would otherwise
    /// pull the distribution towards zero and hide the real cost.
    pub(super) fn observe(
        &self,
        route: &str,
        labels: &DecryptLabels,
        outcome: Option<Outcome>,
        status: StatusCode,
        elapsed: Duration,
    ) {
        // One allocation for the route, shared by both instruments: cloning a
        // ref-counted `StringValue` is an `Arc` bump.
        let route = StringValue::from(Arc::<str>::from(route));
        let width = labels.encryption_type.get();
        let width_label = KeyValue::new("encryption_type", width.map_or(UNKNOWN, |ty| ty.as_str()));
        self.requests.add(
            1,
            &[
                KeyValue::new("http.route", route.clone()),
                KeyValue::new(
                    "host_chain_id",
                    self.chains.label(labels.host_chain_id.get().copied()),
                ),
                KeyValue::new("acp", acp_label(labels.acp_presented.get().copied())),
                width_label.clone(),
                KeyValue::new("outcome", outcome_label(outcome, status)),
            ],
        );
        if width.is_some() {
            self.duration.record(
                elapsed.as_secs_f64(),
                &[KeyValue::new("http.route", route), width_label],
            );
        }
    }
}

/// The `host_chain_id` label values, rendered once at boot from the chains this
/// deployment is configured to serve (`PERMIT_CHAINS_JSON`).
///
/// The chain id arrives in the request body, so it is unbounded input: without
/// this bound a scripted client could mint one series per value it invents.
/// Every real environment bakes the ACP gate on and so configures its chains; a
/// local build without the gate serves no chain and reports them all as
/// [`OTHER_CHAIN`].
#[derive(Debug)]
struct ChainLabels(Box<[(u64, StringValue)]>);

impl ChainLabels {
    fn new(served_chain_ids: impl IntoIterator<Item = u64>) -> Self {
        Self(
            served_chain_ids
                .into_iter()
                .map(|id| (id, StringValue::from(Arc::<str>::from(id.to_string()))))
                .collect(),
        )
    }

    /// A linear scan: the list is a handful of chains, and it is read once per
    /// decrypt-path response.
    fn label(&self, chain_id: Option<u64>) -> StringValue {
        let Some(chain_id) = chain_id else {
            return StringValue::from(UNKNOWN);
        };
        self.0
            .iter()
            .find(|(id, _)| *id == chain_id)
            .map_or_else(|| StringValue::from(OTHER_CHAIN), |(_, l)| l.clone())
    }
}

/// Whether an ACP was presented, or [`UNKNOWN`] for a request that ended
/// before the handler read the body.
fn acp_label(presented: Option<bool>) -> &'static str {
    match presented {
        Some(true) => ACP_PRESENT,
        Some(false) => ACP_ABSENT,
        None => UNKNOWN,
    }
}

/// The response's own machine error code when a funnel produced it; otherwise
/// derived from the status, since a response with a result is a success and
/// anything else was rejected before the funnels could run.
fn outcome_label(outcome: Option<Outcome>, status: StatusCode) -> &'static str {
    match outcome {
        Some(Outcome(code)) => code,
        None if status.is_success() => OK,
        None => REJECTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_label_bounds_caller_supplied_ids() {
        let chains = ChainLabels::new([420105, 421614]);
        assert_eq!(chains.label(Some(420105)).as_str(), "420105");
        assert_eq!(chains.label(Some(999_999_999)).as_str(), OTHER_CHAIN);
        assert_eq!(chains.label(None).as_str(), UNKNOWN);
    }

    #[test]
    fn acp_label_reports_presence_and_the_unset_case() {
        assert_eq!(acp_label(Some(true)), ACP_PRESENT);
        assert_eq!(acp_label(Some(false)), ACP_ABSENT);
        assert_eq!(acp_label(None), UNKNOWN);
    }

    #[test]
    fn outcome_label_falls_back_to_the_status() {
        assert_eq!(
            outcome_label(Some(Outcome::new("ct_not_ready")), StatusCode::NO_CONTENT),
            "ct_not_ready"
        );
        assert_eq!(outcome_label(None, StatusCode::OK), OK);
        assert_eq!(
            outcome_label(None, StatusCode::UNPROCESSABLE_ENTITY),
            REJECTED
        );
    }

    /// The first write wins: the chain id is set at handler entry, so a later
    /// retry of the same request state cannot relabel the sample.
    #[test]
    fn decrypt_labels_keep_the_first_write() {
        let labels = DecryptLabels::default();
        labels.set_host_chain_id(420105);
        labels.set_host_chain_id(1);
        labels.set_acp_presented(true);
        labels.set_acp_presented(false);
        labels.set_encryption_type(EncryptionType::U32);
        labels.set_encryption_type(EncryptionType::Bool);
        assert_eq!(labels.host_chain_id.get().copied(), Some(420105));
        assert_eq!(labels.acp_presented.get().copied(), Some(true));
        assert_eq!(labels.encryption_type.get(), Some(&EncryptionType::U32));
    }
}
