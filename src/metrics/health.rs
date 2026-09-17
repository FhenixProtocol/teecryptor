//! Dependency health: what teecryptor can still reach, and its own verdict.
//!
//! Three families, and the split is deliberate:
//!
//! * `teecryptor_dependency_up{dependency}` — the singleton dependencies
//!   (ct-server, the commitment registry).
//! * `teecryptor_acp_rpc_up{host_chain_id}` — one series per ACL chain, kept a
//!   separate family because it is the only per-chain probe. The label values
//!   come from the configured chain set, so cardinality is bounded by
//!   deployment config and can never be driven by a caller.
//! * `teecryptor_healthy` — teecryptor's OWN verdict over the above. Whoever
//!   draws a status page reads this and does not re-derive it: what a given
//!   dependency being down MEANS is a decision for the service that owns the
//!   dependency, not for the publisher.
//!
//! A dependency this deployment does not configure exports no series at all,
//! rather than a misleading 0 or 1 — a commitment gate that is switched off has
//! nothing to be up or down about, and an absent series says exactly that.
//!
//! Probes write into atomics; the observable gauges read them at collection
//! time. That keeps probing off the export path entirely: a slow or wedged
//! probe delays only its own next round, never a scrape or a push.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use opentelemetry::metrics::{Meter, ObservableGauge};
use opentelemetry::KeyValue;

/// `dependency` label for ct-server, the ciphertext source.
pub const CT_SOURCE: &str = "ct_source";
/// `dependency` label for the commitment registry RPC.
pub const COMMITMENT_REGISTRY: &str = "commitment_registry";

/// Down until proven otherwise. Boot reports 0, never 1: nothing should look
/// healthy before it has actually been probed. Every alert duration is far
/// longer than one probe interval, so starting fail-closed cannot page.
const DOWN: u8 = 0;
const UP: u8 = 1;
/// Never probed yet. Publishes as 0 exactly like `DOWN`; it exists only so the
/// first probe result is always logged, whichever way it lands — the baseline
/// that tells a responder how the process came up.
const UNPROBED: u8 = 2;

/// Shared probe state — written by the probe loop, read by the gauge
/// callbacks. Both lists are fixed at boot, so reads need no locking.
#[derive(Debug)]
pub struct Health {
    named: Vec<(&'static str, AtomicU8)>,
    /// `(chain id, pre-rendered label, state)`. The label is rendered once and
    /// probes compare on the number, so neither the collection path nor the
    /// probe path formats anything.
    chains: Vec<(u64, String, AtomicU8)>,
}

/// Store a probe result, reporting whether it changed — which is when (and
/// only when) [`Health::set`] and [`Health::set_chain`] log: one warn when a
/// dependency goes down, one info when it comes up, never a line per probe.
/// The `dependency-down` alert already covers "still down"; what a responder
/// cannot reconstruct later is the moment it started. Starting from
/// [`UNPROBED`] makes the first round always log.
fn transition(state: &AtomicU8, up: bool) -> bool {
    let new = if up { UP } else { DOWN };
    state.swap(new, Ordering::Relaxed) != new
}

impl Health {
    /// Register exactly the dependencies this deployment has.
    pub fn new(
        dependencies: impl IntoIterator<Item = &'static str>,
        chain_ids: impl IntoIterator<Item = u64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            named: dependencies
                .into_iter()
                .map(|d| (d, AtomicU8::new(UNPROBED)))
                .collect(),
            chains: chain_ids
                .into_iter()
                .map(|id| (id, id.to_string(), AtomicU8::new(UNPROBED)))
                .collect(),
        })
    }

    /// Record a probe result for a named dependency.
    ///
    /// A name that was never registered is a programming error: debug builds
    /// assert, so a typo'd constant fails tests; release builds ignore it —
    /// there is no series to update, and a series born at probe time would sit
    /// at 0 forever, firing an alert that names no cause.
    pub fn set(&self, dependency: &str, up: bool) {
        match self.named.iter().find(|(d, _)| *d == dependency) {
            Some((_, state)) => {
                if transition(state, up) {
                    if up {
                        tracing::info!(dependency, "health: dependency is up");
                    } else {
                        tracing::warn!(dependency, "health: dependency is down");
                    }
                }
            }
            None => debug_assert!(false, "unregistered dependency: {dependency}"),
        }
    }

    /// Record a probe result for one ACL chain. An unregistered chain id is
    /// handled exactly like an unregistered name in [`Health::set`].
    pub fn set_chain(&self, chain_id: u64, up: bool) {
        match self.chains.iter().find(|(id, _, _)| *id == chain_id) {
            Some((_, label, state)) => {
                if transition(state, up) {
                    if up {
                        tracing::info!(host_chain_id = %label, "health: chain RPC is up");
                    } else {
                        tracing::warn!(host_chain_id = %label, "health: chain RPC is down");
                    }
                }
            }
            None => debug_assert!(false, "unregistered chain: {chain_id}"),
        }
    }

    /// The verdict: every configured dependency answered its last probe.
    ///
    /// A chain RPC being down counts against the service as a whole rather
    /// than only that chain. A decrypt for an unreachable chain cannot be
    /// authorised at all, so from a caller's point of view teecryptor is not
    /// fully serving — and the publisher wants one answer per service, with
    /// `teecryptor_acp_rpc_up` available when someone needs to know which
    /// chain.
    pub fn healthy(&self) -> bool {
        self.named
            .iter()
            .all(|(_, s)| s.load(Ordering::Relaxed) == UP)
            && self
                .chains
                .iter()
                .all(|(_, _, s)| s.load(Ordering::Relaxed) == UP)
    }
}

/// The registered gauges, held for the process lifetime: dropping an
/// `ObservableGauge` unregisters its callback and the series stops.
#[derive(Debug)]
pub(super) struct Instruments {
    _gauges: Vec<ObservableGauge<u64>>,
}

impl Instruments {
    pub(super) fn new(meter: &Meter, health: Arc<Health>) -> Self {
        let mut gauges = Vec::new();

        if !health.named.is_empty() {
            let h = Arc::clone(&health);
            gauges.push(
                meter
                    .u64_observable_gauge("teecryptor_dependency_up")
                    .with_description("1 when the named dependency answered its last probe")
                    .with_callback(move |observer| {
                        for (dependency, state) in &h.named {
                            observer.observe(
                                u64::from(state.load(Ordering::Relaxed) == UP),
                                &[KeyValue::new("dependency", *dependency)],
                            );
                        }
                    })
                    .build(),
            );
        }

        if !health.chains.is_empty() {
            let h = Arc::clone(&health);
            gauges.push(
                meter
                    .u64_observable_gauge("teecryptor_acp_rpc_up")
                    .with_description("1 when this chain's ACL RPC answered its last probe")
                    .with_callback(move |observer| {
                        for (_, chain_id, state) in &h.chains {
                            observer.observe(
                                u64::from(state.load(Ordering::Relaxed) == UP),
                                &[KeyValue::new("host_chain_id", chain_id.clone())],
                            );
                        }
                    })
                    .build(),
            );
        }

        // Always registered, even with nothing to probe: an absent verdict is
        // indistinguishable from a dead process, which is the one thing this
        // series exists to rule out.
        let h = Arc::clone(&health);
        gauges.push(
            meter
                .u64_observable_gauge("teecryptor_healthy")
                .with_description("teecryptor's own verdict: every configured dependency reachable")
                .with_callback(move |observer| {
                    observer.observe(u64::from(h.healthy()), &[]);
                })
                .build(),
        );

        Self { _gauges: gauges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_dependencies_register_no_state() {
        let health = Health::new([CT_SOURCE], [] as [u64; 0]);
        assert!(!health.healthy(), "ct_source has not been probed yet");
        health.set(CT_SOURCE, true);
        assert!(health.healthy(), "the only configured dependency is up");
    }

    /// The commitment gate is off in this deployment, so its constant is not
    /// registered. Debug builds assert on the programming error; release
    /// builds compile the assert out and the call is a no-op that cannot
    /// invent a series or flip the verdict.
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "unregistered dependency"))]
    fn an_unregistered_dependency_is_rejected_in_debug() {
        let health = Health::new([CT_SOURCE], [] as [u64; 0]);
        health.set(COMMITMENT_REGISTRY, false);
        health.set(CT_SOURCE, true);
        assert!(
            health.healthy(),
            "release: the unregistered set was a no-op"
        );
    }

    /// Same contract for chain ids — see the test above.
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "unregistered chain"))]
    fn an_unregistered_chain_is_rejected_in_debug() {
        let health = Health::new([] as [&'static str; 0], [1_u64]);
        health.set_chain(999, false);
        health.set_chain(1, true);
        assert!(
            health.healthy(),
            "release: the unregistered set was a no-op"
        );
    }

    #[test]
    fn boot_state_is_down_until_probed() {
        let health = Health::new([CT_SOURCE], [420_105_u64]);
        assert!(
            !health.healthy(),
            "nothing may report healthy before it has been probed"
        );
        health.set(CT_SOURCE, true);
        assert!(!health.healthy(), "the chain RPC is still unprobed");
        health.set_chain(420_105, true);
        assert!(health.healthy());
    }

    #[test]
    fn a_down_chain_makes_the_service_unhealthy() {
        let health = Health::new([CT_SOURCE], [1_u64, 2_u64]);
        health.set(CT_SOURCE, true);
        health.set_chain(1, true);
        health.set_chain(2, true);
        assert!(health.healthy());
        health.set_chain(2, false);
        assert!(!health.healthy());
        health.set_chain(2, true);
        assert!(health.healthy());
    }
}
