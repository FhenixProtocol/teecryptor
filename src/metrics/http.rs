//! Transport instruments: one counter and one latency histogram over the
//! OpenTelemetry HTTP-server semantic-convention attribute set.

use std::borrow::Cow;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;

use super::DURATION_BOUNDARIES;

/// `http.route` for a request that matched no route — axum's 404 fallback.
const UNMATCHED_ROUTE: &str = "unmatched";

/// `http.request.method` for a method outside the fixed set below.
const OTHER_METHOD: &str = "OTHER";

#[derive(Debug)]
pub(super) struct Instruments {
    /// `http_server_requests_total` — the per-status request counter.
    requests: Counter<u64>,
    /// `http_server_request_duration_seconds` — latency histogram, in seconds.
    duration: Histogram<f64>,
}

impl Instruments {
    pub(super) fn new(meter: &Meter) -> Self {
        Self {
            requests: meter
                .u64_counter("http_server_requests_total")
                .with_description(
                    "HTTP responses served, by method, route template and status code.",
                )
                .build(),
            duration: meter
                .f64_histogram("http_server_request_duration_seconds")
                .with_unit("s")
                .with_description("Time from request receipt to response head, in seconds.")
                .with_boundaries(DURATION_BOUNDARIES.to_vec())
                .build(),
        }
    }

    /// Record one served response on both instruments.
    ///
    /// `route` is the matched route TEMPLATE (`/v2/decrypt/{request_id}`) and
    /// `None` when no route matched — never a raw request path, whose request
    /// ids and scanner junk would mint unbounded series. The router interns one
    /// template per registered route, so this label needs no allowlist: its
    /// value set is the route table itself.
    ///
    /// The method does need one. It arrives verbatim off the wire, so an
    /// arbitrary client token would otherwise become a label value.
    pub(super) fn observe(
        &self,
        route: Option<&str>,
        method: &Method,
        status: StatusCode,
        elapsed: Duration,
    ) {
        let attrs = [
            KeyValue::new("http.request.method", method_label(method)),
            KeyValue::new("http.route", route_label(route)),
            KeyValue::new("http.response.status_code", i64::from(status.as_u16())),
        ];
        self.requests.add(1, &attrs);
        self.duration.record(elapsed.as_secs_f64(), &attrs);
    }
}

/// Owned only for a matched template — the fallback is a borrowed constant.
fn route_label(route: Option<&str>) -> Cow<'static, str> {
    route.map_or(Cow::Borrowed(UNMATCHED_ROUTE), |r| Cow::Owned(r.to_owned()))
}

/// The methods this API (and its CORS preflights) actually serves; anything
/// else collapses to [`OTHER_METHOD`].
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::OPTIONS => "OPTIONS",
        Method::HEAD => "HEAD",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        _ => OTHER_METHOD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A method outside the served set must not reach the exposition verbatim:
    /// the token comes straight off the wire, so it is unbounded input.
    #[test]
    fn method_label_collapses_unserved_methods() {
        assert_eq!(method_label(&Method::POST), "POST");
        assert_eq!(
            method_label(&Method::from_bytes(b"FOOBAR").unwrap()),
            OTHER_METHOD
        );
    }
}
