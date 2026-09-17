//! Split an OTLP metrics export into requests the Telemetry API will accept.
//!
//! The API rejects any request carrying more than 200 points, wholesale:
//! `400: "A maximum of 200 points can be written in a single request."` —
//! and the series count only grows as label combinations accumulate, so every
//! deployment eventually crosses the cap and its export dies entirely (staging
//! zee-k did, ~2h after boot, twice). The SDK's `PeriodicReader` exports one
//! request per interval with everything in it and offers no splitting, so the
//! transport splits the serialized request itself.
//!
//! KEEP IN SYNC: duplicated in zee-k-verifier (`zk-verifier/src/otel_split.rs`)
//! on opentelemetry-proto 0.31 — same reasoning as the transport module.

use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::metrics::v1::{metric, Metric, ResourceMetrics, ScopeMetrics};
use prost::Message;

/// The Telemetry API's documented-by-rejection cap.
pub(super) const MAX_POINTS_PER_REQUEST: usize = 200;

fn point_count(m: &Metric) -> usize {
    match &m.data {
        Some(metric::Data::Gauge(d)) => d.data_points.len(),
        Some(metric::Data::Sum(d)) => d.data_points.len(),
        Some(metric::Data::Histogram(d)) => d.data_points.len(),
        Some(metric::Data::ExponentialHistogram(d)) => d.data_points.len(),
        Some(metric::Data::Summary(d)) => d.data_points.len(),
        None => 0,
    }
}

/// A copy of `m` carrying only `range` of its data points.
fn metric_slice(m: &Metric, start: usize, end: usize) -> Metric {
    let mut out = m.clone();
    match &mut out.data {
        Some(metric::Data::Gauge(d)) => d.data_points = d.data_points[start..end].to_vec(),
        Some(metric::Data::Sum(d)) => d.data_points = d.data_points[start..end].to_vec(),
        Some(metric::Data::Histogram(d)) => d.data_points = d.data_points[start..end].to_vec(),
        Some(metric::Data::ExponentialHistogram(d)) => {
            d.data_points = d.data_points[start..end].to_vec()
        }
        Some(metric::Data::Summary(d)) => d.data_points = d.data_points[start..end].to_vec(),
        None => {}
    }
    out
}

/// Split a serialized `ExportMetricsServiceRequest` into encoded requests of
/// at most `max` points each, preserving every resource and scope shell. A
/// request already within the cap comes back untouched (the same bytes).
pub(super) fn split_request(body: &[u8], max: usize) -> Result<Vec<Vec<u8>>, prost::DecodeError> {
    let req = ExportMetricsServiceRequest::decode(body)?;
    let total: usize = req
        .resource_metrics
        .iter()
        .flat_map(|rm| rm.scope_metrics.iter())
        .flat_map(|sm| sm.metrics.iter())
        .map(point_count)
        .sum();
    if total <= max {
        return Ok(vec![body.to_vec()]);
    }

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut current = ExportMetricsServiceRequest::default();
    let mut current_points = 0usize;
    // Which source resource/scope the OPEN shells in `current` mirror — a new
    // chunk, resource or scope invalidates them. Without this, a second
    // resource's metrics would silently land under the first one's shell.
    let (mut cur_ri, mut cur_si) = (usize::MAX, usize::MAX);

    for (ri, rm) in req.resource_metrics.iter().enumerate() {
        for (si, sm) in rm.scope_metrics.iter().enumerate() {
            for m in &sm.metrics {
                let n = point_count(m);
                if n == 0 {
                    continue;
                }
                let mut start = 0;
                while start < n {
                    let end = (start + max).min(n);
                    let points = end - start;
                    if current_points + points > max && current_points > 0 {
                        chunks.push(std::mem::take(&mut current).encode_to_vec());
                        current_points = 0;
                        (cur_ri, cur_si) = (usize::MAX, usize::MAX);
                    }
                    if cur_ri != ri {
                        current.resource_metrics.push(ResourceMetrics {
                            resource: rm.resource.clone(),
                            scope_metrics: vec![],
                            schema_url: rm.schema_url.clone(),
                        });
                        cur_ri = ri;
                        cur_si = usize::MAX;
                    }
                    let cur_rm = current.resource_metrics.last_mut().expect("just ensured");
                    if cur_si != si {
                        cur_rm.scope_metrics.push(ScopeMetrics {
                            scope: sm.scope.clone(),
                            metrics: vec![],
                            schema_url: sm.schema_url.clone(),
                        });
                        cur_si = si;
                    }
                    cur_rm
                        .scope_metrics
                        .last_mut()
                        .expect("just ensured")
                        .metrics
                        .push(metric_slice(m, start, end));
                    current_points += points;
                    start = end;
                }
            }
        }
    }
    if current_points > 0 {
        chunks.push(current.encode_to_vec());
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::metrics::v1::{number_data_point, Gauge, NumberDataPoint};

    fn gauge_metric(name: &str, points: usize) -> Metric {
        Metric {
            name: name.into(),
            data: Some(metric::Data::Gauge(Gauge {
                data_points: (0..points)
                    .map(|i| NumberDataPoint {
                        value: Some(number_data_point::Value::AsInt(i as i64)),
                        ..Default::default()
                    })
                    .collect(),
            })),
            ..Default::default()
        }
    }

    fn request(metrics: Vec<Metric>) -> Vec<u8> {
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    fn counts(chunks: &[Vec<u8>]) -> Vec<usize> {
        chunks
            .iter()
            .map(|c| {
                ExportMetricsServiceRequest::decode(c.as_slice())
                    .unwrap()
                    .resource_metrics
                    .iter()
                    .flat_map(|rm| rm.scope_metrics.iter())
                    .flat_map(|sm| sm.metrics.iter())
                    .map(point_count)
                    .sum()
            })
            .collect()
    }

    #[test]
    fn resources_keep_their_own_metrics() {
        use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, KeyValue};
        use opentelemetry_proto::tonic::resource::v1::Resource;
        let named = |name: &str, metrics: Vec<Metric>| ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".into(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(name.into())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        };
        let body = ExportMetricsServiceRequest {
            resource_metrics: vec![
                named("svc-a", vec![gauge_metric("a", 150)]),
                named("svc-b", vec![gauge_metric("b", 150)]),
            ],
        }
        .encode_to_vec();
        let chunks = split_request(&body, 200).unwrap();
        assert_eq!(
            counts(&chunks),
            vec![150, 150],
            "a resource never shares a shell"
        );
        for (i, want) in [(0usize, "svc-a"), (1usize, "svc-b")] {
            let req = ExportMetricsServiceRequest::decode(chunks[i].as_slice()).unwrap();
            assert_eq!(req.resource_metrics.len(), 1);
            let attrs = &req.resource_metrics[0]
                .resource
                .as_ref()
                .unwrap()
                .attributes;
            match &attrs[0].value.as_ref().unwrap().value {
                Some(any_value::Value::StringValue(v)) => assert_eq!(v, want),
                other => panic!("unexpected attr: {other:?}"),
            }
        }
    }

    #[test]
    fn under_the_cap_is_returned_untouched() {
        let body = request(vec![gauge_metric("a", 199)]);
        let chunks = split_request(&body, 200).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], body, "no re-encode below the cap");
    }

    #[test]
    fn many_small_metrics_pack_up_to_the_cap() {
        let body = request(vec![
            gauge_metric("a", 90),
            gauge_metric("b", 90),
            gauge_metric("c", 90),
        ]);
        let chunks = split_request(&body, 200).unwrap();
        assert_eq!(
            counts(&chunks),
            vec![180, 90],
            "greedy packing, nothing lost"
        );
    }

    #[test]
    fn one_giant_metric_is_split_across_requests() {
        let body = request(vec![gauge_metric("big", 450)]);
        let chunks = split_request(&body, 200).unwrap();
        assert_eq!(counts(&chunks), vec![200, 200, 50]);
        // every point survives, in order
        let values: Vec<i64> = chunks
            .iter()
            .flat_map(|c| {
                ExportMetricsServiceRequest::decode(c.as_slice())
                    .unwrap()
                    .resource_metrics
            })
            .flat_map(|rm| rm.scope_metrics)
            .flat_map(|sm| sm.metrics)
            .flat_map(|m| match m.data {
                Some(metric::Data::Gauge(g)) => g.data_points,
                _ => vec![],
            })
            .map(|p| match p.value {
                Some(number_data_point::Value::AsInt(v)) => v,
                _ => panic!("int points only in this test"),
            })
            .collect();
        assert_eq!(values, (0..450).collect::<Vec<i64>>());
    }
}
