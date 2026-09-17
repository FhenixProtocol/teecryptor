# --- Access log monitoring (Cloud Armor / LB request logs) --------------
# google_compute_backend_service.teecryptor already has log_config.enable=true
# (main.tf), so every request lands in Cloud Logging as resource.type=
# "http_load_balancer". Two consumers are built on top of that feed:
#   1. Log-based metrics, kept for ad-hoc Metrics Explorer viewing / future
#      alert policies — no dashboard is built directly on Cloud Monitoring.
#   2. A BigQuery sink, feeding the actual dashboard, which lives in Looker
#      Studio (see the bottom of this file). BigQuery/Looker is also the only
#      option for the high-cardinality queries (top source IPs, geo
#      distribution) that log-based metrics can't hold — an IP as a metric
#      label would blow past Cloud Monitoring's per-metric label cardinality
#      limit. There's a single backend service (no path matchers), so
#      "route" here means the request's URL path, not a separate backend.

locals {
  lb_log_filter = "resource.type=\"http_load_balancer\" AND resource.labels.backend_service_name=\"${google_compute_backend_service.teecryptor.name}\""
  # Path only, no host/query string, bounded to two segments: the v2 poll routes
  # carry a request id (/v2/decrypt/<uuid>), so an unbounded capture puts one
  # label value per polled request into every metric below.
  route_extractor = "REGEXP_EXTRACT(httpRequest.requestUrl, \"https?://[^/]+(/[^/?]+(?:/[^/?]+)?)\")"
}

# --- Log-based metrics ----------------------------------------------------

resource "google_logging_metric" "lb_requests" {
  name        = "teecryptor-lb-requests"
  description = "Request count per route + status code, from LB access logs. Backs RPS and status breakdowns."
  filter      = local.lb_log_filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "route"
      value_type = "STRING"
    }
    labels {
      key        = "status"
      value_type = "STRING"
    }
  }

  label_extractors = {
    route  = local.route_extractor
    status = "EXTRACT(httpRequest.status)"
  }
}

resource "google_logging_metric" "lb_latency" {
  name        = "teecryptor-lb-latency"
  description = "Request latency distribution per route, from LB access logs."
  filter      = local.lb_log_filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "DISTRIBUTION"
    unit        = "s"
    labels {
      key        = "route"
      value_type = "STRING"
    }
  }

  value_extractor = "EXTRACT(httpRequest.latency)"
  label_extractors = {
    route = local.route_extractor
  }

  bucket_options {
    exponential_buckets {
      num_finite_buckets = 64
      growth_factor      = 1.4
      scale              = 0.01
    }
  }
}

resource "google_logging_metric" "lb_request_size" {
  name        = "teecryptor-lb-request-size"
  description = "Request size (bytes, client to LB) distribution per route, from LB access logs."
  filter      = local.lb_log_filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "DISTRIBUTION"
    unit        = "By"
    labels {
      key        = "route"
      value_type = "STRING"
    }
  }

  value_extractor = "EXTRACT(httpRequest.requestSize)"
  label_extractors = {
    route = local.route_extractor
  }

  bucket_options {
    exponential_buckets {
      num_finite_buckets = 64
      growth_factor      = 2
      scale              = 1
    }
  }
}

# Note: log-based metrics (lb_requests, lb_latency, lb_request_size) above are
# kept for ad-hoc viewing in Metrics Explorer / future alert policies, but no
# dashboard is built on them — the dashboard itself lives entirely in Looker
# Studio (see below), backed by the raw logs in BigQuery.

# --- BigQuery sink: top IPs + geo distribution -----------------------------
# Log-based metrics can't hold source IP as a label (unbounded cardinality),
# and the LB log has no country field to draw a geo pie chart from directly —
# both need a query engine. This sink lands the raw request logs in BigQuery;
# query it directly (see below) or point Looker Studio at it for the pie
# chart / top-10 table.

resource "google_bigquery_dataset" "lb_logs" {
  dataset_id                 = "teecryptor_lb_logs"
  description                = "Raw Cloud Armor / HTTPS LB request logs for ad-hoc queries (top source IPs, geo distribution)."
  location                   = var.region
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

resource "google_logging_project_sink" "lb_logs_to_bq" {
  name                   = "teecryptor-lb-logs-to-bq"
  destination            = "bigquery.googleapis.com/projects/${var.compute_project_id}/datasets/${google_bigquery_dataset.lb_logs.dataset_id}"
  filter                 = local.lb_log_filter
  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

resource "google_bigquery_dataset_iam_member" "lb_logs_sink_writer" {
  dataset_id = google_bigquery_dataset.lb_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.lb_logs_to_bq.writer_identity
}

# --- GeoIP lookup table -----------------------------------------------------
# Terraform can only create the dataset + table shape here — there's no
# Google-managed IP->country dataset or API to populate it from, and the
# usual free sources (MaxMind GeoLite2, or aggregated mirrors like the
# ip-location-db project) require picking a source/license and a one-time
# `bq load` of the CSV, which is a manual/out-of-band step. Once you've
# chosen a source, load its IPv4 ranges into this table (dotted-decimal
# start/end, matching most of those CSVs directly) and the join in the
# example query below will work.

resource "google_bigquery_dataset" "geoip" {
  dataset_id  = "teecryptor_geoip"
  description = "IP -> country range lookup, loaded out-of-band from a GeoIP CSV. Joined against teecryptor_lb_logs for the geo distribution chart."
  location    = var.region
  depends_on  = [google_project_service.apis]
}

resource "google_bigquery_table" "geoip_ranges" {
  dataset_id          = google_bigquery_dataset.geoip.dataset_id
  table_id            = "ip_country_ranges"
  description         = "Populated out-of-band via `bq load` from a GeoIP CSV (e.g. MaxMind GeoLite2-Country, or a free mirror such as the ip-location-db project) — Terraform only owns the schema."
  deletion_protection = false

  schema = jsonencode([
    { name = "start_ip", type = "STRING", mode = "REQUIRED", description = "Range start, dotted-decimal IPv4." },
    { name = "end_ip", type = "STRING", mode = "REQUIRED", description = "Range end, dotted-decimal IPv4." },
    { name = "country_iso_code", type = "STRING", mode = "NULLABLE" },
    { name = "country_name", type = "STRING", mode = "NULLABLE" },
  ])
}

# Example queries (BigQuery console, or as a Looker Studio custom-SQL data source):
#
# Top 10 source IPs, last 24h:
#   SELECT httpRequest.remoteIp AS ip, COUNT(*) AS requests
#   FROM `<project>.teecryptor_lb_logs.requests`
#   WHERE DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
#   GROUP BY ip ORDER BY requests DESC LIMIT 10;
#
# Geo distribution (once teecryptor_geoip.ip_country_ranges is loaded):
#   SELECT geo.country_name AS country, COUNT(*) AS requests
#   FROM `<project>.teecryptor_lb_logs.requests` r
#   JOIN `<project>.teecryptor_geoip.ip_country_ranges` geo
#     ON NET.IPV4_TO_INT64(NET.SAFE_IP_FROM_STRING(r.httpRequest.remoteIp))
#        BETWEEN NET.IPV4_TO_INT64(NET.SAFE_IP_FROM_STRING(geo.start_ip))
#            AND NET.IPV4_TO_INT64(NET.SAFE_IP_FROM_STRING(geo.end_ip))
#   GROUP BY country ORDER BY requests DESC;

output "lb_logs_bq_dataset" {
  description = "BigQuery dataset holding raw LB request logs — query for top IPs / geo distribution, or point Looker Studio at it."
  value       = google_bigquery_dataset.lb_logs.dataset_id
}

output "lb_logs_bq_table" {
  description = "BigQuery table (dataset.table) holding the LB request logs. Name is fixed by the sink: partitioned exports use a single table named after the log ID (\"requests\" for LB request logs), not date-sharded."
  value       = "${google_bigquery_dataset.lb_logs.dataset_id}.requests"
}

output "geoip_bq_table" {
  description = "Empty GeoIP lookup table (dataset.table) — load a GeoIP CSV into this via `bq load` before the geo-distribution query will return rows."
  value       = "${google_bigquery_dataset.geoip.dataset_id}.${google_bigquery_table.geoip_ranges.table_id}"
}

# Looker Studio has no Terraform/API resource to create a report, a data
# source, or charts — everything below is a manual click-through recipe.
# (The "linking API" deep-link approach doesn't work for bootstrapping a
# blank report from nothing — in practice it's for re-pointing a template
# report you already own at new data, and produced three different failures
# when tried here, so don't bother with it.)
#
# 1. lookerstudio.google.com > Create > Data source > BigQuery.
# 2. Project = var.compute_project_id, dataset = lb_logs_bq_dataset output
#    ("teecryptor_lb_logs"), table = "requests" (from lb_logs_bq_table
#    output) > Connect > Create Report.
#
# On that data source, add two calculated fields first — every chart below is
# built from these two plus native fields:
# calculated fields first — every chart below is built from these two plus
# native fields:
#   route  = REGEXP_EXTRACT(httpRequest.requestUrl, "https?://[^/]+(/[^?]*)")
#   status = httpRequest.status
#
# Charts:
#   - Requests by route (RPS stand-in): Time series chart, dimension = the
#     log's timestamp field (default granularity, e.g. per-minute — Looker
#     Studio doesn't bin per-second, so this reads as "requests/min", not a
#     literal RPS instantaneous rate), breakdown dimension = route,
#     metric = Record Count.
#   - Request latency p95 by route: Table or bar chart, dimension = route,
#     metric = httpRequest.latency with aggregation "Percentile" set to 95.
#     httpRequest.latency exports from Cloud Logging as a STRING duration
#     (e.g. "0.123s") — add a calculated field
#     `CAST(REGEXP_EXTRACT(httpRequest.latency, "([0-9.]+)s") AS NUMBER)`
#     and use that as the metric instead (verify the exact string format
#     against real exported rows first, in case Google changes it).
#   - Request size p95 by route: same shape, metric = httpRequest.requestSize
#     with aggregation "Percentile" set to 95 (this one's already numeric).
#   - Total requests by route + status: Table chart, dimensions = route,
#     status, metric = Record Count — rename its alias to "Total Requests"
#     in the field editor (the thing Cloud Monitoring's table couldn't do).
#   - Top 10 IPs: Table chart, dimension = httpRequest.remoteIp, metric =
#     Record Count, sort descending, row limit 10.
#   - Geo pie: Pie chart, but first add a second data source using the
#     custom-SQL connector with the geo distribution query above, since it's
#     a join, not a single table — then dimension = country, metric =
#     requests.
