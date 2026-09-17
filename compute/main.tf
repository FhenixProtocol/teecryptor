# Teecryptor — COMPUTE side (workload owner). Deploy target: a per-env compute
# project (e.g. fhenix-testnet).
#
# Owns the Confidential TDX VM, its firewall, and the runtime SA. The VM attests
# PER PARTNER (each partner's own WIF provider) to read its Shamir share of the
# FHE key; the key SOURCE is baked into the binary and selected by tee-env-COFHE_ENV.
# It PULLS its image from the shared fhenix-artifacts-registry project
# (Artifact Registry only) — this module no longer hosts a registry or CI WIF.
# Image build/push + the WIF live in that project; the runtime SA is granted
# artifactregistry.reader on it from there (surfaced here as the runtime_sa_email
# output).
#
# Applied AFTER the image exists (the digest is pinned here and in every
# partner's CEL). State lives in the COMPUTE project's GCS bucket.

terraform {
  required_version = ">= 1.5"
  # Partial backend config passed at init. compute-module state lives in the
  # COMPUTE project's bucket:
  #   terraform init -backend-config="bucket=<compute-project>-tfstate" \
  #                  -backend-config="prefix=teecryptor/compute"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.compute_project_id
  region  = var.region
  zone    = var.zone
}

locals {
  apis = toset(concat(
    [
      "cloudresourcemanager.googleapis.com",
      "compute.googleapis.com",
      "confidentialcomputing.googleapis.com",
      "artifactregistry.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "sts.googleapis.com",
      "logging.googleapis.com",
      "monitoring.googleapis.com",
      "bigquery.googleapis.com",
    ],
    var.wildcard_domain != "" ? ["certificatemanager.googleapis.com"] : [],
  ))
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = each.value
  disable_on_destroy = false
}

# --- Runtime SA: attached to the VM, used by the CS launcher ------------
# Pulls the image from the shared artifact registry (granted artifactregistry.reader
# there, from the ops project), writes logs, calls the Confidential Computing API.
# Also reads the PUBLIC key material from GCS. Private shares are gated per
# partner by attestation -> STS federation (no keys-access SA, no impersonation).
resource "google_service_account" "runtime" {
  account_id   = "teecryptor"
  display_name = "Teecryptor runtime (decrypt-in-TDX)"
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "log_writer" {
  project = var.compute_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

# The VM pushes its metrics to the Telemetry API as this SA. Metrics-only on
# purpose: telemetry.writer would also grant trace and log write.
resource "google_project_iam_member" "telemetry_writer" {
  project = var.compute_project_id
  role    = "roles/telemetry.metricsWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "confidential_workload" {
  project = var.compute_project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

# --- VPC + subnet (optional) --------------------------------------------
resource "google_compute_network" "teecryptor" {
  count                   = var.create_network ? 1 : 0
  name                    = var.vpc_name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "teecryptor" {
  count         = var.create_network ? 1 : 0
  name          = var.subnet_name
  region        = var.region
  network       = google_compute_network.teecryptor[0].self_link
  ip_cidr_range = var.subnet_cidr
  # Private Google Access lets instances reach Google APIs (attestation, Secret
  # Manager, Artifact Registry) without an external IP — a prerequisite for
  # dropping the access_config {} on the NIC in a future hardening pass.
  private_ip_google_access = true
}

locals {
  network    = var.create_network ? google_compute_network.teecryptor[0].self_link : var.network
  subnetwork = var.create_network ? google_compute_subnetwork.teecryptor[0].self_link : (var.subnetwork != "" ? var.subnetwork : null)
  # Google's fixed IAP TCP-forwarding range. Hardcoded rather than a variable:
  # it is the same everywhere, and the metrics debug rule below must never be
  # widened by an operator into a scrape path.
  iap_range = "35.235.240.0/20"
}

# --- Network: firewalled to the caller CIDR -----------------------------
resource "google_compute_firewall" "allow_callers" {
  name      = "allow-teecryptor-from-callers"
  network   = local.network
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
  source_ranges           = [var.caller_cidr]
  target_service_accounts = [google_service_account.runtime.email]
  depends_on              = [google_project_service.apis]
}


# The text exposition on :9090 — a DEBUG surface, not a scrape target. Metrics
# reach Cloud Monitoring by OTLP push; this rule exists so an operator can read
# the in-process counters through `gcloud compute start-iap-tunnel` when a push
# looks wrong. Deliberately narrower than var.caller_cidr: only IAP, never the
# service callers, and never a collector.
resource "google_compute_firewall" "allow_metrics_debug_over_iap" {
  name      = "allow-teecryptor-metrics-debug-iap"
  network   = local.network
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["9090"]
  }
  source_ranges           = [local.iap_range]
  target_service_accounts = [google_service_account.runtime.email]
  depends_on              = [google_project_service.apis]
}


# --- Instance template: source of truth for every MIG instance ----------
# create_before_destroy lets rolling updates build the new template before
# tearing down the old one — the MIG will never reference a deleted template.
resource "google_compute_instance_template" "teecryptor" {
  name_prefix  = "teecryptor-"
  machine_type = var.machine_type
  region       = var.region

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "TDX"
  }

  # Full shielded surface: secure boot + vTPM (measured boot, the root of the
  # attestation) + integrity monitoring. Explicit, not relying on image defaults.
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Confidential VMs cannot live-migrate — host maintenance must TERMINATE.
  # Combined with tee-restart-policy=Never, a maintenance event takes the VM
  # down until a human relaunches (availability is out of scope, Phase 1).
  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  # Instance templates use disk{} not boot_disk{}.
  disk {
    auto_delete  = true
    boot         = true
    source_image = var.cs_image
    disk_size_gb = 50
    disk_type    = "pd-balanced"
  }

  # First-boot pragmatism: an ephemeral external IP gives the VM egress to
  # Google APIs (STS/IAM/Secret Manager/attestation) and image pull without
  # needing Private Google Access / Cloud NAT. Ingress is still closed except
  # var.caller_cidr (firewall above). For prod, drop access_config and enable
  # Private Google Access on the subnet instead.
  network_interface {
    network    = local.network
    subnetwork = local.subnetwork
    access_config {}
  }

  service_account {
    email  = google_service_account.runtime.email
    scopes = ["cloud-platform"]
  }

  metadata = merge({
    # Image pulled from the shared artifact registry; var.image_reference is the ops
    # path (e.g. europe-west4-docker.pkg.dev/fhenix-artifacts-registry/teecryptor/teecryptor).
    "tee-image-reference"        = "${var.image_reference}@${var.image_digest}"
    "tee-restart-policy"         = "Never"
    "tee-container-log-redirect" = "true"
    # Operator-set env (whitelisted by the image's allow_env_override LABEL).
    "tee-env-CT_SOURCE_URL" = var.ct_source_url
    # Baked-environment selector: the key SOURCE (partner projects +
    # per-partner WIF audiences + public bucket/object) is compiled into the
    # binary; COFHE_ENV only picks which blessed environment applies and the binary
    # fails closed on anything else. Identity is per-partner attested WIF
    # federation — no keys-access SA, no impersonation, so no SA_EMAIL /
    # WIP_AUDIENCE / PARTNERS / PUBLIC_BUCKET / PUBLIC_OBJECT here.
    "tee-env-COFHE_ENV" = var.env
    # Permit + commitment gate ENDPOINTS only. The gate switches, Shamir threshold,
    # commitment version, registry address, warn/enforce mode, AND the permit
    # TaskManager address are baked per-env into the image (reader / env policy) — no
    # longer operator-set here. Only the API-keyed RPC endpoints stay env-supplied
    # (PERMIT_CHAINS_JSON carries just rpc URLs now); a baked policy that enables a gate
    # but finds its RPC unset makes the VM refuse to boot (fail-closed).
    "tee-env-PERMIT_CHAINS_JSON"          = var.permit_chains_json
    "tee-env-COMMITMENT_REGISTRY_RPC_URL" = var.commitment_registry_rpc_url
    },
    # CPU-gate knobs — included only when set, so an empty var leaves the env
    # unset and the binary applies its built-in default (DECRYPT_CONCURRENCY =>
    # available_parallelism, MAX_INFLIGHT => 1000).
    var.decrypt_concurrency != "" ? { "tee-env-DECRYPT_CONCURRENCY" = var.decrypt_concurrency } : {},
    var.max_inflight != "" ? { "tee-env-MAX_INFLIGHT" = var.max_inflight } : {},
    var.commitment_timeout_ms != "" ? { "tee-env-COMMITMENT_TIMEOUT_MS" = var.commitment_timeout_ms } : {},
    var.commitment_cache_size != "" ? { "tee-env-COMMITMENT_CACHE_SIZE" = var.commitment_cache_size } : {},
    var.commitment_cache_ttl_secs != "" ? { "tee-env-COMMITMENT_CACHE_TTL_SECS" = var.commitment_cache_ttl_secs } : {},
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    google_project_iam_member.log_writer,
    google_project_iam_member.confidential_workload,
    google_compute_firewall.allow_callers,
  ]
}

# --- Zonal Managed Instance Group ---------------------------------------
resource "google_compute_instance_group_manager" "teecryptor" {
  name               = "teecryptor-mig"
  base_instance_name = "teecryptor"
  zone               = var.zone

  version {
    instance_template = google_compute_instance_template.teecryptor.id
  }

  target_size = var.mig_target_size

  # Updates are MANUAL by design. OPPORTUNISTIC means the MIG never rolls a
  # running instance on its own: bumping image_digest and `terraform apply`
  # only re-points the template — the live VM keeps the old image until an
  # operator explicitly rolls it:
  #   gcloud compute instance-groups managed rolling-action replace teecryptor-mig \
  #     --zone=<zone> --max-surge=1 --max-unavailable=0
  # REPLACE (not RESTART/REFRESH): a Confidential VM's boot image can't change
  # in place, so the instance is recreated — which also forces fresh attestation.
  update_policy {
    type                  = "OPPORTUNISTIC"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }

  # No auto_healing_policies (Phase 1, deferred — availability is out of scope).
  # Adding it later needs a health check tuned to teecryptor's real cold start
  # (attestation + key fetch + CT corpus load); too tight an initial_delay_sec
  # would reap a VM that is merely still booting and turn a hung instance into a
  # crash loop. Revisit when mig_target_size > 1 and a readiness endpoint exists.

  named_port {
    name = "http"
    port = 8080
  }
}

# --- Load balancer ------------------------------------------------------

# GCP health-check probes come from these two ranges; allow them to :8080.
resource "google_compute_firewall" "allow_health_checks" {
  name      = "allow-teecryptor-health-checks"
  network   = local.network
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
  source_ranges           = ["130.211.0.0/22", "35.191.0.0/16"]
  target_service_accounts = [google_service_account.runtime.email]
  depends_on              = [google_project_service.apis]
}

resource "google_compute_global_address" "lb" {
  name = "teecryptor-lb-ip"
}

# Created only when using the classic Compute-managed cert path (no existing cert, no wildcard).
resource "google_compute_managed_ssl_certificate" "lb" {
  count = var.ssl_certificate_id == "" && var.wildcard_domain == "" && var.ssl_certificate_map == "" ? 1 : 0
  name  = "teecryptor-cert"
  managed {
    domains = var.ssl_domains
  }
  lifecycle {
    precondition {
      condition     = length(var.ssl_domains) > 0
      error_message = "ssl_domains must be set when both ssl_certificate_id and wildcard_domain are empty."
    }
  }
}

# Certificate Manager path — supports wildcard DNS (*.example.com).
# After apply, create the CNAME record from the dns_auth_cname_* outputs in your
# DNS provider before the certificate can be provisioned by Google.
resource "google_certificate_manager_dns_authorization" "wildcard" {
  count       = var.wildcard_domain != "" ? 1 : 0
  name        = "teecryptor-wildcard-auth"
  description = "DNS authorization for wildcard domain"
  domain      = var.wildcard_domain
  depends_on  = [google_project_service.apis]
}

resource "google_certificate_manager_certificate" "wildcard" {
  count       = var.wildcard_domain != "" ? 1 : 0
  name        = "teecryptor-wildcard-cert"
  description = "Google-managed wildcard certificate for *.${var.wildcard_domain}"
  managed {
    domains            = ["*.${var.wildcard_domain}", var.wildcard_domain]
    dns_authorizations = [google_certificate_manager_dns_authorization.wildcard[0].id]
  }
}

resource "google_certificate_manager_certificate_map" "lb" {
  count = var.wildcard_domain != "" ? 1 : 0
  name  = "teecryptor-cert-map"
}

resource "google_certificate_manager_certificate_map_entry" "wildcard" {
  count        = var.wildcard_domain != "" ? 1 : 0
  name         = "teecryptor-wildcard-entry"
  map          = google_certificate_manager_certificate_map.lb[0].name
  certificates = [google_certificate_manager_certificate.wildcard[0].id]
  matcher      = "PRIMARY"
}

locals {
  use_cert_map = var.wildcard_domain != "" || var.ssl_certificate_map != ""
  # Classic path: provided self-link or Compute-managed cert.
  # try() safely handles the count=0 case when wildcard mode is active.
  ssl_certificate = var.ssl_certificate_id != "" ? var.ssl_certificate_id : try(google_compute_managed_ssl_certificate.lb[0].id, null)
  # Certificate Manager path: full resource URI expected by certificate_map attribute.
  cert_map_ref = (
    var.ssl_certificate_map != ""
    ? "//certificatemanager.googleapis.com/projects/${var.compute_project_id}/locations/global/certificateMaps/${var.ssl_certificate_map}"
    : (var.wildcard_domain != "" ? "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.lb[0].id}" : null)
  )
  # Cloud Armor: decode rules from the JSON file, or use an empty list (allow-all default only).
  armor_rules = var.armor_rules_file != "" ? jsondecode(file(var.armor_rules_file)) : []
}

# Cloud Armor security policy. It applies three layers, in priority order:
#   1. Custom rules from var.armor_rules_file (IP allow and deny lists).
#   2. A per-client rate limit that bans abusive source IPs.
#   3. The default rule, which allows the remaining traffic.
# Adaptive Protection watches the backend and reports layer 7 DDoS attacks.
resource "google_compute_security_policy" "teecryptor" {
  name        = "teecryptor-armor"
  description = "Cloud Armor policy for the teecryptor HTTPS load balancer."
  type        = "CLOUD_ARMOR"

  # Adaptive Protection builds a traffic baseline and flags layer 7 DDoS
  # attacks in Cloud Logging, with a suggested mitigation rule. Automatic
  # deployment of that rule is out of scope here; the google provider does not
  # expose it for this resource. Review the alert and add the rule to
  # armor_rules_file, or turn auto-deploy on in the console.
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = var.armor_adaptive_protection
      rule_visibility = "STANDARD"
    }
  }

  # Verbose logging records which rule matched each request. It makes attack
  # traffic visible in the load balancer logs.
  advanced_options_config {
    log_level = "VERBOSE"
  }

  dynamic "rule" {
    for_each = local.armor_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = lookup(rule.value, "description", "")
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value.src_ip_ranges
        }
      }
    }
  }

  # Per-client rate limit. Cloud Armor counts requests for each source IP over
  # a sliding interval. A client above the threshold is banned for
  # armor_rate_limit_ban_duration_sec and receives HTTP 429. The priority sits
  # below the custom rules, so an explicit allow or deny still wins.
  dynamic "rule" {
    for_each = var.armor_rate_limit_enabled ? [1] : []
    content {
      action      = "rate_based_ban"
      priority    = "2000000000"
      description = "DDoS: rate limit each source IP"

      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = ["*"]
        }
      }

      rate_limit_options {
        conform_action   = "allow"
        exceed_action    = "deny(429)"
        enforce_on_key   = "IP"
        ban_duration_sec = var.armor_rate_limit_ban_duration_sec

        rate_limit_threshold {
          count        = var.armor_rate_limit_threshold_count
          interval_sec = var.armor_rate_limit_interval_sec
        }

        ban_threshold {
          count        = var.armor_rate_limit_ban_threshold_count
          interval_sec = var.armor_rate_limit_interval_sec
        }
      }
    }
  }

  # Priority 2147483647 is the required default rule.
  rule {
    action      = "allow"
    priority    = "2147483647"
    description = "Default: allow all"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_health_check" "teecryptor" {
  name                = "teecryptor-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 8080
    request_path = "/healthz"
  }
}

resource "google_compute_backend_service" "teecryptor" {
  name                  = "teecryptor-backend"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec           = 30

  backend {
    group           = google_compute_instance_group_manager.teecryptor.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  health_checks   = [google_compute_health_check.teecryptor.id]
  security_policy = google_compute_security_policy.teecryptor.id

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "teecryptor" {
  name            = "teecryptor-lb"
  default_service = google_compute_backend_service.teecryptor.id
}

resource "google_compute_target_https_proxy" "teecryptor" {
  name    = "teecryptor-https-proxy"
  url_map = google_compute_url_map.teecryptor.id
  # certificate_map and ssl_certificates are mutually exclusive on the proxy.
  ssl_certificates = local.use_cert_map ? [] : [local.ssl_certificate]
  certificate_map  = local.cert_map_ref
}

resource "google_compute_global_forwarding_rule" "teecryptor" {
  name                  = "teecryptor-https"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "443"
  target                = google_compute_target_https_proxy.teecryptor.id
  load_balancing_scheme = "EXTERNAL"
}

# --- Outputs ------------------------------------------------------------
output "mig_name" {
  description = "Name of the Managed Instance Group."
  value       = google_compute_instance_group_manager.teecryptor.name
}

output "mig_self_link" {
  description = "Self-link of the Managed Instance Group."
  value       = google_compute_instance_group_manager.teecryptor.self_link
}

output "mig_instance_group" {
  description = "Instance group URL. To list instance IPs: gcloud compute instances list --filter='name~teecryptor' --zones=<zone>"
  value       = google_compute_instance_group_manager.teecryptor.instance_group
}

output "runtime_sa_email" {
  description = "VM's attached SA. Grant it artifactregistry.reader on the shared artifact registry (done in the ops project)."
  value       = google_service_account.runtime.email
}

output "lb_ip" {
  description = "Static external IP of the HTTPS load balancer. Point your DNS A record here."
  value       = google_compute_global_address.lb.address
}

output "dns_auth_cname_name" {
  description = "DNS CNAME record name to add when using wildcard_domain. null in other modes."
  value       = var.wildcard_domain != "" ? google_certificate_manager_dns_authorization.wildcard[0].dns_resource_record[0].name : null
}

output "dns_auth_cname_value" {
  description = "DNS CNAME record value (target) to add when using wildcard_domain. null in other modes."
  value       = var.wildcard_domain != "" ? google_certificate_manager_dns_authorization.wildcard[0].dns_resource_record[0].data : null
}

output "network_self_link" {
  description = "Self-link of the VPC in use (created or pre-existing)."
  value       = local.network
}

output "subnetwork_self_link" {
  description = "Self-link of the subnet in use (created or pre-existing). null when using the default network without an explicit subnet."
  value       = local.subnetwork
}
