# Teecryptor — KEYS side (identity custodian).
#
# Owns the Confidential-Space attestation Workload Identity Pool + CEL (the trust
# boundary) and the keys-access SA the TDX workload impersonates. It does NOT host
# key material: the FHE-priv secret is Shamir-split across the partner projects, so
# the keys-access SA is granted read on `cofhe-tee-fhe-priv` in EACH partner (via
# the keygen partner module's `readers` map) and objectViewer on the public-material
# bucket — both cross-project grants, applied on those sides, not here. The compute
# side runs the VM and produces the image_digest this module pins.
#
# Two-phase deploy: the compute-side CI builds the image and captures the digest;
# that digest is pinned BOTH in the WIP CEL and the principalSet impersonation
# binding below (defense in depth). See ../SECURITY-OVERVIEW.md.

terraform {
  required_version = ">= 1.5"
  # Partial backend config passed at init. keys-module state lives in the KEYS
  # project's bucket:
  #   terraform init -backend-config="bucket=<keys-project>-tfstate" \
  #                  -backend-config="prefix=teecryptor/keys"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.keys_project_id
}

locals {
  apis = [
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = each.value
  disable_on_destroy = false
}

# The keys-access SA: the identity the attested TDX workload impersonates to read
# the key material. It lives here (keys project); the VM's *attached* SA lives in
# the compute project and never touches keys. Its read grants are cross-project and
# applied elsewhere: `secretAccessor` on `cofhe-tee-fhe-priv` in each partner (the
# keygen partner module's `readers` map) + `objectViewer` on the public-material
# bucket. This module only makes the SA impersonatable by the attested image.
resource "google_service_account" "keys_access" {
  account_id   = "teecryptor-keys-access"
  display_name = "Teecryptor — keys access SA"
  description  = "Impersonated by the attested TDX workload via WIF; reads the partner FHE-priv shares + public material."
  depends_on   = [google_project_service.apis]
}

# --- Workload Identity Federation: attestation JWT -> SA impersonation ---

resource "google_iam_workload_identity_pool" "cs" {
  workload_identity_pool_id = "teecryptor-cs-pool"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "cs" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.cs.workload_identity_pool_id
  workload_identity_pool_provider_id = "cs-provider"

  oidc {
    issuer_uri = "https://confidentialcomputing.googleapis.com/"
    # The workload requests exactly this audience from the CS launcher, and STS
    # validates the token's `aud` against it. Matches the wip_audience output.
    allowed_audiences = ["//iam.googleapis.com/${google_iam_workload_identity_pool.cs.name}/providers/cs-provider"]
  }

  # google.subject is required; attribute.image_digest is consumed by the
  # principalSet binding below. The CEL itself reads the rich nested claims
  # (support_attributes, gce.project_id) directly off `assertion.*`.
  attribute_mapping = {
    "google.subject"         = "assertion.sub"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }

  # The trust boundary. Every guard matters (see ../SECURITY-OVERVIEW.md).
  # gce.project_id is pinned to the COMPUTE project — a VM in any other project
  # is rejected even if it somehow ran our exact image.
  attribute_condition = <<-CEL
    assertion.swname == "CONFIDENTIAL_SPACE"
    && assertion.hwmodel == "GCP_INTEL_TDX"
    && assertion.dbgstat == "disabled-since-boot"
    && ("," + assertion.submods.confidential_space.support_attributes.join(",") + ",").contains(",STABLE,")
    && assertion.submods.container.image_digest == "${var.image_digest}"
    && assertion.submods.gce.project_id == "${var.compute_project_id}"
  CEL
}

# Second, independent digest pin: only attestations whose mapped image_digest
# equals var.image_digest may impersonate the keys-access SA. Independent of the
# provider CEL above — even a second, weaker provider added to this pool would
# still fail this binding unless its JWT carried the same image_digest.
resource "google_service_account_iam_member" "wif_impersonation" {
  service_account_id = google_service_account.keys_access.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.cs.name}/attribute.image_digest/${var.image_digest}"
}

# --- Outputs (handed to the compute side) -------------------------------
output "wip_audience" {
  description = "Audience the TEE workload requests from the CS launcher; also what STS validates. Pass to compute as var.wip_audience."
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool.cs.name}/providers/cs-provider"
}

output "keys_access_sa_email" {
  description = "Email of the SA the workload impersonates to read Secret Manager. Pass to compute as var.keys_access_sa_email."
  value       = google_service_account.keys_access.email
}

output "keys_project_id" {
  value = var.keys_project_id
}
