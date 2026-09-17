variable "compute_project_id" {
  type        = string
  description = "GCP project where the TDX VM runs (the 'workload owner' side). Deploy target: teecryptor-tdx."
}

variable "region" {
  type    = string
  default = "europe-west4"
}

variable "zone" {
  type    = string
  default = "europe-west4-b"
}

# --- Multi-partner Shamir read of the FHE-priv secret ------------------
variable "env" {
  type        = string
  description = "Baked-environment selector — the reader resolves partners/bucket/object from its compiled-in ENVIRONMENTS map and fails closed on anything else."
  validation {
    # Every value here must have a triplet in cofhe-keys' ENVIRONMENTS map, or
    # the reader fails closed at boot. Adding one is a rebuild by design.
    condition     = contains(["staging", "testnet", "mainnet"], var.env)
    error_message = "env must be one of the blessed environments: staging | testnet | mainnet."
  }
}

# --- Image (two-phase deploy: image first, then apply pins the digest) ---
variable "image_digest" {
  type        = string
  description = "Pinned container image digest (sha256:...). Must match the digest pinned in each partner's reader CEL (keygen repo attested_readers)."
}

variable "image_reference" {
  type        = string
  description = "Full AR image reference WITHOUT digest, e.g. europe-west4-docker.pkg.dev/teecryptor-tdx/teecryptor/teecryptor"
}

# --- Runtime config -----------------------------------------------------
variable "ct_source_url" {
  type        = string
  description = "Base URL of the ct-server /GetCT source the VM calls, e.g. http://ct-stub:9450. For the first-boot real-decrypt test this is the corpus-serving stub in this VPC."
}

variable "caller_cidr" {
  type        = string
  description = "Source CIDR allowed to reach :8080 (the internal services that call /decrypt). For an IAP-tunnel smoke test, include 35.235.240.0/20."
}

variable "machine_type" {
  type        = string
  default     = "c3-standard-4"
  description = "Decrypt-only loads just the ~40 KiB ClientKey (no ServerKey), so 4 vCPU/16 GB is ample; validate RSS under load before prod."
}

variable "cs_image" {
  type        = string
  default     = "projects/confidential-space-images/global/images/family/confidential-space"
  description = "Confidential Space image (STABLE family)."
}

variable "network" {
  type    = string
  default = "default"
}

variable "subnetwork" {
  type        = string
  default     = ""
  description = "Subnetwork (name or self-link) for the VM NIC. Required when `network` is a custom-mode VPC (e.g. a shared GKE VPC); the subnet must be in the VM's region. Empty = let GCP use the auto subnet for `network`."
}

# --- GitHub Actions WIF (CI image push) ---------------------------------
variable "github_repository" {
  type        = string
  default     = "FhenixProtocol/teecryptor"
  description = "GitHub repo (org/name) allowed to push images via WIF."
}

variable "github_workflow_ref" {
  type        = string
  default     = "FhenixProtocol/teecryptor/.github/workflows/build-teecryptor.yml@refs/heads/main"
  description = "Exact workflow ref allowed to push images: <org>/<repo>/.github/workflows/<wf>.yml@refs/heads/<branch>."
}

# --- Permit + commitment gate ENDPOINTS ---
# The gate switches, Shamir threshold, commitment version, registry address, and
# warn/enforce mode are baked per-env into the image (see the reader / env policy).
# Only the API-keyed RPC endpoints remain operator-supplied — they must not be
# baked into a publicly-pullable image.
variable "permit_chains_json" {
  type        = string
  default     = "{}"
  description = "JSON map of host_chain_id -> { rpc_url, task_manager } the VM uses to reach each chain's TaskManager. \"{}\" = no verifier installed. Must be non-empty for any env whose baked policy enables the permit gate (the VM refuses to boot otherwise). Example: {\"420105\":{\"rpc_url\":\"https://hostchain-...\",\"task_manager\":\"0x...\"}}."
}

variable "commitment_registry_rpc_url" {
  type        = string
  default     = ""
  description = "JSON-RPC endpoint of the registry chain hosting CommitmentRegistry. \"\" = no verifier installed. Must be non-empty for any env whose baked policy enables the commitment gate (the VM refuses to boot otherwise). The registry address + version are baked into the image."
}

# Commitment tuning knobs — empty string => env var NOT set on the VM, so the
# binary's built-in default applies (COMMITMENT_TIMEOUT_MS => 5000,
# COMMITMENT_CACHE_SIZE => 100000, COMMITMENT_CACHE_TTL_SECS => 3600).
variable "commitment_timeout_ms" {
  type        = string
  default     = ""
  description = "Per-request timeout (ms) for the CommitmentRegistry eth_call. Empty => 5000. The binary enforces a 50ms floor."
}

variable "commitment_cache_size" {
  type        = string
  default     = ""
  description = "Max entries in the commitment result cache. Empty => 100000."
}

variable "commitment_cache_ttl_secs" {
  type        = string
  default     = ""
  description = "How long a cached positive commitment lookup stays valid (seconds). Empty => 3600. Bounds how long a stale hash can outlive a wiped-and-redeployed chain + registry; lower it on environments that get reset often."
}

# --- Performance: CPU gate + overload backstop --------------------------
# Empty string => the env var is NOT set on the VM, so the binary's built-in
# default applies. Set a value only to override (e.g. to sweep the throughput
# knee without rebuilding the image).
variable "decrypt_concurrency" {
  type        = string
  default     = ""
  description = "Max concurrent tfhe decrypts (wait-only CPU gate), wired as DECRYPT_CONCURRENCY. Empty => auto-detect cores (4 on c3-standard-4). Pin a number to override."
}

variable "max_inflight" {
  type        = string
  default     = ""
  description = "Max in-flight requests before the 204 overload backstop, wired as MAX_INFLIGHT. Empty => binary default (1000)."
}

variable "mig_target_size" {
  type        = number
  default     = 1
  description = "Number of instances the MIG maintains. Phase 1 runs a single instance; increase to scale horizontally."
}

# --- Networking (optional VPC creation) ------------------------------------
variable "create_network" {
  type        = bool
  default     = false
  description = "When true, create a dedicated VPC and subnet and ignore var.network / var.subnetwork."
}

variable "vpc_name" {
  type        = string
  default     = "teecryptor-vpc"
  description = "Name of the VPC to create (used when create_network = true)."
}

variable "subnet_name" {
  type        = string
  default     = "teecryptor-subnet"
  description = "Name of the subnet to create (used when create_network = true)."
}

variable "subnet_cidr" {
  type        = string
  default     = "10.0.0.0/24"
  description = "Primary CIDR for the created subnet (used when create_network = true)."
}

# --- Load balancer ----------------------------------------------------------
# Exactly one of ssl_certificate_id, ssl_certificate_map, ssl_domains, or wildcard_domain must be set.
variable "ssl_certificate_id" {
  type        = string
  default     = ""
  description = "Self-link of an existing classic Compute SSL certificate (google_compute_ssl_certificate). Mutually exclusive with the other SSL options."
}

variable "ssl_certificate_map" {
  type        = string
  default     = ""
  description = "Name of an existing Certificate Manager certificate map in this project, managed by a separate Terraform flow. The proxy will reference it via certificate_map. Mutually exclusive with the other SSL options."
}

variable "ssl_domains" {
  type        = list(string)
  default     = []
  description = "Domain names for a new Google-managed SSL certificate (e.g. [\"api.example.com\"]). Used only when ssl_certificate_id and wildcard_domain are both empty. Mutually exclusive with the other two."
}

variable "wildcard_domain" {
  type        = string
  default     = ""
  description = "Base domain for a Google-managed wildcard certificate via Certificate Manager (e.g. \"example.com\" issues a cert for *.example.com). Requires adding a CNAME record output by dns_auth_cname_* to your DNS. Mutually exclusive with ssl_certificate_id and ssl_domains."
}

variable "armor_rules_file" {
  type        = string
  default     = ""
  description = "Path to a JSON file containing Cloud Armor rules to add to the security policy. When empty, only the default allow-all rule applies. See armor_rules.json.example for the expected schema."
}

variable "armor_adaptive_protection" {
  type        = bool
  default     = true
  description = "Enable Cloud Armor Adaptive Protection. It learns the normal traffic pattern and reports layer 7 DDoS attacks in Cloud Logging, with a suggested mitigation rule."
}

variable "armor_rate_limit_enabled" {
  type        = bool
  default     = true
  description = "Add a per-source-IP rate limit rule to the security policy. A client above the threshold receives HTTP 429 for the ban duration."
}

variable "armor_rate_limit_threshold_count" {
  type        = number
  default     = 90
  description = "Requests one source IP may send per armor_rate_limit_interval_sec before Cloud Armor throttles it."
}

variable "armor_rate_limit_ban_threshold_count" {
  type        = number
  default     = 180
  description = "Requests one source IP may send per armor_rate_limit_interval_sec before Cloud Armor bans it for armor_rate_limit_ban_duration_sec."

  validation {
    condition     = var.armor_rate_limit_ban_threshold_count >= var.armor_rate_limit_threshold_count
    error_message = "The ban threshold must be greater than or equal to the throttle threshold."
  }
}

variable "armor_rate_limit_interval_sec" {
  type        = number
  default     = 60
  description = "Length of the sliding window for the rate limit counters, in seconds. Cloud Armor accepts 60, 120, 180, 300, 600, 1200, 1800, 2700 or 3600."

  validation {
    condition     = contains([60, 120, 180, 300, 600, 1200, 1800, 2700, 3600], var.armor_rate_limit_interval_sec)
    error_message = "Cloud Armor accepts only 60, 120, 180, 300, 600, 1200, 1800, 2700 or 3600 seconds."
  }
}

variable "armor_rate_limit_ban_duration_sec" {
  type        = number
  default     = 300
  description = "Time a banned source IP stays blocked, in seconds. It also sets the expiry of an auto-deployed Adaptive Protection rule."
}
