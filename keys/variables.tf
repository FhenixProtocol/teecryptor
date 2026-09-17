variable "keys_project_id" {
  type        = string
  description = "GCP project that holds the FHE key, the WIP/CEL, and the keys-access SA (the 'custodian' side). Deploy target: teecryptor-sa-1."
}

variable "compute_project_id" {
  type        = string
  description = "GCP project where the TDX VM runs (teecryptor-tdx). The CEL pins this — only attestations from VMs in this project are accepted, so a VM in any other project is rejected by STS."
}

variable "image_digest" {
  type        = string
  description = "Pinned container image digest (sha256:...). Produced by the compute side (CI build) and handed here. Pinned in BOTH the WIP CEL and the principalSet impersonation binding (defense in depth)."
}

# NOTE: Cosign image_signatures CEL pinning is deferred (see SECURITY-OVERVIEW.md
# and the original variables.tf note). The digest pin (CEL + principalSet) is the
# primary control for Phase 1. When wiring signature pinning, add a
# `cosign_pubkey_fingerprint` var here + an `attribute.image_signatures` mapping
# + a `contains(",ECDSA_P256_SHA256:<fp>,")` clause in the CEL below, and set
# `tee-signed-image-repos` + the cosign recovery annotations on the compute side.
