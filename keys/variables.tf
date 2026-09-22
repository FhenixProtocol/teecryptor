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

# NOTE: signature-based CEL pinning is NOT planned. Confidential Space's
# `attribute.image_signatures` matches a cosign public-KEY fingerprint. Our build
# is keyless, so it has no key and produces no such fingerprint. The digest pin
# below stays the runtime control; where an image came from is proven at pin time
# by the partner. See SECURITY-OVERVIEW.md.
