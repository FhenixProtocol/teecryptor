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

# NOTE: Cosign image_signatures CEL pinning stays deferred, and the build
# provenance added in 2026-09 does NOT move it any closer. Confidential Space's
# `attribute.image_signatures` matches a Cosign PUBLIC-KEY fingerprint; our build
# is keyless, so it produces no fingerprint that this attribute could ever match.
# Wiring it would mean introducing a signing key we deliberately do not have.
#
# The digest pin (CEL + principalSet) remains the runtime control. Where the
# image came from is proven at PIN time instead, by the partner, against the
# public attestation — see SECURITY-OVERVIEW.md. That check is off-CEL by
# necessity: the attestation token carries no repository or commit claim.
