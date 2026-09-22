# Security overview

> **Phase 1 MVP.** This document states what Teecryptor protects and what it
> leaves to other layers.

## The single security claim

> **The FHE secret key only ever materializes inside the attested image.**

Everything below exists to make that claim defensible. It is the only property
the TEE itself guarantees. It does not cover caller authenticity, end-to-end
result integrity, or ciphertext confidentiality. Ciphertexts are public by
construction.

## Trust boundary

**Inside the TEE (TDX-encrypted memory):** the Teecryptor process and the
deserialized `tfhe::ClientKey` for zone 0. Short-lived GCP credentials exist
during boot only — per-partner attestation JWTs, federated STS tokens, and a
compute-SA metadata token for the public GCS read. Teecryptor drops all of them
before it serves traffic. It impersonates no service account.

**Outside the TEE:** ct-server and its Postgres, all callers, the network, and
every operator. The stored ciphertexts are public FHE ciphertexts, so they leak
nothing without the key.

## How the key is gated

The key never exists whole at rest. It is Shamir-split, one share per **partner
project's** Secret Manager, with the signer key bundled inside the same secret.
To read a partner's share, the VM presents a Confidential Space attestation JWT
to **that partner's** reader Workload Identity Pool. The exchange is attest →
STS federation, with no service-account impersonation anywhere. Each partner's
CEL condition pins:

- `swname == CONFIDENTIAL_SPACE`
- `hwmodel == GCP_INTEL_TDX`
- `dbgstat == disabled-since-boot` (rejects debug images)
- `support_attributes` contains `STABLE`
- `submods.container.image_digest == <pinned digest>`
- `submods.gce.project_id == <compute project>`

Every partner pins the image digest **twice**: once in the CEL, and once in the
digest-scoped `secretAccessor` grant on that partner's share secret. This is
defense in depth, and each partner enforces it independently. Each partner's STS
rejects a rogue image, a non-TDX VM, or a debug VM, so none of them reaches any
share.

The CEL proves *which* image runs. It cannot prove *where that image came from*,
because the attestation token carries no repository, workflow or commit claim. A
partner therefore checks the origin **before** it pins. The build emits a keyless
SLSA build provenance attestation for the amd64 digest, and the certificate binds
that digest to this repository, this workflow, the ref and the commit. The partner
runs `gh attestation verify` on its own machine and asserts the exact digest, the
exact commit, `refs/heads/main` and this workflow file. A non-zero exit means it
does not pin.

The attestation is public: GitHub serves the bundle over an API that needs no
account, and it is also in the public Rekor log. Verification needs no Fhenix
credential and no GitHub login, so the partner trusts the public record rather
than us.

Resolving the image manifest does use the Artifact Registry repository's
`allUsers` reader grant. **That public read is deliberate and the check depends on
it.**

An earlier model held the whole key in a single Fhenix-owned custodian project;
the `keys/` Terraform module is what remains of it, and the reader reads none of
its outputs.

The key source — the partner set, the WIF audiences, and the public bucket and
object — is baked into the binary per environment and selected by `ENV`
(fail-closed). The keygen-origin digest allowlist was removed. Two controls
re-anchor trust in its place: the baked source, and on-chain verification of the
decrypt-signer signature. GCP service endpoint URLs are compile-time constants
rather than environment values, so an operator with `setMetadata` cannot
redirect the STS exchange.

## What TDX does and does not protect against

TDX protects against:

- the cloud operator, hypervisor, or host kernel reading guest memory
- cold-boot and DMA attacks
- other tenants on the same socket

TDX does not protect against:

- side channels (timing and cache)
- bugs in our own code
- root inside the guest
- physical attacks on the CPU package
- compromise of Intel's signing infrastructure
- availability (the VMM can kill the VM)
- rollback or replay of ciphertexts — Phase 1 keeps no monotonic counter

## Result signing

Every `/decrypt` and `/sealoutput` response carries a secp256k1 signature over
the dispatcher-compatible byte layout. Any relying party can therefore verify
that the answer came from this enclave. The signer key is bundled inside the
reconstructed FHE-priv secret, so there is no separate fetch and no
`SIGNER_SECRET` toggle. It loads at boot through the same per-partner
attestation chain as the FHE key, and never leaves the TEE.

The on-chain signature check is the end-to-end trust anchor. A key served from
anywhere but the blessed baked source yields signatures that the host chain
rejects. `GET /signerAddress` returns the signing public key as an Ethereum
address. See the compatibility doc §8 in the gitops repo for the exact
preimage construction and the cross-check test.

## Out of scope for Phase 1

Four items stay out of scope in this phase:

- **mTLS to ct-server.** Without it, an in-VPC attacker can substitute one
  ciphertext for another. Ciphertext confidentiality is not at risk. The
  mitigation is the commitment gate: it refuses any ciphertext whose bytes do
  not hash to the handle's on-chain commitment.
- **Key rotation.**
- **High availability.**
- **Multiple security zones.**

EIP-712 ACPs, the on-chain ACL gate (including public decryption), NaCl sealed
output, and result signing **are** implemented. They moved in from the original
Phase-1 out-of-scope list. See "Access control" and "Result signing" above.

## Access control (the on-chain ACL gate)

ACL enforcement is a baked per-environment **master switch**. It is **on by
default and fail-closed**. Turning it off is a rebuild-time policy decision, so
the setting is part of the attested digest rather than a launch flag. With it on,
the process refuses to boot until the operator configures at least one chain. You
cannot end up serving open decryption by weakening launch config. The baked
policy and the split between baked constants and operator-supplied values are
owned by `src/env_policy.rs`.

The operator supplies only the API-keyed RPC URLs. The **TaskManager contract
address is baked** — one attested constant, deterministic on every chain and
environment — so an operator cannot point the gate at a TaskManager they control.

- **Off**: Teecryptor **never** calls the ACL contract. It decrypts whatever
  ct-server returns, gated only by the firewall CIDR. Use this only where the ACL
  contract is unreachable, because it may not exist in that deployment. Never
  reaching out is deliberate, not a fallback.
- **On**: every decrypt and seal call consults the on-chain TaskManager on the
  caller-supplied `host_chain_id`. A request that carries an ACP takes the
  permit path; a request without one takes the **public-decrypt** path, which
  allows only handles the issuer marked publicly decryptable. Either path denies
  fail-closed. The contract calls are in `src/permit.rs`; the deny status codes
  are in `src/http.rs`.

When the switch is **on** and `PERMIT_CHAINS_JSON` configures more than one
chain, the caller picks which chain's ACL contract Teecryptor consults, through
`host_chain_id`. Teecryptor inherits two assumptions from that design and does
not enforce them. The operator maintains both:

1. **ACL grants are consistent across chains for the same ciphertext handle.**
   Suppose chain A's ACL grants `issuer X` access to `handle H` and chain B's
   does not. A caller can then submit `host_chain_id: A` and decrypt `H`, even
   though chain B's policy denies it. The mitigation is to configure only chains
   whose ACL contracts share grants for the handles you care about. cofhe's
   threshold dispatcher carries the same property and the same mitigation.

2. **The TaskManager ABI is the same on every configured chain.** Teecryptor's
   `sol!` declarations of `ITaskManager::isAllowedWithPermission` and
   `isPubliclyAllowed` are the single interface. If cofhe forks either function
   signature on one chain but not another, response decode on the forked chain
   becomes undefined. cofhe documents the same invariant: *"we use the same ABI
   for all chains, the interface must be kept"*.

If either invariant breaks operationally, restrict the deployment to a single
chain — one entry in `PERMIT_CHAINS_JSON`.

## Commitment gate (the on-chain commitment check)

The commitment gate is a second, independent baked master switch. The commitment
version and the registry address are baked alongside it, so all three form part
of the attested image and no operator can set them. The gate is **on by default
and fail-closed**. The baked policy and the operator-supplied RPC URL are owned
by `src/env_policy.rs`.

Before it decrypts or seals, Teecryptor verifies that the FHE engine posted an
on-chain **commitment** for the handle in cofhe's `CommitmentRegistry`. A missing
commitment means the ciphertext was never legitimately produced and committed, so
Teecryptor refuses to decrypt it. With the gate baked on, the process refuses to
boot until the one operator-supplied piece — the registry RPC URL — is set. You
cannot ship a decryptor that skips the check by weakening launch config, and no
one can drop the baked address to silence it.

- **Off**: Teecryptor never consults the registry.
- **On**: Teecryptor reads the commitment for the handle from the registry
  chain. The ciphertext bytes ct-server serves must then **hash to exactly that
  commitment**. The handle binds the security zone, so the zone is not folded
  into the hash. This binds the decrypt to the ciphertext the engine committed
  to. Teecryptor refuses a ct-server that serves different bytes for a
  legitimately committed handle, and the refusal is terminal. The registry is a
  **single chain-agnostic contract on its own registry chain**, keyed by version
  and handle only. There is therefore one endpoint, one address, and one version,
  and the baked commitment version must equal the engine's for the ciphertexts
  being decrypted. The commitment and ACL checks run **concurrently**, and a
  terminal ACP denial takes precedence over a retryable missing commitment. The
  registry call, the hash formula, and the boot probe are in `src/commitment.rs`.
- **Warn-only**: the gate still runs and logs every failure, but it **allows the
  decrypt** instead of blocking. Use it to phase in enforcement before it bites,
  then rebuild to enforce. It relaxes the integrity guarantee, so it is
  policy-relevant. See the trust note below.

A missing commitment is retryable, the same class as "ct not ready", so a
commitment still propagating resolves on the client's normal re-submit. The
retry response carries a machine-readable reason so clients can tell the causes
apart. Teecryptor caches positive results permanently, because commitments are
write-once on-chain. It never caches absent results, deliberately: attacker-chosen
handles therefore cannot evict warm positive entries, and a landing commitment is
visible immediately. The status codes and retry header are in `src/http.rs`.

At boot, with the gate on, Teecryptor probes the registry once for the configured
version. It **refuses to boot** on a wrong RPC or address, and warns loudly when
the configured version is not active. Both would otherwise surface only as
runtime decrypt failures.

Trust note: the gate trusts the configured registry RPC's answers. It uses a
plain `eth_call` and verifies no proof. The gate **policy** — whether commitment
is on, the registry address, the version, and warn-only mode — is **baked into
the attested image** and forms part of the measured digest that the partner CEL
pins. The pinned digest therefore verifies it, not an inspection of launch env.
The only operator-supplied piece is the registry RPC URL, an API-keyed launch
value that selects which registry endpoint answers. Anyone verifying attestation
quotes should treat it as policy-relevant. The permit gate's switch is likewise
baked, while the chains map stays an operator value.

Alerting contract: every commitment-gate failure logs exactly one line carrying a
stable gate label and a reason field. Key your log-based metrics and alerts off
that pair; the values are append-only and owned by `src/commitment.rs`.

## cofhe compatibility invariants

Teecryptor stays byte-compatible with upstream cofhe's wire formats, FHE params,
EIP-712 ACPs, NaCl sealed output, and Solidity ABIs. **Every coupling is
catalogued in the compatibility doc in the gitops repo**, with the failure
mode of silent drift documented per entry. Read that doc before you bump any
pinned dependency, and add an entry whenever you introduce a new coupling.

## Operational invariants

- `tee-restart-policy = Never` — a boot or security failure stays down for human
  attention. Auto-retry would mask an attack.
- Every outbound boot call is timeout-bounded, so nothing hangs.
- Teecryptor rejects the wide and signed integer types it does not support. The
  supported set and the width cap are in `src/decrypt.rs`.
- The critical deploy test: rebuild the image with a one-byte change and boot it
  **without** re-applying Terraform. STS must reject it, because the CEL still
  pins the old digest, and Secret Manager is never reached. If the rogue image
  reads the key, the IAM configuration is wrong. Stop and fix it.
