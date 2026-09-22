# Teecryptor

Teecryptor is a TDX-attested TFHE decryption service. It runs inside a single
GCP Confidential Space (Intel TDX) VM. It decrypts cofhe FHE ciphertexts with an
FHE key that it reconstructs at boot from per-partner Shamir shares. Each
partner gates its own share with an image-digest attestation (attest → STS
federation). Clients reach it over an HTTP decrypt and seal API.

The FHE secret key and the signer key only ever materialize inside the attested
image.

Each production build on `main` emits a keyless SLSA build provenance attestation,
served by GitHub on an API that needs no account. Before a partner pins a new
digest it proves, against that public record, that our workflow built the digest
from the commit we published beside it. The runtime gate is unchanged: each
partner's CEL still pins the digest only.

## Documentation

| File | Job |
|---|---|
| [SECURITY-OVERVIEW.md](./SECURITY-OVERVIEW.md) | the trust model: the security claim, the boundary, both fail-closed gates, and what stays out of scope |
| [docs/INTEGRATION.md](./docs/INTEGRATION.md) | integration reference: endpoints, request/response wire shapes, EIP-712 signing, ciphertext wire format, error codes |
| [docs/SANDBOX.md](./docs/SANDBOX.md) | local development, three tiers, and the sandbox attested flow |
| [SECURITY.md](./SECURITY.md) | how to report a vulnerability |

The deploy runbook and the cofhe wire/param/ABI compatibility catalogue live in the gitops repo.

## Interface

Teecryptor exposes synchronous v1 and v2 HTTP endpoints for decrypt and seal,
plus `GET /signerAddress` and `GET /healthz`. The wire format matches cofhe, so a
cofhe client reaches it without change.

The endpoints, request and response shapes, the `x-signature-v-format` header, the
EIP-712 signing payload, and every error code are in
[docs/INTEGRATION.md](./docs/INTEGRATION.md).

## The two gates

Teecryptor runs two independent fail-closed gates before it decrypts or seals.
Both switches are baked into the image per environment, so they form part of the
attested digest rather than a launch flag.

The **ACL gate** asks the on-chain cofhe TaskManager whether the caller may read
the handle. The **commitment gate** checks that the FHE engine posted an on-chain
commitment for the handle and that the ciphertext bytes ct-server served hash to
it.

[SECURITY-OVERVIEW.md](./SECURITY-OVERVIEW.md) has both gates in full: what is
baked, what an operator can still supply, the error and retry semantics, and the
cross-chain assumptions the ACL gate inherits.

## cofhe coupling

Teecryptor stays byte-compatible with cofhe's wire format, FHE params, EIP-712
ACPs, NaCl sealed output, and Solidity ABIs. **Every coupling is catalogued in
the compatibility doc in the gitops repo.** Read that doc before you bump
any dependency it lists, and add an entry whenever you introduce a new coupling.

Permissions use **ACP**, cofhe's "Permit V3". See
[docs/INTEGRATION.md](./docs/INTEGRATION.md).

## Status

Phase 1 MVP. [SECURITY-OVERVIEW.md](./SECURITY-OVERVIEW.md) states the security
claim this phase makes and lists what stays out of scope.

## License

Licensed under the Fhenix Non-Commercial Software License. See
[LICENSE](./LICENSE) for the terms and [NOTICE](./NOTICE) for
third-party licenses.
