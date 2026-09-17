# AGENTS.md

Teecryptor is a TDX-attested service that decrypts CoFHE ciphertexts. The FHE
key only ever materializes inside the attested enclave.

Start here:

- `README.md` — what it is, the HTTP endpoints, the doc map.
- `SECURITY-OVERVIEW.md` — the trust model and threat boundary.
- `docs/INTEGRATION.md` — the integration reference: endpoints, wire shapes, EIP-712 signing, ciphertext wire format, error codes.
- `docs/SANDBOX.md` — run it locally.

Build and test: `cargo test`. A `mock` feature runs the full decrypt path on a
laptop; the TDX attestation path needs Confidential Space. See `docs/SANDBOX.md`.

Writing docs and comments: active voice, present tense, one idea per sentence,
simple words. State facts and their mitigations, not warnings. Never claim an
audit that has not happened.
