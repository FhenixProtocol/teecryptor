# Teecryptor integration reference

Teecryptor decrypts a cofhe ciphertext to a value, or seals that value to a
recipient's key. You send a ciphertext handle and an access permission. You
receive the plaintext, or a sealed box, and a signature the chain can verify.

Write your client in any language. This guide gives the model and points to the
code for the exact shapes. The code is the source of truth; read it there rather
than a copy that can drift.

## Endpoints

Routes are wired in `src/main.rs`; the handlers and every request and response
type are in `src/http.rs`.

- `POST /decrypt`, `POST /sealoutput` — v1, synchronous.
- `POST /v2/decrypt`, `POST /v2/sealoutput` — v2, synchronous. A matching
  `GET /v2/decrypt/{id}` (and the seal equivalent) returns the same result.
- `GET /signerAddress` — the address that signs responses.
- `GET /healthz` — readiness.

The request body and each response shape are the Rust types in `src/http.rs`.

## Permissions (ACP)

A request carries an **ACP** — cofhe's Permit V3 access object. You sign it with
EIP-712 `signTypedData`. Two facts a client must get right:

- Sign against the **ACL contract**, not the TaskManager.
- The `scope` field selects what the permission covers: everything, one
  contract, or specific handles.

The ACP object, the EIP-712 domain, and the typed-data types are in
`src/permit.rs`.

## Ciphertext

You reference a ciphertext by **handle**, not by sending its bytes. Teecryptor
fetches the stored **compressed** ciphertext from cofhe's ct-server
(`POST /GetStoredCt`) and decrypts that form. The fetch is in `src/ct_source.rs`;
the accepted form and the type mapping are in `src/decrypt.rs`.

## Response signature

A successful response includes a signature over the result, which a contract
verifies on-chain. The exact bytes that are signed are built in `src/signing/`
(`message_builder.rs` and `service.rs`).

## Sealed output

`/sealoutput` returns the value inside a NaCl `crypto_box`, sealed to the
32-byte X25519 public key you supply. The box layout and encoding are in
`src/seal.rs`.

## Errors

A failure returns a status code and a short reason. Some are retryable and some
are terminal. The codes and how they map to HTTP are in `src/error.rs` and
`src/http.rs`.
