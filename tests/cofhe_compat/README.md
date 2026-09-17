# cofhe wire-format compatibility corpus

This corpus is the regression contract between Teecryptor's `decrypt` and
cofhe's real wire format. Every file here was produced **by cofhe itself** using
the committed dev zone-0 keys; `tests/cofhe_compat.rs` decrypts each one and
asserts the known plaintext. **If that test ever fails, stop and investigate.**

> `dev_zone0_testkey.bin` is a **test key, not a production key.** It is cofhe's
> public dev zone-0 `ClientKey`, used here only to decrypt the fixture corpus in
> CI. Deployed Teecryptor never uses it: production reconstructs the FHE-priv key
> inside the TDX enclave from the partners' Shamir shares (see `SECURITY-OVERVIEW.md`).

## Files

- `dev_zone0_testkey.bin` — copy of `cofhe:deployments/keys/dev/0/decryption_key`,
  the committed dev zone-0 `tfhe::ClientKey` (`safe_serialize`d, 40,313 B).
  - Upstream SHA-256 (verify before regenerating): `02974d882b25cb4b40f52ce658ae21ccbca334f8265b55a62258ded97e73f6ac`
- `manifest.json` — one record per fixture, with its name, type, wire flags, zone,
  and expected plaintext. The record shape is the file itself; `tests/cofhe_compat.rs`
  reads it.
- `<name>.ct` — `safe_serialize`d ciphertexts the compat test decrypts. These
  hold the **plain, pre-expanded** form (`compact = false`, `gzipped = false`).
  The active runtime path instead fetches the stored **compressed** form from
  ct-server (`/GetStoredCt`); `/GetCT` was the earlier plain endpoint.

## Regenerating

Generator lives in cofhe, **not** here (it depends on cofhe-internal helpers
and the cofhe `CompactPublicKey` + `CompressedServerKey`; both are in cofhe's
`deployments/keys/dev/0/`):

- Path in cofhe: `tools/ct-export/`

`$COFHE` below is your cofhe checkout.

```bash
# in cofhe (standalone crate, run from the tool dir)
cd $COFHE/tools/ct-export
cargo run --release -- --keys ../../deployments/keys/dev/0 --out ../../ct-corpus
# Output: cofhe/ct-corpus/{manifest.json, *.ct}

# back in teecryptor
cp $COFHE/ct-corpus/* \
   tests/cofhe_compat/
cp $COFHE/deployments/keys/dev/0/decryption_key \
   tests/cofhe_compat/dev_zone0_testkey.bin

cargo test --test cofhe_compat
```

## Why we commit binaries

The corpus is ~hundreds of KB to a few MB; small enough that committing it is
cheaper than depending on cofhe (private repo) at test time. Teecryptor stays
OSS-clean: no cofhe dep, no cofhe runtime path. The corpus is treated like any
other test fixture — regenerated when cofhe's key or `EncryptionType` set
changes, otherwise stable.

## Why this matters

The decrypt round-trip tests in `src/decrypt.rs` use keys *we* generate with
default params. They prove our decrypt is correct against *itself*. They do
**not** prove we can decrypt real cofhe output, because cofhe uses non-default
crypto params. For **decrypt-only** this does not matter, because the params
travel inside the `safe_serialize`d `ClientKey`. If it ever did matter, this test
is what would catch it. cofhe's exact params live with the generator in cofhe's
`tools/ct-export`.
