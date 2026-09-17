# Local development & sandbox

Only one thing genuinely requires Confidential Space: the **attestation
handshake**, because `/run/container_launcher/teeserver.sock` exists only inside
a CS VM. Everything else runs on a laptop. There are three tiers.

## 1. Full end-to-end decrypt — `cargo test` (recommended)

The `http` integration tests already exercise the whole path on a laptop. They
use a real `tfhe::ClientKey`, a real ciphertext, a mock `/GetCT` through
wiremock, the axum server bound on a loopback port, and a `POST /decrypt` that
returns the correct plaintext. This is the authoritative local proof that
decryption works.

```bash
cargo test
```

> Note: Teecryptor ships no `mock-gce-metadata` server, unlike zee-k-verifier.
> That workload always uses ADC, so it fakes the metadata endpoint. Teecryptor
> instead has a `mock` **feature** that skips the GCP chain entirely. This is
> simpler, and the integration tests cover the real decrypt path.

## 2. Boot the service locally — `--features mock`

This boots the binary with a throwaway generated `ClientKey` and skips
attestation, STS, and Secret Manager. Use it to smoke-test `/healthz` and the
HTTP surface. It does not decrypt real cofhe ciphertexts, because the throwaway
key does not match them. For a successful decrypt, point it at a `/GetCT` whose
ciphertexts were produced with the same key.

> ACL and commitment enforcement both default to **on** and fail closed. A local
> boot therefore needs `REQUIRE_PERMIT=false` and
> `ENABLE_COMMITMENT_VERIFICATION=false`, because the sandbox has no chain RPC.
> Without them, `Config::from_env` bails on the missing `PERMIT_CHAINS_JSON` and
> `COMMITMENT_REGISTRY_*` values. The crate also has a second binary, `genkey`,
> so `cargo run` needs `--bin teecryptor`.

```bash
REQUIRE_PERMIT=false ENABLE_COMMITMENT_VERIFICATION=false CT_SOURCE_URL=http://localhost:9450 cargo run --bin teecryptor --features mock
curl -s localhost:8080/healthz        # 200 once booted
```

`docker-compose.yml` runs this same mock-feature image for container smoke
testing of `/healthz`. It includes no key-matched ct-source.

## 2b. Boot as cofhe's dev decryptor — `MOCK_KEYS_DIR`

`--features mock` has exactly two modes, and `MOCK_KEYS_DIR` picks between them:

| `MOCK_KEYS_DIR` | ClientKey | Signer | Use |
|---|---|---|---|
| unset | fresh throwaway | throwaway | self-contained smoke tests (`/healthz`, HTTP errors) |
| set | `<dir>/ck.binfile` | `<dir>/dispatcher_signer_pk` | decrypt **real** cofhe ciphertexts, signing as the identity the local chain trusts |

The two files load as a pair on purpose. Picking them independently produces a
Teecryptor that decrypts real ciphertexts but signs with an identity no chain
trusts, or the reverse. That half-state looks like it works until someone checks
a signature. Both files are required when the directory is set, and a partial
directory fails at boot rather than falling back to a throwaway.

`<dir>` is cofhe's committed dev keys directory — the same one its dispatcher and
ct-server mount at `/app/keys`. The `ClientKey` bytes go to `KeyStore::load`, the
same code path production uses after it reconstructs the key from the per-partner
Shamir shares. `$COFHE` below is your cofhe checkout.

```bash
# Native cargo:
REQUIRE_PERMIT=false \
ENABLE_COMMITMENT_VERIFICATION=false \
MOCK_KEYS_DIR=$COFHE/deployments/keys/dev \
CT_SOURCE_URL=http://localhost:9450 \
cargo run --bin teecryptor --features mock

# Docker (build the mock image first):
docker build --build-arg FEATURES=mock -t teecryptor:local .
docker run -d --name teecryptor-local \
  -p 18080:8080 \
  -v $COFHE/deployments/keys/dev:/keys:ro \
  -e MOCK_KEYS_DIR=/keys \
  -e CT_SOURCE_URL=http://host.docker.internal:9450 \
  -e REQUIRE_PERMIT=false \
  -e ENABLE_COMMITMENT_VERIFICATION=false \
  -e BIND_ADDR=0.0.0.0:8080 -e RUST_LOG=info \
  teecryptor:local
```

Booted this way, `curl -s localhost:18080/signerAddress` returns cofhe's
dispatcher signer address rather than a random one. That is the quickest check
that the directory was picked up.

`MOCK_KEYS_DIR` exists only in the `mock` build. The production binary is
compiled without it entirely (`#[cfg(feature = "mock")]`), so no environment
variable can influence key or signer material there; its signer is bundled in the
FHE-priv Shamir secret. The variable is also absent from the Dockerfile
`allow_env_override` LABEL, so a Confidential Space VM drops it regardless.

## 2c. Full local rig on cofhe's docker network — `make local-run`

This is the turnkey version of 2b: a no-TDX container that joins the **cofhe
docker-compose network**. Other containers reach it at `http://teecryptor:8080`
and the host reaches it at `http://localhost:18080`. It loads both keys from
cofhe's committed dev keys volume and **signs responses with cofhe's own signer
key**, so signatures verify identically to the real dispatcher's.

First bring up the cofhe stack, which creates the `localcofhenix_default` network
and the ct-server:

```bash
(cd ../cofhe && docker compose up -d --build)
```

Then:

```bash
make local-run        # build mock image + run on cofhe's network
curl -s localhost:18080/healthz         # 200 once booted
curl -s localhost:18080/signerAddress   # EVM address of dispatcher_signer_pk (non-zero)
make local-stop       # stop + remove (leaves cofhe running)
```

> The host port is **18080**, not 8080, because `cofhe-oz-relayer` already
> publishes host `8080`. In-network callers still use `teecryptor:8080`. Override
> with `make local-run LOCAL_PORT=<port>`.

`local-run` mounts cofhe's dev keys read-only, points the container at cofhe's
ct-server, and boots with both gates off for a clean, chain-free start. It wires
those values as Makefile vars you can override on the command line. The exact
values and override names are in the `Makefile`.

**Signing.** Because `MOCK_KEYS_DIR` is set, Teecryptor signs as cofhe's
`dispatcher_signer_pk` rather than the throwaway signer that mock uses by
default. A signed decrypt or seal therefore verifies on-chain exactly like the
dispatcher's. See 2b for the two modes and why the keys load as a pair.

**Faithful ACL.** The gates default to off for a clean boot. To enforce permits
against the local chain, override them. `REQUIRE_PERMIT`,
`ENABLE_COMMITMENT_VERIFICATION` and `PERMIT_CHAINS_JSON` are real Makefile vars,
passed through to the container:

```bash
make local-run \
  REQUIRE_PERMIT=true \
  PERMIT_CHAINS_JSON='{"420105":{"rpc_url":"http://hostchain:8547","task_manager":"<addr>"}}'
```

Chain `420105` runs in-network at `http://hostchain:8547`, and the TaskManager
address comes from the local deploy. `PERMIT_CHAINS_JSON` is passed only when it
is non-empty. Note that `REQUIRE_PERMIT=true` without a valid
`PERMIT_CHAINS_JSON` is a boot failure by design, not a silent downgrade.

## 2d. Prebuilt mock image — `ghcr.io/fhenixprotocol/teecryptor-mock`

Every push to `main` publishes the `FEATURES=mock` build to ghcr as a multi-arch
image, tagged `latest` and the commit sha. A downstream stack can therefore pull
it instead of needing this checkout and the private `cofhe-keys` credentials to
build one. cofhe's `docker-compose.yml` tracks `:latest`.

```bash
docker pull ghcr.io/fhenixprotocol/teecryptor-mock:latest
```

**This image is not deployable.** `mock` compiles out attestation and the Shamir
key reconstruction. It reads keys from a plain directory (`MOCK_KEYS_DIR`) and
otherwise mints throwaway ones. Deployable images come from
`build-teecryptor.yml`, push to the shared Artifact Registry, and are what a
Confidential Space VM pins by digest. The two use a separate workflow, a separate
registry, and a separate name, so nothing can confuse them.

Access: the package inherits this repo's visibility, so a pull needs a token with
`read:packages`. Any *other* repo's CI, such as cofhe's, must be granted access to
the package once, under the package's *Manage Actions access*.

## 3. Real attested flow in your own project

The attestation handshake runs only in Confidential Space, so the full Shamir
round-trip needs a real GCP project. This section covers the **sandbox** case,
where the image sits in *your* project's Artifact Registry next to the compute.
Substitute your own `<PROJECT>` / `<REGION>` / `<REPO>` / `<ZONE>`.

> Production is different: the image lives in the shared ops Artifact Registry,
> and the runtime SA's pull permission is granted there. That is why step 4 below
> is manual rather than part of `compute/` Terraform — sandbox-only IAM stays out
> of the production IaC. The production runbook lives in the gitops repo.

### Flow

1. Build and push the amd64 image to **your** project's Artifact Registry:
   ```bash
   gcloud auth configure-docker <REGION>-docker.pkg.dev --quiet
   docker buildx build --platform linux/amd64 --ssh default --provenance=false \
     --metadata-file /tmp/bx.json \
     -t <REGION>-docker.pkg.dev/<PROJECT>/<REPO>/teecryptor:e2e --push .
   jq -r '."containerimage.digest"' /tmp/bx.json   # -> the amd64 platform digest
   ```
2. **Partner onboarding (keygen repo Terraform).** Each partner's
   `attested_readers` entry for `teecryptor` pins your compute project plus the
   digest from step 1, and grants a digest-scoped read of ONLY that partner's
   share secret.
3. Set `compute/terraform.tfvars`: `image_digest` from step 1, and `env`. The key
   **source** — the partner set, the per-partner WIF audiences, and the public
   bucket and object — is baked into the binary per environment and selected by
   `COFHE_ENV`. It is fail-closed and not operator-settable.
4. **Grant the runtime SA image-pull permission** — see the gotcha below.
5. `terraform -chdir=compute apply` → the TDX VM boots, attests, and
   reconstructs T-of-N.
6. Verify from the serial log: `Signing service initialized with address: 0x…`
   matches the published `decrypt_signer_address`, and `teecryptor listening
   0.0.0.0:8080`.
7. **Critical security test:** rebuild with a one-byte change and boot the new
   image **without** re-applying the partner reader Terraform. Every partner's
   STS must reject the attestation, because each reader CEL still pins the old
   digest, and no share may be readable. If the rogue image reads any share, the
   IAM configuration is wrong. Stop and fix it.
8. `terraform -chdir=compute destroy` to stop billing.

### Gotcha: the runtime SA needs `artifactregistry.reader` (manual, sandbox-only)

**Symptom** (serial log): the VM never starts and shows
`failed to pull image … 403 Forbidden` or `failed to fetch oauth token … 403`.

**Cause:** for a co-located image, the VM's runtime SA
(`teecryptor@<PROJECT>...`) needs `artifactregistry.reader` on your repository.
That grant is not in `compute/` Terraform, because production grants it in the
shared registry project instead. A `terraform destroy` and re-apply also
recreates the runtime SA with a new uid, which orphans any prior grant — it then
shows as `deleted:serviceAccount:…?uid=…` in the repository IAM policy, and the
next deploy 403s.

**Fix — re-run after every `destroy` + `apply`:**
```bash
PROJECT=<PROJECT>; REGION=<REGION>; REPO=<REPO>
SA=teecryptor@${PROJECT}.iam.gserviceaccount.com
gcloud artifacts repositories add-iam-policy-binding "$REPO" \
  --location="$REGION" --project="$PROJECT" \
  --member="serviceAccount:${SA}" --role="roles/artifactregistry.reader"

# Then re-pull by recreating the instance (name from: gcloud compute instances list):
gcloud compute instance-groups managed recreate-instances teecryptor-mig \
  --instances=<INSTANCE> --zone=<ZONE> --project="$PROJECT"
```

Check that the grant landed on the **current** SA rather than a stale `deleted:`
one:
```bash
gcloud artifacts repositories get-iam-policy "$REPO" --location="$REGION" --project="$PROJECT"
```

### Gotcha: a new teecryptor image needs the partner reader Terraform re-applied

**Symptom** (workload logs): teecryptor boots and attests, then exits with
`STS 400 … {"error":"unauthorized_client","error_description":"The given
credential is rejected by the attribute condition."}`, followed by
`Error: load + reconstruct FHE-priv key`.

**Cause:** each partner's reader WIF provider `attribute_condition` (the CEL in
the keygen repo's `attested_readers`) pins the **teecryptor** image digest. That
pin is the identity check for which image may read that partner's share. After
you build a new image, the partners' CELs still pin the old digest, so each
partner's STS rejects the new VM at the federation exchange.

**Fix — this is the two-phase deploy.** Partners pin the digest first, then
`compute/` runs that image:
```bash
# keygen repo: update the teecryptor image digest in each partner's
# attested_readers and terraform apply per partner. Then recreate the compute
# instance so its attestation is re-checked against the new CELs:
gcloud compute instance-groups managed recreate-instances teecryptor-mig \
  --instances=<INSTANCE> --zone=<ZONE> --project="$PROJECT"
```
