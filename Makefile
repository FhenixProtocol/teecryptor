# Teecryptor operational targets. Layout: compute (workload owner) per env +
# a shared fhenix-artifacts-registry project that hosts ONLY the Artifact
# Registry + the CI image-push WIF (no Terraform state — see below). Key custody
# is per-partner (Shamir shares, keygen repo terraform); the legacy keys/
# custodian stack is kept applied only until the partner-enforced-reader Part 2
# cutover retires it.
#
# Terraform state lives per-project: keys-module state in the KEYS project's bucket,
# compute-module state in the COMPUTE project's bucket (gs://<project>-tfstate).
# KEYS_PROJECT/COMPUTE_PROJECT select the deploy target; the VM's baked-source
# selector is compute tfvars `env` (wired as COFHE_ENV).
# Two-phase deploy: `image` captures the amd64 digest; pinning and rolling happen
# in the gitops repo (per-env var-files) plus each partner's attested_readers in
# the keygen repo. This Makefile does not deploy — see `make deploy`.
# Requires: gcloud, terraform, docker, cargo. Touches real GCP.

ARTIFACTS_PROJECT ?= fhenix-artifacts-registry
KEYS_PROJECT      ?= teecryptor-sa-1
COMPUTE_PROJECT   ?= teecryptor-tdx
REGION            ?= europe-west4
# Image lives in the shared artifact registry; every env's VM pulls the same digest.
IMAGE             ?= $(REGION)-docker.pkg.dev/$(ARTIFACTS_PROJECT)/teecryptor/teecryptor
TAG               ?= dev

# --- Local (no-TDX) run against the cofhe docker-compose stack ---
# Reuses the SAME Dockerfile with FEATURES=mock (compiles out attestation/GCP),
# keys read from cofhe's committed dev keys volume. See docs/SANDBOX.md.
COFHE_KEYS    ?= ../cofhe/deployments/keys/dev
COFHE_NET     ?= localcofhenix_default
CT_SOURCE_URL ?= http://ct-server:9450
# Clean-boot defaults. Override to exercise the real gates against the local
# chain, e.g.
#   make local-run REQUIRE_PERMIT=true PERMIT_CHAINS_JSON='{"420105":{...}}'
REQUIRE_PERMIT                 ?= false
ENABLE_COMMITMENT_VERIFICATION ?= false
PERMIT_CHAINS_JSON             ?=
LOCAL_IMAGE   ?= teecryptor:local-mock
# Host publish port. NOT 8080: cofhe-oz-relayer already publishes host :8080, and
# this rig runs alongside the cofhe stack. In-network callers use teecryptor:8080
# regardless (the host port only affects `curl` from the host).
LOCAL_PORT    ?= 18080

# Backend = per-project state bucket (gs://<project>-tfstate), one prefix per module.
TF_INIT_KEYS    = terraform -chdir=keys    init -backend-config="bucket=$(KEYS_PROJECT)-tfstate"    -backend-config="prefix=teecryptor/keys"
TF_INIT_COMPUTE = terraform -chdir=compute init -backend-config="bucket=$(COMPUTE_PROJECT)-tfstate" -backend-config="prefix=teecryptor/compute"

.PHONY: help test image deploy keys destroy local-run local-stop

help:
	@echo "targets: test | image | deploy | keys | destroy | local-run | local-stop"
	@echo "set KEYS_PROJECT + COMPUTE_PROJECT to pick the env; state in gs://<project>-tfstate"
	@echo "image -> shared artifact registry ($(IMAGE)); pin that digest in the gitops var-file"
	@echo "deploy -> retired; prints the real apply + rolling-action replace procedure and exits 1"
	@echo "local-run -> no-TDX container on cofhe's docker network, keys from $(COFHE_KEYS)"
	@echo "see the gitops repo for the deploy runbook and alerting policies"

# Run the full local test suite (the authoritative end-to-end decrypt proof).
test:
	cargo test --all-targets

# Build + push an amd64 image to the shared artifact registry and PRINT its digest. The
# TDX VM runs amd64, so this single-arch digest is the platform digest to pin.
# (CI's build-teecryptor.yml is the multi-arch path and prints the amd64 digest.)
# Pin the printed digest as image_digest in the env's gitops var-file AND in each
# partner's attested_readers (keygen repo) — never the multi-arch manifest-list digest.
image:
	docker build --platform linux/amd64 -t "$(IMAGE):$(TAG)" .
	docker push "$(IMAGE):$(TAG)"
	@DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' "$(IMAGE):$(TAG)" | sed 's,.*@,,'); \
	  echo; \
	  echo "PIN THIS amd64 digest in the env's gitops var-file AND each partner's attested_readers:"; \
	  echo "    image_digest = \"$$DIGEST\""

# This target no longer deploys; it prints the real procedure and fails. The old
# recipe could not deploy an env for two reasons:
#   1. `terraform -chdir=compute apply` took no -var-file, so it only ever saw an
#      auto-loaded compute/terraform.tfvars. A deployed env's values live in the
#      gitops repo since they were centralised, and that file is not in the tree.
#   2. An apply alone rolls nothing. The MIG's update_policy is OPPORTUNISTIC, so an
#      apply only re-points the instance template (see compute/main.tf) — the running
#      VM keeps the old image until an operator replaces it.
# The recipe printed below is the real one. Run it from a gitops checkout.
deploy:
	@echo "make deploy is retired — it applied compute/ with no -var-file and never rolled the MIG."; \
	 echo; \
	 echo "Pin the digest in the env's gitops var-file AND each partner's attested_readers,"; \
	 echo "apply the partner Terraform, then:"; \
	 echo; \
	 echo "  terraform -chdir=compute init -reconfigure \\"; \
	 echo "    -backend-config=bucket=<env-compute-project>-tfstate \\"; \
	 echo "    -backend-config=prefix=teecryptor/compute"; \
	 echo "  terraform -chdir=compute apply -var-file=<gitops>/terraform/<env>/teecryptor/<env>.tfvars"; \
	 echo; \
	 echo "  gcloud compute instance-groups managed rolling-action replace teecryptor-mig \\"; \
	 echo "    --zone=<zone> --project=<env-compute-project> --max-surge=1 --max-unavailable=0"; \
	 echo; \
	 echo "Replace, not stop/start: a Confidential VM's boot image is fixed at creation, so"; \
	 echo "stop/start returns the SAME instance on the SAME image and reports healthy."; \
	 echo "This MIG has no autohealing, so verify the new instance booted the intended digest:"; \
	 echo; \
	 echo "  gcloud compute instances describe <instance> --zone=<zone> --project=<p> \\"; \
	 echo "    --format='value(metadata.items.filter(\"key:tee-image-reference\").extract(\"value\"))'"; \
	 echo; \
	 echo "Full runbook: the gitops repo."; \
	 exit 1

# LEGACY DEV ONLY: generate a tfhe-rs ClientKey, push to Secret Manager in the
# legacy KEYS project, shred the local copy. The current reader does NOT use this
# secret — production key material is the per-partner Shamir shares written by the
# keygen ceremony (keygen repo).
keys:
	@echo "DEV ONLY — generates and uploads a dev ClientKey to Secret Manager ($(KEYS_PROJECT))."
	cargo run --quiet --bin genkey > /tmp/teecryptor-dev-key.bin
	gcloud secrets versions add teecryptor-key-z0 --project="$(KEYS_PROJECT)" --data-file=/tmp/teecryptor-dev-key.bin
	shred -u /tmp/teecryptor-dev-key.bin 2>/dev/null || rm -f /tmp/teecryptor-dev-key.bin

# Tear everything down (compute first — it depends on keys' outputs).
destroy:
	@test -n "$(KEYS_PROJECT)" -a -n "$(COMPUTE_PROJECT)" || (echo "ERROR: set KEYS_PROJECT and COMPUTE_PROJECT" && exit 1)
	$(TF_INIT_COMPUTE)
	terraform -chdir=compute destroy
	$(TF_INIT_KEYS)
	terraform -chdir=keys    destroy

# LOCAL, NO TDX: build the mock image and run it as a plain container on cofhe's
# docker network, reading the FHE + signer keys from cofhe's keys volume. Other
# containers on that network reach it at http://teecryptor:8080; the host reaches
# it at http://localhost:$(LOCAL_PORT). NOT attested — local dev only.
#
# Prereq: the cofhe stack is up (creates the $(COFHE_NET) network + ct-server):
#     (cd ../cofhe && docker compose up -d --build)
local-run:
	@docker network inspect "$(COFHE_NET)" >/dev/null 2>&1 || \
	  { echo "ERROR: docker network '$(COFHE_NET)' not found — start cofhe first:"; \
	    echo "    (cd ../cofhe && docker compose up -d --build)"; \
	    echo "  (or override COFHE_NET=<name> — see 'docker network ls')"; exit 1; }
	@test -f "$(COFHE_KEYS)/ck.binfile" -a -f "$(COFHE_KEYS)/dispatcher_signer_pk" || \
	  { echo "ERROR: '$(COFHE_KEYS)' must contain ck.binfile AND dispatcher_signer_pk — set COFHE_KEYS to cofhe's deployments/keys/dev"; exit 1; }
	docker build --build-arg FEATURES=mock -t "$(LOCAL_IMAGE)" .
	docker rm -f "$(LOCAL_NAME)" >/dev/null 2>&1 || true
	docker run -d --name "$(LOCAL_NAME)" \
	  --network "$(COFHE_NET)" \
	  -v "$(abspath $(COFHE_KEYS)):/keys:ro" \
	  -p "127.0.0.1:$(LOCAL_PORT):8080" \
	  -e MOCK_KEYS_DIR=/keys \
	  -e CT_SOURCE_URL="$(CT_SOURCE_URL)" \
	  -e BIND_ADDR=0.0.0.0:8080 \
	  -e REQUIRE_PERMIT="$(REQUIRE_PERMIT)" \
	  -e ENABLE_COMMITMENT_VERIFICATION="$(ENABLE_COMMITMENT_VERIFICATION)" \
	  $(if $(PERMIT_CHAINS_JSON),-e PERMIT_CHAINS_JSON='$(PERMIT_CHAINS_JSON)',) \
	  -e RUST_LOG=info \
	  "$(LOCAL_IMAGE)"
	@echo "teecryptor up: http://$(LOCAL_NAME):8080 (in-network) | http://localhost:$(LOCAL_PORT) (host)"
	@echo "check: curl -s localhost:$(LOCAL_PORT)/healthz  (200 once booted)"

# Stop + remove the local container (leaves the cofhe stack running).
local-stop:
	docker rm -f "$(LOCAL_NAME)" >/dev/null 2>&1 || true
