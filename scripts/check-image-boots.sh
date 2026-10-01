#!/usr/bin/env bash
# Prove that a built teecryptor image starts: the binary loads, links and runs main.
#
#   scripts/check-image-boots.sh <image-ref>
#
# A provenance check proves who built an image. It does not prove that the image
# runs. An image whose binary cannot load passes every provenance check, and the
# failure shows only when a VM boots it.
#
# The check runs the image with no COFHE_ENV and no network. teecryptor first
# installs the rustls crypto provider, then reads COFHE_ENV and stops. The
# expected error thus proves that the dynamic loader, glibc and the TLS provider
# all work, and that nothing else ran: no key load and no I/O.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <image-ref>" >&2
  exit 2
fi
image="$1"
# The context string of Config::from_env (src/main.rs). COFHE_ENV is the
# first required variable. A change to that message, or a new required variable
# read before it, must change this line too.
expected='env var COFHE_ENV not set'

# Pull a registry image first, with retries. A registry can briefly refuse a
# manifest that was just pushed. A pull failure is an infrastructure fault, not
# a boot fault, so it must not read as one.
if ! docker image inspect "${image}" >/dev/null 2>&1; then
  for attempt in 1 2 3; do
    docker pull --platform linux/amd64 "${image}" && break
    if [ "${attempt}" -eq 3 ]; then
      echo "::error::could not pull ${image}. This is NOT a boot failure: the check did not run." >&2
      exit 1
    fi
    sleep 10
  done
fi

# The binary must exit non-zero here. Capture the exit code without set -e
# aborting the script.
set +e
output="$(docker run --rm --network none --platform linux/amd64 "${image}" 2>&1)"
status=$?
set -e

printf '%s\n' "${output}"

if [ "${status}" -eq 0 ]; then
  echo "::error::${image} exited 0 with no COFHE_ENV. It must refuse to start." >&2
  exit 1
fi
if ! grep -qF "${expected}" <<<"${output}"; then
  echo "::error::${image} did not reach main. Expected the error: ${expected}" >&2
  exit 1
fi
echo "OK: ${image} loads and runs main."
