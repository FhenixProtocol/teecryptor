#!/usr/bin/env bash
# Local end-to-end proof of REAL cofhe decrypt — no GCP, no attestation.
#
# Boots the ct-stub (serving the committed corpus) + teecryptor in --features
# mock loading the REAL 40 KiB cofhe ClientKey via MOCK_KEYS_DIR, then POSTs
# /decrypt for every corpus handle and asserts the known plaintext. The decrypt
# path and the /GetCT contract are identical to the TDX deployment; only the
# attestation/Secret-Manager shell is stubbed out by mock mode.
#
# Prereq: cargo build --release --features mock --bin teecryptor
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

BIN=target/release/teecryptor
KEY=tests/cofhe_compat/dev_zone0_testkey.bin
STUB_PORT=9450
APP_PORT=8080

[ -x "$BIN" ] || { echo "missing $BIN — run: cargo build --release --features mock --bin teecryptor"; exit 1; }

# MOCK_KEYS_DIR takes a DIRECTORY laid out like cofhe's deployments/keys/dev and
# loads the ClientKey and the signer together, so stage one under the names it
# expects. The signer is throwaway: this demo asserts plaintexts, not signatures.
KEYS_DIR=$(mktemp -d)
cp "$KEY" "$KEYS_DIR/ck.binfile"
head -c 32 /dev/urandom > "$KEYS_DIR/dispatcher_signer_pk"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$KEYS_DIR"
}
trap cleanup EXIT

echo "== starting ct-stub on :$STUB_PORT =="
CORPUS_DIR=tests/cofhe_compat PORT=$STUB_PORT python3 tools/ct-stub/server.py &
pids+=($!)

echo "== starting teecryptor (mock, real key) on :$APP_PORT =="
MOCK_KEYS_DIR="$KEYS_DIR" \
  CT_SOURCE_URL="http://127.0.0.1:$STUB_PORT" \
  BIND_ADDR="127.0.0.1:$APP_PORT" \
  REQUIRE_PERMIT=false \
  RUST_LOG=info \
  "$BIN" &
pids+=($!)

echo "== waiting for /healthz =="
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null || { echo "healthz never came up"; exit 1; }
echo "   healthz OK"

echo "== decrypting every corpus handle =="
# handles.json was written by the stub at startup
python3 - "$APP_PORT" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
handles = json.load(open("tools/ct-stub/handles.json"))
ok = bad = 0
for h, meta in handles.items():
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/decrypt",
        data=json.dumps({"handle": h}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=30))
        got, want = resp.get("plaintext", "").lower(), meta["plaintext"].lower()
        if got == want:
            print(f"  PASS {meta['name']:<14} {h[:14]}… -> {got}"); ok += 1
        else:
            print(f"  FAIL {meta['name']:<14} want {want} got {got}"); bad += 1
    except Exception as e:
        print(f"  FAIL {meta['name']:<14} error: {e}"); bad += 1
print(f"\n== {ok} passed, {bad} failed ==")
sys.exit(1 if bad else 0)
PY
