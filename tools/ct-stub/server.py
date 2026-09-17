#!/usr/bin/env python3
"""Minimal cofhe ct-server stub for the TDX first-boot real-decrypt test.

Serves the committed compatibility corpus (`tests/cofhe_compat/*.ct`, real
cofhe ciphertexts with known plaintexts) over `POST /GetCT`, exactly matching
the wire contract Teecryptor's `src/ct_source.rs` expects:

    request : { "hash": "0x<handle>" }
    200     : { "data": "0x<hex of safe_serialize'd ct>",
                "uint_type": <i32>, "security_zone": 0,
                "compact": false, "gzipped": false }
    404     : unknown handle

Handles are synthetic and deterministic (0x000…0N in manifest order) — the
ciphertext type comes from `uint_type` in the response, not the handle, so any
opaque handle works. The handle→plaintext table is printed at startup and
written to `handles.json` so the decrypt assertions know what to expect.

stdlib only (no deps), so it runs on a bare Debian/COS GCE VM via a startup
script. Config via env: CORPUS_DIR (default ./tests/cofhe_compat), PORT (9450).
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CORPUS_DIR = os.environ.get("CORPUS_DIR", "tests/cofhe_compat")
PORT = int(os.environ.get("PORT", "9450"))


def load_corpus(corpus_dir):
    """Return {handle_hex_lower: {data_hex, uint_type, security_zone, name, plaintext}}."""
    with open(os.path.join(corpus_dir, "manifest.json"), "rb") as f:
        manifest = json.load(f)
    table = {}
    for i, entry in enumerate(manifest):
        handle = "0x" + format(i + 1, "064x")
        with open(os.path.join(corpus_dir, entry["file"]), "rb") as f:
            raw = f.read()
        table[handle.lower()] = {
            "data": "0x" + raw.hex(),
            "uint_type": entry["encryption_type"],
            "security_zone": entry.get("security_zone", 0),
            "name": entry["name"],
            "plaintext": entry["expected_plaintext_hex"],
        }
    return table


TABLE = load_corpus(CORPUS_DIR)


def norm(h):
    h = (h or "").strip().lower()
    if not h.startswith("0x"):
        h = "0x" + h
    return h


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != "/GetCT":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            self._json(400, {"error": f"bad json: {e}"})
            return
        entry = TABLE.get(norm(req.get("hash")))
        if entry is None:
            self._json(404, {"error": "ciphertext not found"})
            return
        self._json(200, {
            "data": entry["data"],
            "uint_type": entry["uint_type"],
            "security_zone": entry["security_zone"],
            "compact": False,
            "gzipped": False,
        })

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("ct-stub: " + (fmt % args) + "\n")


def main():
    # Emit the handle→plaintext map so the decrypt test knows what to assert.
    out = {h: {"name": e["name"], "uint_type": e["uint_type"], "plaintext": e["plaintext"]}
           for h, e in TABLE.items()}
    with open(os.path.join(os.path.dirname(__file__) or ".", "handles.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"ct-stub: loaded {len(TABLE)} ciphertexts from {CORPUS_DIR}", file=sys.stderr)
    for h, e in TABLE.items():
        print(f"  {h}  {e['name']:<14} uint_type={e['uint_type']}  -> {e['plaintext']}", file=sys.stderr)
    print(f"ct-stub: POST http://0.0.0.0:{PORT}/GetCT", file=sys.stderr)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
