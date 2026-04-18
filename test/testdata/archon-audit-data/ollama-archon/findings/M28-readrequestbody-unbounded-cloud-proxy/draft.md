Phase: 8
Sequence: 028
Slug: readrequestbody-unbounded-cloud-proxy
Verdict: VALID
Rationale: `server/cloud_proxy.go:289-300` calls `io.ReadAll(r.Body)` with no size limit on every non-zstd cloud-passthrough request — `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/messages`, `/api/experimental/web_search`, `/api/experimental/web_fetch` — while the zstd branch has a 20 MiB cap (line 35). Advocate confirms no other MaxBytesReader in the chain and concedes real remote-DoS when chained with 0.0.0.0 bind or any allowedHosts bypass.
Severity-Original: HIGH
Severity-Final: MEDIUM
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

`readRequestBody` at `server/cloud_proxy.go:289-300`:

```go
func readRequestBody(r *http.Request) ([]byte, error) {
    body, err := io.ReadAll(r.Body)
    ...
}
```

is the entry point for every cloud-passthrough request path (`cloudPassthroughMiddleware` at `server/cloud_proxy.go:73-135`; direct callers at `server/routes.go:1966-1978 webExperimentalProxyHandler`). The zstd branch at lines 89-91 wraps the body with `http.MaxBytesReader(..., maxDecompressedBodySize)` (20 MiB ceiling), but the non-zstd path — the common path for any plain JSON POST — does not.

Any plain-JSON POST to a cloud-passthrough endpoint is buffered fully in RAM before processing. Endpoints with this sink include:
- `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/messages` (OpenAI-compat)
- `/api/experimental/web_search`, `/api/experimental/web_fetch`
- plus every future endpoint that routes through `cloudPassthroughMiddleware`

Paired with p8-060 (0.0.0.0 bind removes host filter) or p8-061 (DNS-rebinding via `.localhost`), the attack is remote-reachable: a single POST of a 4 GB body forces a 4 GB allocation in the Ollama process, triggering OOM kill or sustained GC pressure that degrades inference throughput.

## Location

- `server/cloud_proxy.go:289-300` — `readRequestBody` with unbounded `io.ReadAll`
- `server/cloud_proxy.go:73-135` — `cloudPassthroughMiddleware`; 20 MiB cap present only in zstd branch (line 35: `maxDecompressedBodySize = 20<<20`)
- `server/routes.go:1966-1978` — `webExperimentalProxyHandler` also routes through the same sink

Related but distinct: `server/middleware/openai.go:511-523` (`ResponsesMiddleware` reads the same unbounded body on the OpenAI-compat path — same root pattern, same severity).

## Attacker Control

Any network-reachable HTTP client; body content and size are fully attacker-controlled.

## Trust Boundary Crossed

B10 (network) → process memory.

## Impact

- Single-request OOM DoS against the Ollama daemon; inference sessions dropped.
- GC pressure from large allocations degrades tail-latency of concurrent inference.
- When chained with p8-062 (`OLLAMA_EXPERIMENT=client2` bypasses middleware) the attack is also unauthenticated on the client2 path.

## Evidence

Tracer confirmed the code path on HEAD. CodeQL `DFD-8-zstd-readall` reports the zstd cap correctly but does NOT fire on the non-zstd branch — true-negative gap.

Advocate: "On default loopback bind, OOM is a local-only DoS." Synthesizer retains HIGH because (a) 0.0.0.0 bind is documented and common in Docker / WSL2 / LAN setups, (b) browser drive-by via `.localhost` reaches the endpoint with a simple POST, (c) defense-in-depth dictates a cap regardless of bind.

## Reproduction Steps

1. `OLLAMA_HOST=0.0.0.0 ollama serve`.
2. `yes | head -c 4G > big.json; curl -X POST http://<target>:11434/v1/chat/completions -H 'Content-Type: application/json' --data-binary @big.json`.
3. Monitor `ollama`'s RSS — it grows to 4 GB before JSON parsing fails.

Remediation: wrap `r.Body` with `http.MaxBytesReader(c.Writer, r.Body, maxRawBodySize)` at entry into `readRequestBody` — apply a 32 MiB cap (similar to the decompressed 20 MiB budget, with some headroom for JSON overhead). Apply identical cap to `ResponsesMiddleware`. Register the cap as a `sync.Once`-initialized constant so every cloud-passthrough sink shares one source of truth.

---

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Independent reproduction against the real `server` package at commit 57653b8e streamed a 512 MiB body through `cloudPassthroughMiddleware` → `readRequestBody` → `io.ReadAll` in 577 ms with no cap; scales linearly to RAM-exhaustion; no blocking control found on plain-POST path when bound non-loopback.
Severity-Final: MEDIUM
PoC-Status: executed
