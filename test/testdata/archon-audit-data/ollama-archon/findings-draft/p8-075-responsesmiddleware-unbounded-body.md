Phase: 8
Sequence: 075
Slug: responsesmiddleware-unbounded-body
Verdict: FALSE POSITIVE (adversarial)
Rationale: `server/middleware/openai.go:511-523 ResponsesMiddleware` calls `io.ReadAll` on the raw OpenAI-compat request body without wrapping in `http.MaxBytesReader` — the dedicated sibling of p8-063 for the OpenAI-compat translation layer. Advocate confirms gin has no default body cap and no other wrapping happens upstream.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The actual `ResponsesMiddleware` (at `middleware/openai.go:509-571`, not `server/middleware/openai.go:511-523`) does not call `io.ReadAll`; it uses `c.ShouldBindJSON(&req)` which is a streaming `json.Decoder` with no buffering step, and the unbounded buffering observed on the `/v1/responses` path actually occurs in the preceding `cloudPassthroughMiddleware -> readRequestBody -> io.ReadAll` call (already covered by p8-063).
Severity-Final: N/A (DISPROVED — subsumed by p8-063)
PoC-Status: executed

## Summary

`ResponsesMiddleware` in `server/middleware/openai.go:511-523` is the OpenAI-compat shim for the `/v1/responses` family. It needs to inspect the incoming JSON to translate it to Ollama-native format, so it reads the full request body:

```go
// middleware/openai.go:511-523 (per pre-seed; body shape confirmed in sinks.json)
body, err := io.ReadAll(c.Request.Body)
...
```

No `http.MaxBytesReader` wrapper. No `Content-Length` check. No chunk-size bound.

Distinct from p8-063 (which covers `cloud_proxy.go:289-300 readRequestBody`) because:

- p8-063 is the cloud-passthrough path (forwards bytes to ollama.com).
- This finding is the on-host translation path — the bytes stay on the ollama process, get JSON-decoded, then re-encoded, further amplifying transient memory usage.

Every request to `/v1/responses`, `/v1/chat/completions` (when routed through the `ResponsesMiddleware`), and any other endpoint that installs this middleware shares the sink.

## Location

- `server/middleware/openai.go:511-523` — `io.ReadAll(c.Request.Body)` unbounded
- `server/routes.go` — route registration that installs `ResponsesMiddleware`

## Attacker Control

Any HTTP client reaching the OpenAI-compat endpoints; request-body size fully attacker-controlled.

## Trust Boundary Crossed

B10 (network) → process memory.

## Impact

Single-request OOM DoS. Because the translation layer re-encodes after decoding, the peak working set is 2-3× the attacker's body size. Combined with p8-063 (cloud-passthrough), the attacker has multiple independent OOM primitives that a defender must patch uniformly.

## Evidence

Tracer flagged the sink in the pre-seed (H-00.11 per file numbering). Advocate: "For ResponsesMiddleware raw JSON path, io.ReadAll has no cap" — no compensating control found.

## Reproduction Steps

1. Ollama bound with any reachable listener (loopback with p8-061 drive-by reach, or 0.0.0.0).
2. `curl -X POST http://<target>:11434/v1/responses -H 'Content-Type: application/json' --data-binary @4gb.json`.
3. Ollama process RSS grows to ~8-12 GB before JSON parse fails.

Remediation: apply `http.MaxBytesReader(c.Writer, c.Request.Body, maxOpenAIBodySize)` at the top of `ResponsesMiddleware`. Use the same constant as p8-063's fix (shared between cloud passthrough and OpenAI-compat).
