## Summary

Two gin-registered routes relay attacker-controlled queries to ollama.com signed with the victim's identity:

- `POST /api/experimental/web_search` → `webExperimentalProxyHandler` → `proxyCloudRequestWithPath(c, body, "api/web_search", ...)`
- `POST /api/experimental/web_fetch` → same handler with path `api/web_fetch`

`proxyCloudRequestWithPath` at `server/cloud_proxy.go:179-213` builds the outbound request to `https://ollama.com/api/web_{search,fetch}` and calls `cloudProxySignRequest(outReq.Context(), outReq)`. `signCloudProxyRequest` at `server/cloud_proxy.go:360-373` signs with `auth.Sign(ctx, ...)` which reads `~/.ollama/id_ed25519` and signs the request body+headers+path with the victim's ed25519 private key.

No per-route auth, no bearer token, no user-confirmation prompt. The local-trust model of the daemon (any loopback request is equivalent to the local user) is the sole guard — and p8-060 / p8-061 break that model.

## Details

Two gin-registered routes relay attacker-controlled queries to ollama.com signed with the victim's identity:

- `POST /api/experimental/web_search` → `webExperimentalProxyHandler` → `proxyCloudRequestWithPath(c, body, "api/web_search", ...)`
- `POST /api/experimental/web_fetch` → same handler with path `api/web_fetch`

`proxyCloudRequestWithPath` at `server/cloud_proxy.go:179-213` builds the outbound request to `https://ollama.com/api/web_{search,fetch}` and calls `cloudProxySignRequest(outReq.Context(), outReq)`. `signCloudProxyRequest` at `server/cloud_proxy.go:360-373` signs with `auth.Sign(ctx, ...)` which reads `~/.ollama/id_ed25519` and signs the request body+headers+path with the victim's ed25519 private key.

No per-route auth, no bearer token, no user-confirmation prompt. The local-trust model of the daemon (any loopback request is equivalent to the local user) is the sole guard — and p8-060 / p8-061 break that model.

### Location

- `server/routes.go:1707-1708` — route registration, no per-route auth
- `server/routes.go:1958-1978` — `webExperimentalProxyHandler`
- `server/cloud_proxy.go:179-213` — `proxyCloudRequestWithPath` (outbound signing)
- `server/cloud_proxy.go:360-373` — `signCloudProxyRequest` (ed25519 signing with local key)

### Attacker Control

Request body forwarded verbatim. Query text + model choice + fetch URL entirely attacker-controlled.

### Trust Boundary Crossed

B10 (network) → local identity (victim's ed25519 signing capacity) → remote ollama.com account.

### Evidence

Tracer confirmed reachability, CodeQL `DFD-9-web-fetch-ssrf` reports this flow with `reachable: true, path_count: 1`. Source `os.Getenv('OLLAMA_HOST')` → sink `http.NewRequest*` in cloud-proxy handlers.

Advocate: "The daemon's trust model is explicit: localhost = trusted user. Every endpoint inherits this model." Synthesizer notes that adding per-endpoint auth for signing-key-involving endpoints is not "architectural inconsistency" — it is defense-in-depth for a cryptographic capability that other endpoints do not invoke.

## Root Cause

Validated rationale: `/api/experimental/web_search` and `/api/experimental/web_fetch` (routes.go:1707-1708) have no per-route auth; any client that reaches the daemon causes `proxyCloudRequestWithPath` to sign an outbound HTTPS request to ollama.com with the victim's `~/.ollama/id_ed25519` — charging the victim's account and poisoning their query history. Advocate concedes no auth exists; the design presumes loopback-only trust, but that presumption fails under p8-060 (0.0.0.0) or p8-061 (.localhost drive-by).

Primary cited code reference: `server/routes.go:1707`.

Merge extraction sink line: - `server/routes.go:1707-1708` — route registration, no per-route auth

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed (partial - signing pipeline confirmed reaches ollama.com; billing effect requires signed-in victim not present in test env)`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Achieve reachability to the daemon (p8-060 = 0.0.0.0 bind, p8-061 = `.localhost` drive-by, or local).
2. `curl -X POST http://<ollama>:11434/api/experimental/web_search -H 'Content-Type: application/json' -d '{"query":"attacker query string","model":"gpt-5"}'`.
3. Inspect ollama.com dashboard — query appears in victim's history; usage billed to victim.

Remediation:
- Require a per-process API-key or a local-UI confirmation prompt (similar to the agent approval prompt) for routes that invoke cloud-proxy signing.
- Add rate-limiting keyed by `X-Forwarded-For` or socket address to bound damage.
- At minimum, document that `/api/experimental/web_{search,fetch}` is a privileged signing proxy and refuse to serve it when the bind is non-loopback unless an allowlist env is set.

## Impact

- Free use of the victim's ollama.com cloud resources (billed to the victim).
- Poisoning of the victim's query history on ollama.com (search/fetch queries that the victim never issued become attributed to them — a potential compliance incident).
- `web_fetch` specifically retrieves attacker-chosen URLs; combined with p8-063 (unbounded response body) and p8-064-adjacent SSE hijack paths (H-04, PARTIAL), it pivots into a signed-SSRF primitive where ollama.com mediates but the victim is billed.
- Combines with p8-060 / p8-061 into CHAIN-A identity theft.

_Synthesized during merge normalization from `archon/findings/M29-web-search-fetch-unauth-signing-oracle/draft.md`._
