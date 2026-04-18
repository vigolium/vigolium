## Summary

Two unbounded `io.ReadAll(resp.Body)` sinks run during a single `/api/pull` to an attacker-controlled registry:

1. `server/auth.go:81` — reads the response body from the token endpoint when the manifest URL returns 401.
2. `server/images.go:864` — reads the manifest body.

Neither call wraps the reader in `io.LimitReader` or `http.MaxBytesReader`, and there is no `Content-Length` pre-check. A malicious registry that responds with a multi-GB body (or a never-ending chunked stream) to either endpoint causes the ollama process to allocate memory until OOM-killed, dropping all active inference sessions.

## Details

Two unbounded `io.ReadAll(resp.Body)` sinks run during a single `/api/pull` to an attacker-controlled registry:

1. `server/auth.go:81` — reads the response body from the token endpoint when the manifest URL returns 401.
2. `server/images.go:864` — reads the manifest body.

Neither call wraps the reader in `io.LimitReader` or `http.MaxBytesReader`, and there is no `Content-Length` pre-check. A malicious registry that responds with a multi-GB body (or a never-ending chunked stream) to either endpoint causes the ollama process to allocate memory until OOM-killed, dropping all active inference sessions.

### Location

- `server/images.go:864` — `data, err := io.ReadAll(resp.Body)` (manifest)
- `server/auth.go:81` — `body, err := io.ReadAll(response.Body)` (token)

### Attacker Control

Malicious registry (reached via `/api/pull` with attacker-controlled `name`). No victim authentication required.

### Trust Boundary Crossed

Network (hostile registry) → local process memory.

### Evidence

```go
// server/images.go:860-867
resp, err := makeRequestWithRetry(ctx, http.MethodGet, requestURL, headers, nil, regOpts)
if err != nil {
    return nil, nil, err
}
defer resp.Body.Close()

data, err := io.ReadAll(resp.Body)    // <-- unbounded
```

```go
// server/auth.go:75-83
response, err := makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})
if err != nil {
    return "", err
}
defer response.Body.Close()

body, err := io.ReadAll(response.Body)   // <-- unbounded
```

No `io.LimitReader`, `http.MaxBytesReader`, or `Content-Length` cap exists in either path (verified by grep across `server/`).

## Root Cause

Validated rationale: Two separate unbounded io.ReadAll sinks (manifest + token response) fire during a single /api/pull to an attacker-controlled registry; Advocate confirmed no LimitReader or MaxBytesReader anywhere in the chain.

Primary cited code reference: `server/images.go:864`.

Merge extraction sink line: - `server/images.go:864` — `data, err := io.ReadAll(resp.Body)` (manifest)

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed (sink-level httptest reproduction)`.

PoC script present: `poc.go`.

Supporting evidence is present under `evidence/`.

1. Run attacker registry that handles `GET /v2/evil/foo/manifests/latest` by streaming bytes forever (or returning a single 10 GB body).
2. Victim:
   ```
   curl -X POST http://127.0.0.1:11434/api/pull -d '{"name":"attacker.com/evil/foo:latest"}'
   ```
3. Observe ollama RSS grows unboundedly until OOM kill.
4. Token-side variant: return `401 WWW-Authenticate: Bearer realm="https://attacker.com/token",service="x",scope="y"` on manifest; then stream unlimited body on `/token`.

Debate context: Tracer confirmed both sinks. Advocate searched for limits in the same functions, the `makeRequest`/`makeRequestWithRetry` helpers, and the `http.Client` setup — none exist. Fix is one-line: `io.ReadAll(io.LimitReader(resp.Body, MAX_MANIFEST_SIZE))` with a sensible cap (e.g., 4 MiB for manifests, 64 KiB for token responses).

## Impact

- Process OOM → SIGKILL by the kernel OOM killer.
- All active inference requests drop; any in-progress model loads lose state; other clients lose connectivity.
- Unauthenticated remote DoS.
- Amplification: on 401 path, BOTH sinks fire in one request — attacker returns a small 401 with a legit `WWW-Authenticate`, then serves a multi-GB body on the token endpoint. If that succeeds, the manifest sink fires next.

_Synthesized during merge normalization from `archon/findings/H2-manifest-token-oom/draft.md`._
