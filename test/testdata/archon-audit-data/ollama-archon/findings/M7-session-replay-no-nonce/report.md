## Summary

`api/client.go do()` constructs the signing challenge as `method + "," + path + "?ts=" + now` — purely client-side, no server-supplied nonce. The server verifier (when `OLLAMA_AUTH=1`) must accept a timestamp window to tolerate clock skew and network latency. Any network observer or MITM who captures an `Authorization: <pubkey>:<sig>` header of a signed request can replay the same header within the tolerance window against any endpoint accepting the same `method+path+ts` tuple.

Properly-designed challenge-response schemes require a server-generated nonce (e.g., in the 401 response's WWW-Authenticate header) that the client incorporates into the signed material — making every signature bound to a specific server-issued challenge and therefore non-replayable.

## Details

`api/client.go do()` constructs the signing challenge as `method + "," + path + "?ts=" + now` — purely client-side, no server-supplied nonce. The server verifier (when `OLLAMA_AUTH=1`) must accept a timestamp window to tolerate clock skew and network latency. Any network observer or MITM who captures an `Authorization: <pubkey>:<sig>` header of a signed request can replay the same header within the tolerance window against any endpoint accepting the same `method+path+ts` tuple.

Properly-designed challenge-response schemes require a server-generated nonce (e.g., in the 401 response's WWW-Authenticate header) that the client incorporates into the signed material — making every signature bound to a specific server-issued challenge and therefore non-replayable.

### Location

- `api/client.go` — `do()` method; challenge construction at `fmt.Sprintf("%s,%s?ts=%s", method, path, now)` (exact line varies by HEAD; grep for `%s,%s?ts=`).

### Attacker Control

Network observer or MITM on the request path. `OLLAMA_AUTH=1` must be enabled by the operator (non-default).

### Trust Boundary Crossed

Network observation → authenticated API operation.

### Evidence

Per Deep Probe PH-A-21 round-3-hypotheses:
```go
// api/client.go:do() (snippet, line number HEAD-dependent)
chal := fmt.Sprintf("%s,%s?ts=%s", method, path, now)
```
Contrast with `server/auth.go:32-48 registryChallenge.URL()`:
```go
values.Add("ts", strconv.FormatInt(time.Now().Unix(), 10))
nonce, err := auth.NewNonce(rand.Reader, 16)
values.Add("nonce", nonce)
```
The registry path adds a nonce; the API client path does not. The server-side API verifier must reconstruct identical `chal` without a nonce to match.

## Root Cause

Validated rationale: api/client.go constructs signing challenge as method+path+ts with no server-supplied nonce; captured Authorization headers replay within timestamp tolerance — Advocate concurred as design gap, gated by non-default OLLAMA_AUTH=1.

Primary cited code reference: `server/auth.go:32`.

Merge extraction sink line: Contrast with `server/auth.go:32-48 registryChallenge.URL()`:

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Enable `OLLAMA_AUTH=1` on a test server.
2. MITM a signed `POST /api/generate` request; capture the `Authorization` header.
3. Within N seconds (the tolerance window), resend the exact request to the same server — accepted.
4. To test a different endpoint: find another route that accepts the same signature format (requires trial).

Debate context: Advocate confirmed as design gap with limited realistic impact due to OLLAMA_AUTH being opt-in. Fix: add server-issued nonce challenge to the auth protocol (requires both client and server change).

## Impact

- Replay of authenticated requests (`POST /api/delete`, `POST /api/push`, `POST /api/create`) within the timestamp tolerance window.
- If the window is wide (multi-minute), attackers can accumulate captured headers and replay opportunistically.
- Does not compromise the private key itself.

_Synthesized during merge normalization from `archon/findings/M7-session-replay-no-nonce/draft.md`._
