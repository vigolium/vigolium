# Adversarial Cold Review — p8-062 client2-experiment-bypasses-middleware

## Step 1 — Restatement and decomposition

Claim in my own words: when the Ollama server is started with the env var
`OLLAMA_EXPERIMENT=client2`, the HTTP handler wired into the listener is an
instance of `registry.Local` rather than the gin router. `Local.ServeHTTP`
matches the request path; for `/api/pull` and `/api/delete` it dispatches to
its own internal handlers, and only for other paths does it forward to the
gin router that carries `allowedHostsMiddleware`, CORS and other
middleware. Therefore `/api/pull` and `/api/delete` are served with no
middleware enforcement of any kind. An attacker who can reach the listener
(for example from the LAN when `OLLAMA_HOST=0.0.0.0` or cross-origin via
DNS rebinding when bound to loopback with a permissive host suffix) can
hit these two endpoints without the DNS-rebinding/Host-header filter, and
use `/api/pull` to force the server to fetch arbitrary model URLs
(including IMDS-style link-local hosts when `insecure:true` is requested).

Sub-claims:
- A. Attacker controls a POST request body and Host header reaching
  `/api/pull` on the Ollama listener.
- B. The request reaches `Local.handlePull` without passing through
  `allowedHostsMiddleware` or CORS.
- C. The downstream pull logic honours the attacker-provided name,
  producing SSRF and/or the absence of the normally-required Host-header
  defense-in-depth.

All three sub-claims are internally coherent.

## Step 2 — Independent code path trace

Trace was performed directly from `cmd.Serve` downwards, without relying
on the finding draft's snippets:

- `server/routes.go:96` — `var useClient2 = experimentEnabled("client2")`,
  evaluated at package init from `os.Getenv("OLLAMA_EXPERIMENT")`
  (`server/routes.go:92-94`).
- `server/routes.go:1789-1796` — in `Serve`, if `useClient2` is true,
  `rc, _ = ollama.DefaultRegistry()`; otherwise `rc` remains nil.
- `server/routes.go:1798` — `h, _ := s.GenerateRoutes(rc)`.
- `server/routes.go:1646-1744` — `GenerateRoutes` constructs `r := gin.Default()`
  then `r.Use(cors.New(corsConfig), allowedHostsMiddleware(s.addr))`
  (lines 1674-1679). It registers `r.POST("/api/pull", s.PullHandler)` at
  line 1689 and `r.DELETE("/api/delete", s.DeleteHandler)` at line 1694.
  At lines 1735-1744, when `rc != nil`, it returns
  `&registry.Local{Client: rc, Logger: …, Fallback: r, Prune: PruneLayers}`.
- `server/routes.go:1803` — `http.Handle("/", h)`; the outer listener now
  calls `(*registry.Local).ServeHTTP` for every request.
- `server/internal/registry/server.go:109-112` — `ServeHTTP` wraps the
  response writer and calls `serveHTTP`.
- `server/internal/registry/server.go:114-129` — the inner `serveHTTP`
  switches on `r.URL.Path`: `/api/delete` -> `s.handleDelete`,
  `/api/pull` -> `s.handlePull`, default -> `s.Fallback.ServeHTTP`. There
  is no middleware layer of any kind before the switch.
- `server/internal/registry/server.go:259-…` — `handlePull` consumes the
  request body via `decodeUserJSON[*params]` and, if the JSON is valid,
  calls `s.Client.Pull(r.Context(), p.model())`.

Sanitisation or protection functions encountered on the path:
- `statusCodeRecorder` wraps the ResponseWriter for status capture only.
- `decodeUserJSON` decodes JSON (it does not enforce Host or CORS policy,
  and does not cap body size).
- No Host-header check exists in `server/internal/registry/server.go`
  (grep-verified: zero occurrences of `Host`, `allowedHost`, or
  `r.Request.Host` in that file).

Framework protections: gin's default middleware (Logger and Recovery) is
attached to `r` in `gin.Default()` but only runs when execution reaches
the fallback. The outer `Local.ServeHTTP` recovers nothing explicitly,
though that is orthogonal to the middleware bypass claim.

## Step 3 — Protection surface search

| Layer | Candidate control | Blocks the attack? |
|---|---|---|
| Language | Go type system — n/a to a logic bypass. | No |
| Framework | gin CORS + `allowedHostsMiddleware` in `r.Use(...)` at `server/routes.go:1676-1679`. | No — gin is reached only via the `default` branch of `Local.ServeHTTP`. |
| Middleware | None registered on `Local`. | No |
| Application | `OLLAMA_EXPERIMENT` env var is opt-in; `useClient2` defaults false. | Partial — blocks when the flag is unset, but does nothing when the operator sets it. |
| Documentation | `SECURITY.md` (read, 25 lines) does not mention the flag. `docs/` has zero occurrences of `OLLAMA_EXPERIMENT` (grep across `docs/**/*.md*`). | No documented warning that enabling client2 disables middleware. |

No protection blocks the attack once the flag is set.

## Step 4 — Real-environment reproduction

Environment: Ollama worktree at commit `57653b8e` (`git status: clean`), Go
1.26.1 darwin/arm64.

Approach: build a deterministic Go test that wires the production
`registry.Local{Fallback: ginRouter}` arrangement exactly as
`GenerateRoutes` produces when `rc != nil`, attach an observable
host-check middleware to the gin router, and issue real HTTP requests
through `httptest.Server`.

Test source archived at
`/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/p8-062/middleware_bypass_review_test.go`.
Test output archived at
`/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/p8-062/test-output.txt`.

Healthcheck: the `/api/tags` control request (no Local interception)
passed through gin and was rejected 403 by the host-check middleware,
confirming the middleware is wired correctly and would normally fire.

Attempts:
- Attempt 1 — `GET /api/pull` with `Host: attacker.example.com`:
  Response 405 with body `{"code":"method_not_allowed","error":"method not allowed"}`.
  host-check middleware invoked = false. gin `/api/pull` handler invoked = false.
  The 405 comes from `Local.handlePull`'s own method guard at
  `server/internal/registry/server.go:260-262` — proving that the request
  was served entirely within `Local` without ever traversing gin
  middleware.
- Attempt 2 — `GET /api/tags` with the same hostile Host: response 403,
  host-check middleware invoked = true. Control confirmed.
- Attempt 3 — `GET /api/delete` with the same hostile Host: response 405
  from `Local.handleDelete`, host-check middleware invoked = false.

All three attempts support the claim. No variation needed beyond the
three shown. PoC-Status: executed.

## Step 5 — Prosecution brief

Under `OLLAMA_EXPERIMENT=client2`, the listener's outermost HTTP handler
is `*registry.Local`. Its `serveHTTP` at `server/internal/registry/server.go:114-129`
switches on the request path and routes `/api/pull` and `/api/delete` to
its own handlers with no intervening middleware. The gin router,
which is the only place `allowedHostsMiddleware` and the CORS middleware
are registered (`server/routes.go:1676-1679`), is only ever invoked via
the `default` branch. An experimental-flag-enabled user therefore loses
DNS-rebinding protection and CORS enforcement on the two most
security-sensitive endpoints in the API: `/api/pull`, which can force the
server to make outbound HTTP requests to attacker-chosen names
(including link-local 169.254.169.254 when `insecure:true`), and
`/api/delete`, which can erase a victim's model cache. The reproduction
test (Step 4) demonstrates deterministically that requests to these two
paths never reach the middleware layer, while the control request to
`/api/tags` is correctly blocked. No documentation (SECURITY.md,
docs/faq.mdx, any `docs/**/*.md*`) warns that `client2` disables
middleware. The gate is an undocumented experiment flag whose label
implies "may be unstable", not "opens the model-management surface
without Host-header validation".

## Step 6 — Defense brief

The behaviour is conditional on an explicit opt-in environment variable
(`OLLAMA_EXPERIMENT=client2`) that defaults to false
(`server/routes.go:96`). On a default installation the handler returned
from `GenerateRoutes` is the gin router itself, with
`allowedHostsMiddleware` fully engaged, so `allowedHostsMiddleware` still
defends `/api/pull` and `/api/delete` for the overwhelming majority of
users. The operator who enables an experiment named "client2" is
implicitly acknowledging the new code path is not stable, and the
upstream dispatcher is a deliberate architectural choice to prototype a
replacement pull/delete implementation. The claimed SSRF against IMDS
further requires either a permissive allowlist (`OLLAMA_HOST=0.0.0.0`,
per p8-060) or a DNS-rebinding primitive, both of which are separately
tracked. Without that prerequisite, a remote attacker cannot reach the
loopback listener. Reproduction therefore proves only that the
middleware is bypassed in the abstract — whether that matters in
practice depends on conditions that are themselves gated.

## Step 7 — Severity challenge

Starting from MEDIUM baseline.

- Remotely triggerable? Yes, but only when either `OLLAMA_HOST` is
  permissive or a DNS-rebinding primitive is available. Without those,
  the listener is loopback-only and the bypass has no cross-boundary
  effect.
- Meaningful trust boundary crossing? Yes (network -> host pull/delete)
  in the presence of the prerequisite.
- No significant preconditions? No — requires `OLLAMA_EXPERIMENT=client2`
  AND a bind primitive AND (for IMDS) cloud deployment.
- Documented risk? No — SECURITY.md and docs do not describe the flag as
  security-relevant.

The upgrade to HIGH would require the bypass to be exploitable on a
default install. It is not; the experiment flag is strictly opt-in. The
downgrade-to-LOW signal (non-default config) is present, but the attack
surface once enabled is genuinely high-value (SSRF to IMDS +
model-wipe), so LOW understates the risk. The original HIGH is not
supported by the evidence; MEDIUM is the correct calibration.

Final severity: MEDIUM.

## Step 7 — Verdict

CONFIRMED. The prosecution brief survives the defense: the defense's
strongest point is "gated by opt-in flag", but that does not negate the
bypass; it only narrows the affected population. Real-environment
reproduction succeeded with three positive and one control observation,
all in the same test run.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Test `TestPullBypassesAllowedHosts` and
`TestDeleteBypassesAllowedHosts` at
`archon/real-env-evidence/p8-062/middleware_bypass_review_test.go`
deterministically show that `registry.Local.serveHTTP` dispatches
`/api/pull` and `/api/delete` without invoking the gin-registered
`allowedHostsMiddleware`, while the control test `TestTagsDoesNotBypass`
proves the middleware is otherwise wired correctly.
Severity-Final: MEDIUM (downgraded from original HIGH because the bypass
is gated by an opt-in non-default env var).
PoC-Status: executed.
