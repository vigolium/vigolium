Adversarial cold-verification review of p8-060

## Step 1 — Restatement and decomposition

Claim: Ollama's `allowedHostsMiddleware` contains an early-return that waives all host-header / DNS-rebinding checks whenever the socket is not bound to a loopback address. Consequence: setting `OLLAMA_HOST=0.0.0.0` (documented LAN-exposure knob) leaves every API route reachable from LAN with any Host header, no auth, no CORS filtering for non-browser clients.

Sub-claims:
- A. Attacker (LAN peer) can send HTTP requests with arbitrary Host header.
- B. When the server is bound to a non-loopback socket address, the middleware calls `c.Next()` without consulting the request's Host header.
- C. The resulting unauthenticated reach includes sensitive endpoints (/api/me, /api/pull, /api/generate, experimental web_search/web_fetch).

All sub-claims coherent.

## Step 2 — Independent code-path trace

Entry:
- `cmd/cmd.go:1827` — `ln, err := net.Listen("tcp", envconfig.Host().Host)`. `envconfig.Host()` returns `url.URL{Host: "0.0.0.0:11434"}` when `OLLAMA_HOST=0.0.0.0` is set (`envconfig/config.go:22-60`).
- `server/routes.go:1784` — `s := &Server{addr: ln.Addr()}`. `ln.Addr().String()` = `"0.0.0.0:11434"`.
- `server/routes.go:1678` — `allowedHostsMiddleware(s.addr)` registered on gin engine.
- `server/routes.go:1608-1644` — middleware body:
  - Line 1615 — `if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() { c.Next(); return }`.
  - `netip.ParseAddrPort("0.0.0.0:11434")` succeeds; `Addr()` is the IPv4 unspecified address; `IsLoopback()` returns false.
  - Branch taken: immediate `c.Next()`. The remainder (lines 1620-1642: Host split, private-IP check, `allowedHost` suffix allowlist, terminal `AbortWithStatus(403)`) never executes.
- Routes 1682-1733 register unauthenticated handlers including `/api/me`, `/api/pull`, `/api/generate`, `/api/experimental/web_search`, `/api/experimental/web_fetch`.

No validation or sanitization intervenes. The only two middlewares in the chain are `cors.New(corsConfig)` and `allowedHostsMiddleware` (`routes.go:1676-1679`). CORS does not enforce anything on requests without an `Origin` header.

## Step 3 — Protection-surface search

| Layer | Finding |
|---|---|
| Language (Go) | No bounds / type protection relevant here. |
| Framework (gin) | Default gin router; no auth middleware registered globally. CORS is the other middleware; it rejects cross-origin *browser* requests only when Origin header is present. curl/python/electron clients send no Origin and are not filtered. |
| Middleware | `allowedHostsMiddleware` itself — short-circuited as described. No other host-header or DNS-rebinding filter exists. |
| Application | Individual handlers do not re-check Host; `/api/tags`, `/api/generate`, `/api/me`, `/api/pull`, etc. read body + process directly. |
| Auth | No LAN-client authentication. `auth.GetPublicKey()` is used for signing *upstream* ollama.com calls, not for verifying LAN callers. |
| Documentation | `docs/faq.mdx:183-187` says "Change the bind address with the `OLLAMA_HOST` environment variable" with no warning about disabling DNS-rebinding protection. No `SECURITY.md` entry accepting this behavior. |

No blocking protection was found. The short-circuit is by-design per git history (`fc8c0445`, `5c143af7`), but the design decision's security consequence is not documented.

## Step 4 — Real-environment reproduction

Environment: local macOS, Go 1.26.1, built `./ollama` from HEAD at commit 57653b8e.

Healthcheck:
- `GET /api/version` → 200 (server functional).

Attack with OLLAMA_HOST=0.0.0.0:21437:
- `POST /api/me` with `Host: evil.attacker.example`, empty JSON body → HTTP 401 with body containing `signin_url` whose `key=` query parameter is the base64 of the victim's real `ssh-ed25519 …` public key. The 401 comes from the *handler* (not signed in to ollama.com); the host filter never fired.
- `GET /api/tags` with `Host: evil.attacker.example` → 200 `{"models":[]}`.
- `POST /api/generate` with `Host: evil.attacker.example` → 404 `{"error":"model 'x' not found"}` — handler reached and executed.

Control with OLLAMA_HOST=127.0.0.1:21438:
- Same requests with spoofed Host → 403 (middleware blocks, as designed).
- Legitimate `Host: 127.0.0.1:21438` → 200 (baseline works).

Delta between runs is exactly the short-circuit at `server/routes.go:1615-1618`.

Evidence stored: `archon/real-env-evidence/ollama-host-nonloopback-shortcircuits-allowedhosts/` (5 curl outputs + README).

Unit-test reproduction (isolated): `/tmp/cold-verify-shortcircuit/main_test.go` replays the middleware in isolation across 4 bind/host combinations — PASS for all, confirming branch logic.

## Step 5 — Prosecution brief

The code at `server/routes.go:1615-1618` unconditionally waives Host-header validation when `addr.Addr().IsLoopback()` is false. This is triggered by the documented LAN-exposure configuration `OLLAMA_HOST=0.0.0.0` (faq.mdx:185). Reproduction against HEAD confirms:

1. With `OLLAMA_HOST=0.0.0.0`, a LAN client can POST `/api/me` with `Host: evil.attacker.example` and receive the victim's ssh-ed25519 public key (base64 encoded in signin_url).
2. `/api/tags` returns the local model list without authentication.
3. `/api/generate`, `/api/pull`, `/api/experimental/web_{search,fetch}` are reachable.

No authentication, no CORS (non-browser clients), no rate limit, no Host allowlist. This opens the daemon's entire API to any LAN peer. Sensitive downstream effects (SSRF via /api/pull, quota-abuse via /api/experimental/web_search signed with victim's key, unauthenticated inference DoS) compound from this single attack surface. The short-circuit is not merely theoretical: the middleware's remaining 22 lines are dead code under non-loopback bind.

## Step 6 — Defense brief

The short-circuit is deliberate, not a bug:

1. Default bind is `127.0.0.1:11434` (`envconfig/config.go:22`); user must explicitly opt into network exposure by setting `OLLAMA_HOST`.
2. Git history (`fc8c0445` added the middleware in response to CVE-2024-28224; `5c143af7` generalized the non-loopback short-circuit) shows the decision is explicit: when the user has chosen to expose Ollama, the rebinding filter (designed for browser victims attacking loopback) is no longer relevant.
3. DNS-rebinding is a browser-specific attack; browser CORS would block cross-origin reads of the API for most endpoints regardless. Non-browser LAN clients don't need to rebind — they can connect directly to the advertised IP anyway.
4. `/api/me` returns a *public* key, not a secret. SSH public keys are publishable by definition.
5. LAN exposure is the user's conscious decision. The service cannot discriminate between "LAN peer I trust" and "LAN peer I don't" without adding authentication, which is a separate design decision (and a common hardening request). This is a missing feature, not a security bug.
6. The finding draft itself notes: "exploitation requires user to bind 0.0.0.0 — a documented but security-weakening configuration." That is classic user-config-hardening territory.

## Step 7 — Severity challenge

Start at MEDIUM.

- Remotely triggerable: yes, but only within the LAN to which the user has deliberately exposed Ollama.
- Trust boundary: yes, LAN-peer → local-daemon. But crossing it is the *purpose* of `OLLAMA_HOST=0.0.0.0`; the defect is the loss of the host-header filter, not the opening of the port.
- Preconditions: user must opt into LAN exposure with a documented env var. Not default.
- Internet-facing: only if user's firewall/NAT allows; not by default.

Downgrade signals present:
- Requires non-default config (opt-in to 0.0.0.0).
- Attack surface precondition documented.
- Public-key disclosure is informational.

Upgrade signals absent:
- No unauthenticated RCE from this finding alone.
- Downstream compounding attacks (SSRF, quota abuse) are separately tracked findings and don't inherit severity here.

Challenged severity: MEDIUM. This is lower than the draft's HIGH; the lower wins per Step-6 rule.

## Step 8 — Verdict

Prosecution survives: the code path, sub-claims, and reproduction all hold exactly as described. No protection blocks the claim. Reproduction executed successfully in a real environment with evidence captured.

Defense brief argues "by-design" but does not provide a protection that blocks the attack; it contests severity/framing, not technical truth.

Verdict: CONFIRMED. Severity-Final: MEDIUM. PoC-Status: executed.
