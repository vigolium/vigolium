Phase: 8
Sequence: 060
Slug: ollama-host-nonloopback-shortcircuits-allowedhosts
Verdict: VALID
Rationale: `server/routes.go:1615-1618` short-circuits `allowedHostsMiddleware` whenever `addr.Addr().IsLoopback()` is false — so `OLLAMA_HOST=0.0.0.0` (the documented way to expose Ollama on a LAN) disables the entire DNS-rebinding + host-header filter while CORS and auth remain the only guards. Advocate argues this is intended-by-docs and CORS still blocks browser drive-by, but the net effect on non-browser LAN attackers (curl, Electron, extensions, VSCode webview) is a permanent unauthenticated surface to `/api/me`, `/api/pull`, `/api/experimental/web_{search,fetch}`, `/api/generate` et al.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: check-5-ambiguous (exploitation requires user to bind 0.0.0.0 — a documented but security-weakening configuration with no inline warning)
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

The `allowedHostsMiddleware` in `server/routes.go:1608-1644` implements a host-header + DNS-rebinding filter (the documented response to CVE-2024-28224). At line 1615, it performs a short-circuit test:

```go
if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() {
    c.Next()
    return
}
```

When `OLLAMA_HOST=0.0.0.0:11434` (the documented way to expose Ollama for Docker, WSL2, and multi-host deployments — `docs/faq.mdx:185`), `addr.Addr()` is the unspecified address and `IsLoopback()` returns false. Control falls through to `c.Next()` and every subsequent check (the suffix allowlist, the `isLocalIP` check, the terminal `c.AbortWithStatus(403)`) is skipped entirely. The rest of the middleware body is dead code under this bind.

Every route registered afterwards — including the unauthenticated `/api/experimental/web_search`, `/api/experimental/web_fetch`, `/api/me`, `/api/pull`, `/api/generate` — becomes reachable by any LAN client with any Host header, with no host-header filter and no DNS-rebinding protection. Non-browser clients (curl, python, ollama-desktop, vscode) never trigger gin's CORS path, so CORS is not a defense for them. The only remaining guard is the default (opt-in, deployment-dependent) OS firewall or reverse proxy.

## Location

- `server/routes.go:1608-1644` — `allowedHostsMiddleware`
- `server/routes.go:1615-1618` — short-circuit on non-loopback bind
- `envconfig/config.go:20-60` — `Host()` default `127.0.0.1:11434` (so this is a post-opt-in state)
- `docs/faq.mdx:185-191` — documents `OLLAMA_HOST=0.0.0.0` as the supported way to expose Ollama

## Attacker Control

Any LAN or internet-reachable attacker (depending on how the user exposed the port), sending HTTP requests directly. No authentication required.

## Trust Boundary Crossed

Network (B10) → local-daemon trust. The daemon's entire design assumes "loopback-bound = only local trusted user can reach me" — binding 0.0.0.0 is supposed to extend that trust to LAN peers, but the middleware also waives every subsequent filter, leaving auth as the zero remaining defense.

## Impact

- Unauthenticated LAN access to:
  - `POST /api/experimental/web_search` / `web_fetch` — proxy queries signed with the victim's ed25519 key, billed to the victim's ollama.com account (see finding p8-064).
  - `POST /api/me` — ed25519 public-key disclosure (finding p8-062).
  - `POST /api/pull` — SSRF to IMDS / link-local (already finding p8-002; amplified by remote reachability here).
  - `POST /api/generate` / `/api/chat` — unauthenticated inference, quota abuse, local model disclosure.
- Each unbounded body sink (p8-003, p8-063) becomes remote-DoS instead of local-only.

## Evidence

Tracer confirmed on HEAD (`57653b8e`): line 1615's unconditional `c.Next()` is the first branch taken whenever the bind is non-loopback. Every route registered at lines 1689-1744 is reachable.

Advocate defense brief (H-00.08): "the short-circuit is BY DESIGN — if the user chose to expose, stop filtering Host header." Synthesizer accepts the design intent argument but records the material security consequence: docs at `docs/faq.mdx:185-191` never warn that binding 0.0.0.0 also disables rebinding defense; the user sees a network-exposure knob without the security-flag side-effect.

## Reproduction Steps

1. Start ollama with `OLLAMA_HOST=0.0.0.0:11434 ollama serve`.
2. From a LAN peer, issue `curl -s http://<ollama-host>:11434/api/me -d '{}' -H 'Host: anything.example'`.
3. Response includes the victim's ed25519 public key in `signin_url` — the host-filter never ran.
4. Repeat the same against `/api/pull`, `/api/experimental/web_search`, `/api/generate` — all reachable.

Remediation: on non-loopback bind, keep the host check active but swap the default allowlist to `[<OLLAMA_HOST value>]` (opt-out by user-configured allowlist), add a boot-time warning banner ("OLLAMA_HOST=0.0.0.0 exposes this daemon to every LAN client; DNS-rebinding protection has been disabled"), and document the net security change in `docs/faq.mdx:185`.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Reproduced end-to-end against HEAD `57653b8e` with OLLAMA_HOST=0.0.0.0 — spoofed `Host: evil.attacker.example` succeeded on `/api/me` (leaking ed25519 public key), `/api/tags`, and reached `/api/generate`, while the 127.0.0.1-bound control returned 403 for the same requests, confirming the short-circuit at `server/routes.go:1615-1618` is the sole gate.
Severity-Final: MEDIUM
PoC-Status: executed
