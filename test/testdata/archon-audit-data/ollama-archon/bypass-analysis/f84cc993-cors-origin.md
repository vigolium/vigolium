# Bypass Analysis: f84cc993 — CORS Origin Hardcoding

**Cluster ID**: cors-access-control
**Undisclosed tag**: [undisclosed]

## Patch Summary

Commit f84cc993 (Aug 2024) introduced route-group separation: "open" endpoints (chat, generate, embed, show, tags) got `ollama.com` added to their CORS origins, while "restricted" endpoints (delete, push, create, copy, blobs) did NOT receive `ollama.com` — they only got the base `envconfig.Origins()` list.

**However, the current `main` branch has reverted this separation.** The current `GenerateRoutes()` applies a single CORS config and a single `allowedHostsMiddleware` to ALL routes — no route-group distinction exists. The ollama.com origins are also absent from the current default list.

## Current State (main branch)

### Default CORS Origins (envconfig.AllowedOrigins)

Always included regardless of OLLAMA_ORIGINS:
- `http[s]://localhost[:*]`, `http[s]://127.0.0.1[:*]`, `http[s]://0.0.0.0[:*]`
- `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`

OLLAMA_ORIGINS prepends additional origins but does NOT replace defaults. There is no way to restrict the default list — it can only be extended.

### Route Protection

All routes share one CORS policy and one `allowedHostsMiddleware`. Destructive endpoints (`DELETE /api/delete`, `POST /api/push`, `POST /api/create`) have identical CORS and Host restrictions as inference endpoints.

### allowedHostsMiddleware Behavior

This middleware is the primary access control for browser-based requests. It checks the `Host` header (not `Origin`):
1. If the server is NOT listening on loopback — middleware is **skipped entirely** (all hosts allowed).
2. If listening on loopback — allows loopback IPs, private IPs, unspecified addrs, local IPs, and hosts ending in `.localhost`, `.local`, `.internal`, or matching the OS hostname.
3. Rejects everything else with 403.

**Key finding**: CORS `Origin` and `allowedHostsMiddleware` `Host` are independent checks. A cross-origin request from `file://*` will pass CORS (origin allowed) AND pass the Host check (request goes to `localhost:11434`). Both checks pass.

## Bypass Verdict: **bypassable**

### Vector 1: file:// origin reaches all endpoints including destructive ones

`file://*` is in the default CORS allow list. Any local HTML file opened in a browser can make cross-origin requests to `http://localhost:11434/api/delete` and it will pass both:
- CORS check: `file://` origin matches `file://*`
- Host check: request Host is `localhost:11434` which is loopback

**Impact**: A malicious HTML file (e.g., downloaded attachment, local phishing page) can delete models, push models, create models, and exfiltrate inference results. No user interaction beyond opening the file is required.

### Vector 2: OLLAMA_ORIGINS only adds, never restricts

Setting `OLLAMA_ORIGINS` does not remove the dangerous defaults (`file://*`, `app://*`). Users cannot lock down origins — they can only widen the attack surface. This is a design gap, not a bypass per se, but it means there is no mitigation available to security-conscious deployments.

### Vector 3: allowedHostsMiddleware bypassed on non-loopback listeners

When Ollama binds to `0.0.0.0:11434` (common in Docker/remote setups via `OLLAMA_HOST=0.0.0.0`), `allowedHostsMiddleware` is entirely skipped. In this configuration, any website can reach all endpoints if it can guess or enumerate the origin (CORS still applies, but `0.0.0.0` with wildcard port is in the default list).

### Vector 4: Reverted route-group separation

The commit f84cc993 attempted to separate open vs restricted routes with different CORS policies. The current codebase has collapsed this back into a single policy. The protective separation no longer exists, meaning even if ollama.com were re-added, it would reach destructive endpoints too.

## Evidence

- `/private/tmp/ollama/envconfig/config.go:86-109` — `AllowedOrigins()` always includes `file://*` and localhost wildcards
- `/private/tmp/ollama/server/routes.go:1638-1714` — single CORS config for all routes, no group separation
- `/private/tmp/ollama/server/routes.go:1600-1636` — `allowedHostsMiddleware` skips check when server addr is non-loopback
