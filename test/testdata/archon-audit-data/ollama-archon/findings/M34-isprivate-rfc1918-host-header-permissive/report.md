## Summary

The host-header filter at `server/routes.go:1625-1629`:

```go
if addr, err := netip.ParseAddr(...); err == nil {
    if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() {
        return true
    }
}
```

allows `IsPrivate()` — meaning a Host header of `10.0.0.1`, `172.16.0.1`, or `192.168.0.1` passes. This is intended to support legitimate LAN-side access when the reverse-proxy rewrites the Host to a private address, but in combination with classical DNS rebinding (where the attacker's domain's A record flips between the attacker IP and an RFC1918 IP pointing at the target Ollama), a browser may issue a request with Host matching the rebind target.

The defender argument is that the RFC1918 check sits INSIDE the "bind is loopback" short-circuit (see p8-060) and that reaching a loopback-bound daemon requires local access — but DNS rebinding was invented specifically to breach this model, and the RFC1918 membership check accepts exactly the kind of fake host header a rebinding attack would use.

## Details

The host-header filter at `server/routes.go:1625-1629`:

```go
if addr, err := netip.ParseAddr(...); err == nil {
    if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() {
        return true
    }
}
```

allows `IsPrivate()` — meaning a Host header of `10.0.0.1`, `172.16.0.1`, or `192.168.0.1` passes. This is intended to support legitimate LAN-side access when the reverse-proxy rewrites the Host to a private address, but in combination with classical DNS rebinding (where the attacker's domain's A record flips between the attacker IP and an RFC1918 IP pointing at the target Ollama), a browser may issue a request with Host matching the rebind target.

The defender argument is that the RFC1918 check sits INSIDE the "bind is loopback" short-circuit (see p8-060) and that reaching a loopback-bound daemon requires local access — but DNS rebinding was invented specifically to breach this model, and the RFC1918 membership check accepts exactly the kind of fake host header a rebinding attack would use.

### Location

- `server/routes.go:1625-1629` — `IsPrivate()` branch
- Adjacent: `server/routes.go:1615-1618` — the loopback short-circuit (p8-060)

### Attacker Control

DNS rebinding attacker: controls `evil.example` DNS resolution; resolves first to attacker's public IP (initial JS load), then to `10.0.0.1` on second lookup (resolves to the target's Ollama via the LAN router / NAT loopback).

### Trust Boundary Crossed

B10 (network attacker via rebinding).

### Evidence

Tracer confirmed the branch at `routes.go:1625-1629`. Advocate: "MEDIUM at best — the relevant attack is DNS rebinding where a browser resolves attacker.com to 10.x."

## Root Cause

Validated rationale: `server/routes.go:1625-1629 allowedHostsMiddleware` accepts any Host header whose parsed IP satisfies `netip.Addr.IsPrivate()` (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); inside a loopback-bound deployment, any process already on localhost that needs to bypass the Host filter can pose Host headers such as `10.0.0.1:11434`. Advocate's Pattern-4 argument (same-origin already implied) has merit but misses DNS-rebinding to RFC1918 in scenarios where the attacker-site resolves to 10.x, the browser sends Origin `http://evil.example` with Host `10.0.0.1:11434` (host check passes; CORS preflight is the remaining guard).

Primary cited code reference: `server/routes.go:1625`.

Merge extraction sink line: - `server/routes.go:1625-1629` — `IsPrivate()` branch

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Set up a rebinding DNS server that resolves `rebind.attacker.example` first to attacker's public IP (serves JS), then flips the A record to `10.0.0.1` (or whatever RFC1918 IP the victim's Ollama is reachable at).
2. Victim visits `http://rebind.attacker.example`.
3. JS: `fetch('http://rebind.attacker.example:11434/api/tags')` — second DNS lookup resolves to `10.0.0.1`; browser sends Host: `rebind.attacker.example:11434`.
4. Wait — the Host header is the original DNS name, not the resolved IP. Host: `rebind.attacker.example` would fail the IsPrivate check.
5. Refined exploitation: browser makes request with Host `10.0.0.1:11434` directly (some `fetch` options allow overriding Host; or use `XMLHttpRequest` with manual Host). This bypass is narrower in modern browsers (most refuse to set Host), so the practical attack surface is from non-browser in-LAN clients that craft arbitrary Host headers.

Remediation: remove `IsPrivate()` from the allowed-host check. Require explicit opt-in via `OLLAMA_ORIGINS` or an allowlist to reach a non-loopback-origin-reachable endpoint. Document the change.

## Impact

Lower than p8-060 / p8-061 because CORS preflight blocks JSON-POST drive-by from unknown origins — so the practical reach is:
- Simple-request GETs (CSRF-style side effects).
- Endpoints reached by in-AllowOrigins contexts (browser extensions, Electron apps).

Calibrated MEDIUM. Included as a distinct finding because remediating p8-060 / p8-061 does not automatically fix this (RFC1918 acceptance is a separate branch).

_Synthesized during merge normalization from `archon/findings/M34-isprivate-rfc1918-host-header-permissive/draft.md`._
