Phase: 8
Sequence: 074
Slug: dns-rebinding-drive-by-identity-chain
Verdict: VALID
Rationale: Chain of p8-061 (`.localhost` auto-resolution) + p8-064 (unauth web_search) + p8-069 (pubkey disclosure via /api/me) produces a drive-by identity theft primitive against any victim running ollama with defaults — from any webpage they visit. Advocate's CORS preflight argument partially mitigates JSON-POST endpoints from arbitrary drive-by origins, but the identity-signing + pubkey disclosure subset of the chain still succeeds via simple-request GETs and in-AllowOrigins contexts (browser extensions, Electron apps, vscode-webview). MEDIUM per Synthesizer rule on CORS mitigation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-3-ambiguous (CORS preflight partially blocks JSON POST drive-by; the chain falls back to simple-request GETs and in-allowlist extensions)
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

Chain of primitives, each individually tracked in a standalone finding, composed into a drive-by remote identity-theft path:

1. **p8-061**: Host `*.localhost` suffix-match + RFC 6761 browser auto-resolve → any webpage the victim visits reaches the local daemon cross-origin without DNS infrastructure.
2. **p8-069**: Unauth `/api/me` returns the victim's ed25519 public key — the attacker learns WHO to target.
3. **p8-064**: Unauth `/api/experimental/web_search` relays attacker queries signed with the victim's ed25519 key → queries billed to the victim, poisoning their history.
4. (Optional amplification) **p8-005 realm downgrade + MITM**: the signed request to ollama.com can be captured when the adversary also controls one outbound hop (hard precondition).

Advocate correctly flagged that CORS preflight blocks JSON-POST drive-by for arbitrary `http://evil.example` Origins. Synthesizer accepts MEDIUM (not CRITICAL) because:

- CORS DOES block plain JSON-POST drive-by to `/api/experimental/web_search` from unknown origins (preflight fails).
- BUT the chain still succeeds when the attacker origin is in `envconfig.AllowedOrigins()`:
  - `app://*` — any Electron app the user launched
  - `file://*` — any local HTML file the user opened
  - `tauri://*` — any Tauri-wrapped app
  - `vscode-webview://*` / `vscode-file://*` — ANY installed VSCode extension
- For the `/api/me` pubkey disclosure step: even simple-request GETs can succeed; the response body may not be readable cross-origin, but an attacker can observe via side channels (timing) or via the above-listed allowed origins.

## Location

See p8-061, p8-064, p8-069 for component details.

## Attacker Control

Any webpage the victim visits (for the DNS-auto-resolve angle) OR any VSCode extension / Electron app (for the CORS-allowed angle).

## Trust Boundary Crossed

B10 (network attacker) + B11 (remote identity / billing side effect).

## Impact

- Drive-by identity disclosure (pubkey + hostname) from any visited page (simple-request or in-allowlist origin).
- Drive-by resource theft (queries billed to victim) from any in-allowlist origin (malicious browser extension, compromised VSCode extension).
- Drive-by history poisoning (victim's search/fetch log on ollama.com attributed to them).

## Evidence

Tracer: "Steps 1-3 (drive-by → unauth proxy → victim key used) are fully reachable." PARTIAL status because "step 4 (key capture) requires MITM." Synthesizer treats steps 1-3 as the main finding.

Advocate: "CORS preflight blocks drive-by JSON POST to /api/experimental/web_search for non-allowed origins; MEDIUM not CRITICAL." Synthesizer adopts MEDIUM.

## Reproduction Steps

**Via malicious VSCode extension (most realistic drive-by):**
1. Attacker publishes a benign-looking VSCode extension (or compromises one).
2. Extension background script: `fetch('http://localhost:11434/api/me', {method:'POST'})` — passes CORS because `vscode-webview://*` is allowed.
3. Response body contains `signin_url` with pubkey.
4. Extension then: `fetch('http://localhost:11434/api/experimental/web_search', {method:'POST', body:JSON.stringify({query:'...', model:'gpt-5'})})` — same CORS pass.

**Via drive-by webpage (limited to simple-request side channel):**
1. Visited page: `<img src="http://evil.localhost:11434/api/me">`.
2. Browser auto-resolves `evil.localhost` → `127.0.0.1`.
3. Daemon accepts Host header (suffix match).
4. Response leaks key in Location / body — browser doesn't expose it to JS, but server-side log poisoning and timing side-channels still cross the trust boundary.

Remediation:
- Tighten allowedHost suffix list (remove `.localhost`, `.local`, `.internal`).
- Add a per-route auth on `/api/me` and `/api/experimental/*`.
- Reject requests whose `Origin` is not in the allowlist even without preflight (i.e., check `Origin` on every request, not only preflight).
