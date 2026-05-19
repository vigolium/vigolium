---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/utils/loadAndBundleSpec.ts:22-24 `if (IS_BROWSER) { config.resolve.http.customFetch = global.fetch; }` with no wrapper; :37 `await bundle(bundleOpts)` consumes it; bundler walks every absolute `$ref` URL.
FP-Reasoning: Source matches the draft exactly — `global.fetch` is assigned without any URL filter, scheme allowlist, or canonicalization, and passed to `@acmely/openapi-core`'s `bundle()`. The KB's Architecture Model and Attack Surface tables both explicitly call this out as the canonical `ssrf-fetch` sink ("`customFetch` invocations from `@acmely/openapi-core` ... no allow-list, no per-host limit, no scheme restriction"). Default config is exploitable; browser SOP only bounds response read-out, not the request emission.
Severity-Original: HIGH
Severity-Tracer: HIGH
Severity-Advocate: HIGH (with CORS caveat for browser path)
Class: SSRF / Bundler-Side
Origin-Finding: PH-01
Origin-Pattern: PATT-007
File: src/utils/loadAndBundleSpec.ts:22-24
Chamber: chamber-02
Source: any absolute-URL `$ref` value in attacker-supplied or attacker-influenced spec
Sink: `global.fetch(url)` via `config.resolve.http.customFetch` consumed by `@acmely/openapi-core` bundler
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: Node/SSR path yields full read-out SSRF unconditionally; browser path blind SSRF always; requires attacker-influenced spec input (moderate precondition).
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
PoC-Notes: Node path confirmed. bundle() -> BaseResolver -> readFileFromUrl() -> node-fetch(url) with no URL filtering. Mock internal server received GET /latest/meta-data/iam/security-credentials/ec2-default. Full read-out SSRF: attacker $ref fetched unconditionally, response inlineable into bundled spec. Browser path also vulnerable (global.fetch assigned without wrapper). Evidence in archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/evidence/.
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
---

# SSRF via Unrestricted `$ref` Fetch in `loadAndBundleSpec` — No Scheme/Host Allow-List

## Summary

`src/utils/loadAndBundleSpec.ts:22-24` wires the browser's `global.fetch` directly as the bundler's `customFetch` with no scheme allow-list, no host allow-list, and no URL canonicalization step. Every absolute-URL `$ref` in the parsed spec is fetched by the bundler with the visitor's network identity (browser path) or the host process's network identity (Node/SSR path). This is the canonical SSRF sink for the `$ref` resolution pipeline.

## Location

- `src/utils/loadAndBundleSpec.ts:22-24` — `if (IS_BROWSER) { config.resolve.http.customFetch = global.fetch; }` — direct assignment, no wrapper.
- `src/utils/loadAndBundleSpec.ts:37` — `await bundle(bundleOpts)` — bundler walks every `$ref` and calls `customFetch(url)` per absolute URL.

## Attacker Control

Full URL string. Any `$ref` value in any schema, parameter, response, example, callback, or webhook can be `"https://internal.corp/admin/action"`, `"http://169.254.169.254/latest/meta-data/"`, or `"file:///etc/passwd"` (Node path).

## Trust Boundary Crossed

- **Browser path**: attacker spec → visitor's intranet (any same-origin or CORS-open endpoint reachable from the visitor's browser).
- **Node/SSR path**: attacker spec → server-side network (no CORS at all — full SSRF including loopback, link-local, cloud metadata, internal services).

## Impact

- **Browser path (HIGH where intranet CORS is open)**: blind SSRF always (request reaches target regardless of CORS); read-out SSRF when CORS permits (same-origin, CORS-open intranet APIs, CORS-open cloud-metadata services). Side-channels: timing, error vs success.
- **Node/SSR path (HIGH unconditionally)**: full read-out SSRF, including cloud metadata exfiltration, internal admin endpoint hits, port scanning.

## Defense Search Results (Advocate)

- No `SECURITY.md` exists in repo (`Glob /SECURITY*` → none).
- `README.md` contains no `trusted`/`untrusted`/`threat model`/`security` strings — no documented "specs must come from trusted source" doctrine.
- The sole browser-path guard is the SAME-ORIGIN POLICY enforced by the user-agent (CORS). This is bypassable for the cases enumerated under "Browser path" above.
- The Node-path has NO guard.
- No URL canonicalization, no scheme allow-list, no `customFetch` wrapper in this repo.

## Evidence

```typescript
// src/utils/loadAndBundleSpec.ts:22-24
if (IS_BROWSER) {
  config.resolve.http.customFetch = global.fetch;
}
```

```typescript
// src/utils/loadAndBundleSpec.ts:37
await bundle(bundleOpts);
```

## Reproduction Steps

1. Author a spec with `$ref: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"` referenced from any schema.
2. Load the spec via `Acme.init(specUrl)` from a context where 169.254.169.254 is reachable (cloud-hosted docs portal, internal jump host).
3. The bundler issues `fetch("http://169.254.169.254/latest/meta-data/...")`.
4. If CORS permits (same-origin proxy or CORS-open metadata), response body is inlined into the bundled spec and rendered.

## Pairs With

- `p10-022` (PH-08): `<acme spec-url="…">` HTML-attribute entry point uses the same sink.
- `p10-020` (H-01): `examples[].externalValue` uses a SEPARATE bare `fetch()` that ALSO bypasses any `customFetch` wrapper a defender might install at this layer.

## Distinguishing from p10-020

p10-020 is a customFetch-BYPASS variant in `Example.ts:41` — a SECOND independent SSRF sink. This finding (p10-029) is the primary `customFetch` sink in `loadAndBundleSpec`.
