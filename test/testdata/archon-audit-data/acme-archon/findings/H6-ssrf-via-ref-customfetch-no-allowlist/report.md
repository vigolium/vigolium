# [H6] Ssrf Via Ref Customfetch No Allowlist

## Summary

`src/utils/loadAndBundleSpec.ts:22-24` wires the browser's `global.fetch` directly as the bundler's `customFetch` with no scheme allow-list, no host allow-list, and no URL canonicalization step. Every absolute-URL `$ref` in the parsed spec is fetched by the bundler with the visitor's network identity (browser path) or the host process's network identity (Node/SSR path). This is the canonical SSRF sink for the `$ref` resolution pipeline.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: SSRF / Bundler-Side
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P1

## Impact

- **Browser path (HIGH where intranet CORS is open)**: blind SSRF always (request reaches target regardless of CORS); read-out SSRF when CORS permits (same-origin, CORS-open intranet APIs, CORS-open cloud-metadata services). Side-channels: timing, error vs success.
- **Node/SSR path (HIGH unconditionally)**: full read-out SSRF, including cloud metadata exfiltration, internal admin endpoint hits, port scanning.

## Affected Component

- **File**: `src/utils/loadAndBundleSpec.ts:22-24`
- **Source**: any absolute-URL `$ref` value in attacker-supplied or attacker-influenced spec
- **Sink**: `global.fetch(url)` via `config.resolve.http.customFetch` consumed by `@acmely/openapi-core` bundler
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/utils/loadAndBundleSpec.ts:22-24`. See draft.md for the full trace.

## Vulnerable Code

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

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
[poc] Internal service listening at http://127.0.0.1:19254/latest/meta-data/iam/security-credentials/ec2-default
[poc] Building attacker-controlled spec with $ref: "http://127.0.0.1:19254/latest/meta-data/iam/security-credentials/ec2-default"
[internal-server] INCOMING REQUEST: GET /latest/meta-data/iam/security-credentials/ec2-default
[internal-server] From: 127.0.0.1:19254

=== SSRF Evidence ===
[poc] Internal server received request: GET /latest/meta-data/iam/security-credentials/ec2-default
[poc] Request time: 2026-05-19T01:33:49.385Z
{"status":"confirmed","evidence":"internal-server received GET /latest/meta-data/iam/security-credentials/ec2-default — HTTP request emitted to attacker-specified $ref URL with no allow-list check","notes":"Node path: loadAndBundleSpec -> bundle() -> BaseResolver -> readFileFromUrl() -> node-fetch(url) with no scheme/host filter. Browser path additionally sets config.resolve.http.customFetch = global.fetch with the same absence of filtering."}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: http
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/utils/loadAndBundleSpec.ts:22-24`.
Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-19T04:04:18Z
Confirm-Evidence: archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/confirm-evidence
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: internal-server received GET /latest/meta-data/iam/security-credentials/ec2-default — HTTP request emitted to attacker-specified $ref URL with no allow-list check
