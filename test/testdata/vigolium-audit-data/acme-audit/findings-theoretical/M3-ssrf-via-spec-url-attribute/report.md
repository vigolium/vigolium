# [M3] Ssrf Via Spec Url Attribute

## Summary

The standalone web-component `autoInit()` reads the `spec-url` HTML attribute directly and passes it to `loadAndBundleSpec()` with no URL validation. Any platform allowing injection of HTML attributes on the `<acme>` element exposes this SSRF entry point.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Firm (code-traced, PoC theoretical)
- **Vulnerability Type**: SSRF / Browser-Side
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
M3 — SSRF via spec-url Attribute: Impact Evidence
===================================================

VULNERABILITY CLASS : Browser-Side SSRF (no URL validation)
ATTACK PRECONDITION : Attacker can inject/edit the value of the spec-url
                      HTML attribute on a <acme> element (CMS/embed context).
                      No script injection required.

CODE PATH (confirmed by poc.js static trace):
  1. standalone.tsx:107
       const specUrl = element.getAttribute('spec-url');
       — attacker-controlled value read verbatim from HTML attribute

  2. standalone.tsx:108-109
       if (specUrl) {
         init(specUrl, {}, element);
       }
       — only truthy check; no scheme/host validation

  3. loadAndBundleSpec.ts:22-23
       if (IS_BROWSER) {
         config.resolve.http.customFetch = global.fetch;
       }
       — browser's ambient fetch() assigned as transport, inheriting
         cookies, same-site credentials, and local-network access

  4. loadAndBundleSpec.ts:37
       const { bundle: { parsed } } = await bundle(bundleOpts);
       — @acmely/openapi-core issues fetch(specUrl) using customFetch
         with NO URL validation layer

ATTACKER GAIN:
  - Blind SSRF: GET request is sent to any URL the attacker specifies,
    including http://169.254.169.254/latest/meta-data/ (EC2 IMDS),
    http://[REDACTED]/ (internal network hosts), file:// URIs (where supported).
  - Response read-back requires CORS cooperation (CORS-gated side-channel),
    but timing
…(truncated)

```

## Affected Component

- **File**: `src/standalone.tsx:107`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/standalone.tsx:107`. See draft.md for the full trace.

## Vulnerable Code

- `src/standalone.tsx:107` — attribute read without validation
- `src/standalone.tsx:109` — direct pass to `init()`
- `src/utils/loadAndBundleSpec.ts:22-24` — unguarded `customFetch`

## Proof of concept & Evidence

No live execution evidence — static code-path tracer confirmed the vulnerable flow without dynamic execution. PoC requires a pre-built browser bundle or live environment. See `evidence/` for the tracer script and log.

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: http
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/standalone.tsx:107`.
