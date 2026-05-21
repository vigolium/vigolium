---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/models/Example.ts:41 calls `fetch(this.externalValueUrl)` with no scheme/host allowlist; URL derived from spec-author-controlled `externalValue` at :23-25; render path Example.tsx:14-15 → exernalExampleHook.ts:20 → Example.ts:32-41 confirmed live in default config.
FP-Reasoning: All cited file:line references match current source exactly. The fetch sink is reached for any spec containing `examples[].externalValue` without any opt-in or flag. No scheme check, no host allowlist, no `customFetch` indirection. Blind SSRF reaches arbitrary destinations (limited only by browser SOP for read-out); the Example.ts path entirely bypasses the `customFetch` wrapper installed at loadAndBundleSpec.ts:23, so it is a structurally distinct SSRF sink from PH-01/PH-08.
Severity-Original: HIGH
Class: SSRF / Read-Out SSRF
Origin-Finding: H-01
Origin-Pattern: PATT-007
File: src/services/models/Example.ts:41
Chamber: chamber-02
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: HIGH severity; spec-author-controlled URL triggers bare fetch() at render time; cloud metadata exfiltration possible with no allowlist or scheme check.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
PoC-Notes: PoC exercises the real ExampleModel class (src/services/models/Example.ts) via ts-node. Global fetch() intercepted before module import; confirmed that ExampleModel.getExternalValue() dispatches bare fetch() to http://169.254.169.254/latest/meta-data/iam/security-credentials/ with no scheme/host validation and returns the response body to the caller. Exit code 0. Evidence in archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/evidence/.
---

# SSRF via `examples[].externalValue` Bare `fetch()` Without URL Allow-List

## Summary

`ExampleModel.getExternalValue()` at `src/services/models/Example.ts:41` calls bare `fetch(this.externalValueUrl)` — a direct browser `fetch` with no scheme check, no host allow-list, and no reuse of the `customFetch` channel configured in `loadAndBundleSpec`. The URL is spec-author-controlled via `examples[X].externalValue`. The response body is returned to the DOM renderer.

## Attack Scenario

A spec author sets:
```yaml
paths:
  /pets:
    get:
      responses:
        '200':
          content:
            application/json:
              examples:
                internalLeak:
                  externalValue: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

When any user expands the `/pets GET` operation and views examples:
1. `ExampleModel` constructor at `:23-25` computes `externalValueUrl = new URL(externalValue, parser.specUrl).href` — no validation.
2. `Example.tsx:14-15` routes to `<ExternalExample>` component when `example.value === undefined && example.externalValueUrl`.
3. `exernalExampleHook.ts:20` calls `example.getExternalValue(mimeType)`.
4. `Example.ts:41` executes `fetch("http://169.254.169.254/latest/meta-data/...")`.
5. Browser sends GET to metadata endpoint; if CORS is open or same-origin, response body is parsed and rendered in the DOM.

## Impact

- **Blind SSRF** (always): request reaches target regardless of CORS policy. Side-channel: timing, error vs success.
- **Read-out SSRF** (when CORS permits or same-origin): full response body exposed in the rendered example panel.
- **Cloud metadata exfiltration**: cloud-hosted documentation portals rendering attacker specs may expose instance metadata.

## Rendering Pipeline Safety

The rendering path does NOT introduce XSS for fetched content:
- JSON MIME: `jsonToHTML` applies `htmlEncode()` — safe.
- Non-JSON MIME: Prism.js `highlight()` escapes HTML — safe.

The exploit is data exfiltration, not code execution.

## Distinguishing from PH-01/PH-08

PH-01 and PH-08 use `customFetch` via `@acmely/openapi-core`'s bundler during spec load. This finding uses a completely independent `fetch()` call in the model layer, triggered at render time (not load time), with a separate module-level cache that is never invalidated.

## Code Evidence

- `src/services/models/Example.ts:5` — module-level cache `externalExamplesCache`
- `src/services/models/Example.ts:23-25` — URL construction from spec field
- `src/services/models/Example.ts:41` — bare `fetch()` call
- `[REDACTED].ts:20` — hook triggers fetch
- `src/components/PayloadSamples/Example.tsx:14-15` — routing to ExternalExample
