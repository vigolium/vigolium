# [M12] Oauth Scope Description Xss Default Sanitize False

## Summary

1. `src/services/AcmeNormalizedOptions.ts:317` — `this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec)` → defaults to `false` (per H-00-A root cause).
2. `[REDACTED].tsx:59` — `<Markdown inline={true} source={flow.scopes[scope]}/>` — OAuth flow scope description string from `spec.components.securitySchemes.*.flows.*.scopes`.
3. `[REDACTED].tsx:63` — `<Markdown source={scheme.description}/>` — security scheme description.
4. Both reach `[REDACTED].tsx:16` → `sanitize(false, html)` returns raw HTML → `:31` `dangerouslySetInnerHTML`.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Firm (code-traced, PoC theoretical)
- **Vulnerability Type**: XSS
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Intent-Verdict**: intentional-design
- **Triage-Priority**: skip

## Impact

See draft.md for full impact analysis on `[REDACTED].tsx:59`.

## Affected Component

- **File**: `[REDACTED].tsx:59`
- **Source**: spec.components.securitySchemes.*.flows.*.scopes.<name> (scope description string) | spec.components.securitySchemes.*.description
- **Sink**: [REDACTED].tsx:31 (dangerouslySetInnerHTML) reached via OAuthFlow.tsx:59 (<Markdown inline={true} source={flow.scopes[scope]}/>) and SecurityRequirement.tsx:63 (<Markdown source={scheme.description}/>)
- **Chamber**: chamber-01

## Source to Sink Flow

1. `src/services/AcmeNormalizedOptions.ts:317` — `this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec)` → defaults to `false` (per H-00-A root cause).
2. `[REDACTED].tsx:59` — `<Markdown inline={true} source={flow.scopes[scope]}/>` — OAuth flow scope description string from `spec.components.securitySchemes.*.flows.*.scopes`.
3. `[REDACTED].tsx:63` — `<Markdown source={scheme.description}/>` — security scheme description.
4. Both reach `[REDACTED].tsx:16` → `sanitize(false, html)` returns raw HTML → `:31` `dangerouslySetInnerHTML`.

## Vulnerable Code

See `[REDACTED].tsx:59` and draft.md for code excerpts.

## Proof of concept & Evidence

No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/config.md:77-80`. Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS.". Sub-finding of H-00-A sharing same root cause/sink; scope-description XSS limited to spec-render context; remediation covered by parent finding

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

- Default Acme configuration.
- Spec contains a `securitySchemes` block with attacker-controlled `description` or scope-name → description map.

## Remediation

Adopt the H-00-A remediation (change `sanitize` default to `true`, or warn loudly when default is active with a fetched-spec URL). No additional per-site fix is required if H-00-A is remediated.
