---
ID: H-00-B
Verdict: VALID
Severity-Original: HIGH
Class: XSS
File: [REDACTED].tsx:16
Source: spec description fields rendered through marked → dompurify.sanitize(html) with no config
Sink: [REDACTED].tsx:31 (dangerouslySetInnerHTML after bare-config DOMPurify pass)
Chamber: chamber-01
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: XSS via outdated DOMPurify only on non-default sanitize:true deployments; 3 advisories apply to bare config but PoC translation unconfirmed
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: HIGH severity is conditional on a runtime PoC against the bare default-config DOMPurify 3.2.4 call; without PoC fall back to MEDIUM. Only 3 of 7 advisories (h8r8, v8jm, v2wj) apply to default-config calls; the 3 HIGH-severity advisories (crv5, v9jr, h7mw) require non-default config Acme does not use. Headline GHSA-h8r8 mXSS requires re-contextualization (rawtext parent), and Acme assigns into a generic <div>; published PoC does not translate one-to-one.
Debate: archon/chamber-workspace/chamber-01/debate.md
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
PoC-Notes: GHSA-h8r8-wccr-v5f2 bypass confirmed: DOMPurify 3.2.4 (default config, jsdom window) preserves onerror handler and raw </xmp> sequence in sanitized output. Re-contextualization test (innerHTML of xmp wrapper) yields img[onerror] in parsed DOM — handler fires. DOMPurify 3.3.2 produces clean <img src="x"> for same payload (no onerror, no </xmp>). Exploit requires sanitize:true AND a raw-text re-contextualization step (SSR template, xmp/noscript wrapping). String-level bypass (onerror in sanitized output) confirmed without re-contextualization. Evidence in archon/findings/H2-dompurify-outdated-mxss/evidence/exploit.log.
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

# p5-002 — DOMPurify 3.2.4 unpatched against 7 active advisories (mXSS bypass when sanitize=true)

**Severity**: High
**CWE**: CWE-79 (XSS via sanitizer bypass)
**CVSS estimate**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N) — requires sanitize=true deployment
**DFD Slice**: spec-markdown-to-dangerouslySetInnerHTML (sanitize=true path)
**Phase**: D5 — Code Scan

## Finding Summary

Acme installs DOMPurify `^3.2.4` (resolved exactly to 3.2.4 in the lockfile). This version is
unpatched against 7 active advisories requiring upgrade to 3.3.2 or 3.4.0. When Acme is deployed
with `sanitize: true` (or `untrustedSpec: true`), all Markdown rendered from spec content passes
through DOMPurify before `dangerouslySetInnerHTML`. Each of these bypasses allows XSS despite
DOMPurify being active.

## Active Vulnerabilities in DOMPurify 3.2.4

| Advisory | Min Fix | Severity | Description |
|----------|---------|----------|-------------|
| GHSA-39q2-94rc-95cp | 3.4.0 | Medium | ADD_TAGS short-circuit bypasses FORBID_TAGS |
| GHSA-cj63-jhhr-wcxv | 3.3.2 | Medium | USE_PROFILES prototype pollution allows event handlers |
| GHSA-cjmm-f4jc-qw8r | 3.3.2 | Low | ADD_ATTR predicate skips URI validation |
| GHSA-crv5-9vww-q3g8 | 3.4.0 | High | SAFE_FOR_TEMPLATES bypass in RETURN_DOM mode |
| GHSA-h7mw-gpvr-xq4m (CVE-2026-41240) | 3.4.0 | High | FORBID_TAGS bypass via function-based ADD_TAGS predicate |
| GHSA-h8r8-wccr-v5f2 | 3.3.2 | Medium | Mutation-XSS via re-contextualization |
| GHSA-v9jr-rg53-9pgp (CVE-2026-41238) | 3.4.0 | High | Prototype Pollution to XSS bypass via CUSTOM_ELEMENT_HANDLING |

## Attack Scenario

When the embedding app enables `sanitize: true`, a spec author crafts a `description` field
with an mXSS payload that bypasses DOMPurify 3.2.4. For example, GHSA-h8r8-wccr-v5f2 (mutation-XSS
via re-contextualization) allows payloads that parse safely in isolation but mutate in the DOM
context, defeating sanitization.

The relevant code path:
```
spec.*.description
  → MarkdownRenderer.renderMd()
  → marked() produces HTML
  → SanitizedMdBlock.tsx: dompurify.sanitize(html) [line 16, called when sanitize=true]
  → dangerouslySetInnerHTML {{ __html: ... }} [line 30]
  → DOM XSS
```

## Impact

- **Scope**: Any deployment using `sanitize: true` against untrusted specs
- **Effect**: Full DOM XSS in embedding origin; session hijack, cookie theft, DOM manipulation
- **Default state**: `sanitize` defaults to `false`, meaning most deployments are vulnerable to
  simpler raw-HTML XSS (p5-001 class) but not specifically to the DOMPurify bypass. However,
  the intended secure mode (`sanitize: true`) is itself vulnerable via the above CVEs.

## Evidence

- `package-lock.json` line 7746: `"dompurify": { "version": "3.2.4" }`
- `[REDACTED].tsx:10`: `const dompurify = DOMPurify['default'] as DOMPurify.DOMPurify;`
- `[REDACTED].tsx:16`: `const sanitize = (sanitize, html) => (sanitize ? dompurify.sanitize(html) : html);`
- DOMPurify is invoked with **default configuration** — no custom `ALLOWED_TAGS`, `ALLOWED_ATTR`, or `ADD_TAGS` overrides in Acme itself. Advisory bypass techniques that rely on non-default DOMPurify config (GHSA-39q2-94rc-95cp, GHSA-h7mw-gpvr-xq4m, GHSA-crv5-9vww-q3g8) require the config options be set, which Acme does not set — those three may be less exploitable in Acme's default usage.
- Advisories GHSA-cj63-jhhr-wcxv (USE_PROFILES pollution), GHSA-h8r8-wccr-v5f2 (mXSS re-contextualization), and GHSA-v9jr-rg53-9pgp (CUSTOM_ELEMENT_HANDLING PP-to-XSS) do not require special config and affect default DOMPurify usage.

## Reachability

- `call-graph-slices.json` slice `spec-markdown-to-dangerouslySetInnerHTML` (Path 2): `reachable: true`
- Requires `options.sanitize = true` at deployment

## Remediation

Upgrade DOMPurify to `>=3.4.0`. Current `package.json` specifies `"dompurify": "^3.2.4"` — bump
the constraint to `"^3.4.0"` and run `npm install`.
