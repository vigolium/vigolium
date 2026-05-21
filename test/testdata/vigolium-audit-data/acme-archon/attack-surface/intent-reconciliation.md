# Intent Reconciliation — Phase D9 (audit contract)

**Date**: 2026-05-19
**Target**: `/Users/<user>/Desktop/oss-to-run/acme`
**Drafts evaluated**: 27 (all VALID p10-* / p5-* / p6-* / p2-* drafts; p10-033 INCONCLUSIVE and p5-005 already-triaged are out of this pass per orchestrator scope)

## Project context

Acme is a client-side-only React/MobX renderer for OpenAPI specs (no backend, no auth surfaces). Its single largest documented trust contract is the `sanitize` (alias `untrustedSpec`) option, which `docs/config.md:77-80` and `docs/config.md:212-214` declare as opt-in: setting `true` treats the spec as untrusted and routes Markdown through DOMPurify; the default (`false`) trusts the operator-supplied spec author. `CHANGELOG.md:1965` records `untrusted-spec` as the named XSS mitigation. The MDX-style vendor tags `<security-definitions>`, `<security-definition>`, `<schema-definition>` are documented operator-facing surface (`docs/security-definitions-injection.md`). The `demo/` folder is explicitly out-of-scope per `archon/attack-surface/knowledge-base-report.md:1104`.

## Per-Finding Verdicts

| Finding | Class | Intent-Verdict | Routed | Basis (source:line) | Confidence |
|---------|-------|----------------|--------|---------------------|------------|
| p5-003-sanitize-default-off-xss | XSS | intentional-design | skip (→theoretical) | docs/config.md:77-80 | strong |
| p6-002-sanitize-false-default-fail-open | XSS | intentional-design | skip | docs/config.md:77-80 | strong |
| p10-004-oauth-scope-description-xss-default-sanitize-false | XSS | intentional-design | skip | docs/config.md:77-80 | strong |
| p10-001-schemaref-mdx-second-order-xss | XSS-via-MDX | intentional-design | skip | docs/security-definitions-injection.md:1-24 + docs/config.md:77-80 | strong |
| p10-030-demo-cors-acme-ly-ssrf | SSRF (demo) | documented-feature | skip | KB:1104 (demo out-of-scope) | strong |
| p5-006-sourcecode-prism-unguarded-sink | XSS-latent | intentional-design | none (annotate) | KB:1094 | medium |
| p10-003-theme-css-injection-styled-components | CSS-Injection | genuine-vuln | none | none | weak |
| p5-001-spec-href-javascript-scheme-xss | XSS (href) | genuine-vuln | none | none | weak |
| p5-002-dompurify-outdated-mxss | XSS (mXSS) | genuine-vuln | none | none | weak |
| p5-004-parseprops-redos | ReDoS | genuine-vuln | none | none | weak |
| p6-001-oauth-url-javascript-injection | XSS (href) | genuine-vuln | none | none | weak |
| p6-003-html-attribute-overrides-js-options | hidden-control-channel | genuine-vuln | none | none | weak |
| p10-002-logo-href-data-uri-tracking | Info-Leak | genuine-vuln | none | none | weak |
| p10-005-component-regexp-cross-line-redos | ReDoS | genuine-vuln | none | none | weak |
| p10-006-markdown-component-sanitize-prop-dead | API-contract | genuine-vuln | none | none | weak |
| p10-020-ssrf-externalvalue-fetch-no-allowlist | SSRF | genuine-vuln | none | none | weak |
| p10-021-externalexamplescache-cross-spec-poisoning | Cache poisoning | genuine-vuln | none | none | weak |
| p10-022-ssrf-via-spec-url-attribute | SSRF | genuine-vuln | none | none | weak |
| p10-023-allof-breadth-dos-no-limit | Parser DoS | genuine-vuln | none | none | weak |
| p10-024-hoistoneofs-exponential-schema-dos | Parser DoS | genuine-vuln | none | none | weak |
| p10-025-x-refsstack-injection-cycle-detection-bypass | Cycle bypass | genuine-vuln | none | none | weak |
| p10-026-decodeuri-before-pointer-cross-section-traversal | Pointer injection | genuine-vuln | none | none | weak |
| p10-027-webhooks-parser-bug-parity | Surface multiplier | genuine-vuln | none | none | weak |
| p10-028-searchstore-indexitems-unbounded-dos | Post-parse DoS | genuine-vuln | none | none | weak |
| p10-029-ssrf-via-ref-customfetch-no-allowlist | SSRF (bundler) | genuine-vuln | none | none | weak |
| p10-031-byref-returns-empty-object-bad-ref | Robustness | genuine-vuln | none | none | weak |
| p10-032-findderived-quadratic-dos | Parser DoS | genuine-vuln | none | none | weak |
| p2-051-overrides-not-propagated-to-consumers | Supply-chain | genuine-vuln | none | none | weak |
| p2-052-yarn-pnpm-ignore-overrides | Supply-chain | genuine-vuln | none | none | weak |

## Reframed classes (intentional-design / documented-feature)

The five findings reframed by documented intent all reduce to two project decisions:

1. **`sanitize` is opt-in.** `p5-003`, `p6-002`, `p10-004`, and `p10-001` all stand on the documented default-off sanitize gate. Operators following Acme docs are expected to set `sanitize:true` when the spec author is untrusted; without that, the entire markdown render path is "operator-trust" by design. These findings still describe real exploitable behavior — they are routed to the theoretical bucket rather than dropped, so engineering effort can be directed to potential default-flip hardening rather than PoC confirmation of a documented condition.
2. **`demo/` is out-of-scope.** `p10-030` lives entirely in `demo/index.tsx` and abuses the Acmely-operated `cors.acme.ly` proxy. KB `## Out-of-Scope Paths` declares `demo/**` as not part of the published library bundle. Remediation belongs to the proxy service, not acme.

## Genuine-vuln surfaces that survive intent review

- **Spec-derived href scheme injection** (`p5-001`, `p6-001`, `p10-002`) — KB Threat Model T6/T7 explicitly lists this as in-scope; no doc claims React `<a href={spec.url}>` is intended to allow `javascript:` schemes.
- **SSRF via spec content** (`p10-020`, `p10-022`, `p10-029`) — no Acme doc warns embedders about `$ref`/`externalValue`/`spec-url` SSRF.
- **Parser DoS cluster** (`p10-005`, `p10-023..028`, `p10-032`, `p5-004`) — algorithmic-complexity bugs; no documented intent.
- **Pointer/cycle-detection integrity bugs** (`p10-025`, `p10-026`, `p10-031`) — no doc claims internal tracking fields (`x-refsStack`) or `%2F`-decoded refs are an exposed feature.
- **HTML-attribute override of options** (`p6-003`) — trust-boundary collapse not described in docs.
- **Dependency-version hygiene** (`p5-002`, `p2-051`, `p2-052`) — no documented intent.
- **Theme CSS interpolation** (`p10-003`) — operator-trust on theme is implicit in `docs/config.md` Theme settings but no doc explicitly says raw-string interpolation is a deliberate design choice; kept genuine with weak intent.
- **Markdown sanitize prop dead** (`p10-006`) — internal-API contract bug, not declared intent (per orchestrator scoping note).

## Docs considered but not applied as load-bearing intent

- `README.md` — feature catalogue only, no security claims that scope a specific finding.
- `docs/acme-vendor-extensions.md` — describes x-* extensions structurally; no security trust claims that match any finding's exact path.
- `docs/quickstart.md` / `docs/deployment/**` — operational, no trust-model claims encountered.
- `CHANGELOG.md` entry at line 361 ("sanitize array of items") — refers to an unrelated rendering option, not the XSS-sanitize gate.

## Routing summary

- Findings whose `Triage-Priority` was overwritten to `skip` with `context-reviewer` reasoning: **5** (p5-003, p6-002, p10-001, p10-004, p10-030). These will route to `archon/findings-theoretical/` via the existing `consolidate_drafts.py` skip channel and continue to receive a full report, just out of the main Summary table.
- Findings annotated with `Intent-Verdict: intentional-design` at MEDIUM confidence and **not** routed: **1** (p5-006 — already at `Triage-Priority: skip` from earlier triage; KB-only basis is medium, so no soft-route is added by this pass).
- Findings annotated `Intent-Verdict: genuine` (weak intent): **21**. Triage-Priority untouched. All survive to PoC/confirmation as full findings.
