# [M11] Schemaref Mdx Second Order Xss

## Summary

1. `src/services/MarkdownRenderer.ts:176` — `parseProps(props)` extracts `schemaRef` from MDX tag in spec description text (e.g. `<schema-definition schemaRef="#/components/schemas/Pwn" />`). No allow-list or sanitization of prop names or values.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Firm (code-traced, PoC theoretical)
- **Vulnerability Type**: XSS-via-MDX-schemaRef-second-order
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Intent-Verdict**: intentional-design
- **Triage-Priority**: skip

## Impact

See draft.md for full impact analysis on `src/services/MarkdownRenderer.ts:183`.

## Affected Component

- **File**: `src/services/MarkdownRenderer.ts:183`
- **Source**: spec description text containing <schema-definition schemaRef="#/components/schemas/X"/> + the dereferenced schema's description field (split payload across two spec sections)
- **Sink**: [REDACTED].tsx:31 (dangerouslySetInnerHTML, reached via FieldDetails.tsx:107 → Markdown → SanitizedMarkdownHTML)
- **Chamber**: chamber-01

## Source to Sink Flow

1. `src/services/MarkdownRenderer.ts:176` — `parseProps(props)` extracts `schemaRef` from MDX tag in spec description text (e.g. `<schema-definition schemaRef="#/components/schemas/Pwn" />`). No allow-list or sanitization of prop names or values.

2. `src/services/MarkdownRenderer.ts:183` — `componentDefs.push({ component: SchemaDefinition, propsSelector: ..., props: { ...parseProps(props), ...componentMeta.props, children } })` — attacker-controlled `schemaRef` is placed in `props`.

3. `[REDACTED].tsx:47` — `<PartComponent {...{ ...part.props, ...part.propsSelector(store) }} />` — `propsSelector` for `SchemaDefinition` only returns `{ parser, options }`, it does NOT return `schemaRef`, so the attacker-controlled `schemaRef` survives into the component's props.

4. `[REDACTED].tsx:29` — `SchemaDefinition.getMediaType(schemaRef)` builds `{ schema: { $ref: schemaRef } }` and `MediaTypeModel` resolves the `$ref` via `parser.byRef(schemaRef)`.

5. The dereferenced schema's `description` field is extracted at `src/services/models/Schema.ts` and passed through `FieldDetails` as `field.description`.

6. `src/components/Fields/FieldDetails.tsx:107` — `<Markdown compact={true} source={description} />` renders the resolved schema's description.

7. `src/components/Markdown/Markdown.tsx:29` → `SanitizedMarkdownHTML` → `[REDACTED].tsx:31` → `dangerouslySetInnerHTML={{ __html: sanitize(options.sanitize, html) }}` — with default `sanitize: false`, the raw HTML executes.

## Vulnerable Code

See `src/services/MarkdownRenderer.ts:183` and draft.md for code excerpts.

## Proof of concept & Evidence

No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/security-definitions-injection.md:1-24 + docs/config.md:77-80`. Quote: "You can inject the Security Definitions widget anywhere in your specification description" / "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS.". MEDIUM severity XSS requiring attacker control of two spec sections and vendor MDX tag usage; default sanitize=false but limited blast radius to spec viewers.

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

- Default Acme configuration (no special options needed).
- Attacker controls any description field AND any schema description in the spec (can be split across `$ref`-included files).

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/MarkdownRenderer.ts:183`.
