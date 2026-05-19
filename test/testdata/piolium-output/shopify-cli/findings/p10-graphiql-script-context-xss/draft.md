---
Phase: 10
Sequence: 7
Slug: graphiql-script-context-xss
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: executed
Pre-FP-Flag: requires-valid-graphiql-key-url
Debate: piolium/chamber-workspace/c02-graphiql-local-server/debate.md
Origin-Drafts: p4-009-graphiql-script-context-xss.md
id: p10
slug: graphiql-script-context-xss
severity: info
Protocol: http
Auth-Required: yes
Auth-Roles-Required: anonymous
---

# GraphiQL embeds query parameters into an inline script without HTML-safe JSON escaping

## Summary
The local GraphiQL page accepts `query` and `variables` URL parameters, runs `JSON.stringify`, and emits them directly inside an inline `<script>` block. JSON stringification does not escape `<` or `</script>`, so a crafted value can break out of the script context when the request includes a valid GraphiQL key.

## Location
- `packages/app/src/cli/services/dev/graphiql/server.ts:206-227` — decodes URL parameters and passes `JSON.stringify` output to the template.
- `packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx:254-259` — inserts `query` and `variables` into inline JavaScript.

## Attacker Control
An attacker who can cause the developer to open a GraphiQL URL containing the valid per-run/derived key can control `query` or `variables` in the rendered page. The key precondition keeps severity at Medium.

## Trust Boundary Crossed
URL data crosses into executable JavaScript in the trusted local GraphiQL origin, which can make same-origin requests to the token-backed GraphQL proxy.

## Impact
JavaScript execution in the local GraphiQL origin, enabling same-origin calls to `/graphiql/graphql.json` and manipulation of the developer's GraphiQL session.

## Evidence
`server.ts` passes `query: queryParam ? JSON.stringify(queryParam) : undefined`; the template emits `query: {{query}}` and `variables: {{variables}}` inside `<script>`. There is no replacement for `<`, `>`, `&`, U+2028/U+2029, or `</script>`.

## Reproduction Steps
1. Obtain or reuse a legitimate GraphiQL URL containing `?key=[REDACTED:secret]
2. Add a `query` or `variables` parameter containing a `</script><script>...</script>` sequence.
3. Load the URL; the inline script context is broken because the JSON string was not HTML-escaped.
