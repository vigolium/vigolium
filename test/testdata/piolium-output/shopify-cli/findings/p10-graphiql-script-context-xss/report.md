# [p10] GraphiQL inline script context XSS via query parameters

## Summary

The local GraphiQL page renders attacker-controlled `query` and `variables` URL parameters into an inline `<script>` block using `JSON.stringify` only. When a developer opens a GraphiQL URL containing the valid per-run GraphiQL key, a crafted `</script><script>...</script>` value breaks out of the JavaScript string and executes in the trusted local GraphiQL origin.

## Details

The `/graphiql` route requires the correct key before rendering, so exploitation requires a URL with a valid GraphiQL key. After that check, the route decodes the `query` and `variables` parameters and passes them to the template as raw JSON strings. In [`server.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/graphiql/server.ts#L174-L226), only newlines are normalized before `JSON.stringify` is used:

```ts
if (key && query.key !== key) {
  setResponseStatus(event, 404)
  return `Invalid path ${event.path}`
}

function decodeQueryString(input: string | undefined) {
  return input ? decodeURIComponent(input).replace(/\n/g, '\\n') : undefined
}

const queryParam = decodeQueryString(query.query as string | undefined)
const variables = decodeQueryString(query.variables as string | undefined)

return renderLiquidTemplate(
  // ...
  {
    url,
    defaultQueries: [{query: defaultQuery}],
    query: queryParam ? JSON.stringify(queryParam) : undefined,
    variables: variables ? JSON.stringify(variables) : undefined,
  },
)
```

The GraphiQL template then places those values directly inside an inline script. The decisive sink is in [`templates/graphiql.tsx`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx#L250-L259):

```tsx
fetcher: GraphiQL.createFetcher({
  url: '{{url}}/graphiql/graphql.json?key=[REDACTED:secret]&api_version=' + apiVersion,
}),
defaultEditorToolsVisibility: true,
{% if query %}
query: {{query}},
{% endif %}
{% if variables %}
variables: {{variables}},
{% endif %}
```

`JSON.stringify` makes the value valid JavaScript string syntax, but it does not HTML-escape `<`, `>`, `&`, U+2028/U+2029, or the `</script>` sequence. Because browsers terminate a script element on `</script>` while parsing HTML, a JSON string containing that sequence can close the current script block and start a new attacker-controlled script.

## Root Cause

The implementation uses JavaScript string serialization as if it were safe HTML script-context serialization. Data from URL parameters crosses from the request into an executable `<script>` block without an HTML-safe JSON serializer or equivalent escaping that prevents `</script>` from being interpreted by the HTML parser.

## Proof of Concept (PoC)

PoC-Status: `executed`.

The runnable PoC is `piolium/findings/p10-graphiql-script-context-xss/poc.js`. It creates a Vitest test that starts a local GraphiQL server with `key: 'poc-key'`, requests `/graphiql?key=[REDACTED:secret]&query=<payload>`, and checks whether the rendered HTML contains a standalone injected `<script id='poc-xss'>` that targets the same-origin GraphQL proxy.

Minimal payload shape:

```text
/graphiql?key=[REDACTED:secret]&query=%3C%2Fscript%3E%3Cscript%20id%3D'poc-xss'%3Efetch('%2Fgraphiql%2Fgraphql.json%3Fkey%3Dpoc-key%26api_version%3Dunstable'%2C%7Bmethod%3A'POST'%2Cheaders%3A%7B'Content-Type'%3A'application%2Fjson'%7D%2Cbody%3AJSON.stringify(%7Bquery%3A'%7B%20shop%20%7B%20name%20%7D%20%7D'%7D)%7D)%3C%2Fscript%3E%3Cscript%3E
```

The executed evidence in `evidence/impact.log` shows the security effect:

```text
HTTP status: 200
Valid GraphiQL key accepted: true
Standalone injected script tag present: true
Injected script targets same-origin proxy: true
HTML-safe escaping absent: true
```

The same log captures the rendered response context, where the parameter value appears as `query: "</script><script id='poc-xss'>fetch('/graphiql/graphql.json?key=[REDACTED:secret]&api_version=unstable', ...)` rather than as escaped text.

## Impact

An attacker who can induce a developer to open a GraphiQL URL containing the valid key can execute arbitrary JavaScript in the local GraphiQL origin. In that origin, the script can call `/graphiql/graphql.json` as same-origin and use the same GraphiQL key, enabling actions through the token-backed Admin GraphQL proxy with the app scopes available to the developer's local session. The valid-key precondition limits exposure, but the executed PoC confirms that, once the key is accepted, the page renders the payload as an executable script tag instead of escaping it.

## Remediation

Serialize `query` and `variables` with an HTML-safe JSON serializer before embedding them in an inline script. At minimum, escape `<`, `>`, `&`, U+2028, and U+2029 (for example, serializing `<` as `\u003C`) so `</script>` cannot terminate the script element. Prefer moving user-controlled data into a non-executable JSON data island or DOM attribute read via `textContent`, and add a regression test that verifies a `</script><script>` URL parameter is rendered inert rather than executable.

## Confirmation (V4)
Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p10-graphiql-script-context-xss/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 2
Confirm-FpCheck: not-run
Confirm-Notes: standalone <script id='poc-xss'> emitted in GraphiQL HTML; variant1 live mock route probe recorded; variant2 started real GraphiQL server and rendered exploitable HTML; The injected script includes a same-origin /graphiql/graphql.json POST using the valid GraphiQL key.
Confirm-Queued-V5: no
