# Authorization Coverage Gaps — Acme Phase D7

**Note**: Acme is a client-side library with no backend routes, sessions, or user identity. The concept of "coverage gaps" applies only to the access-control-analogous surfaces enumerated in the authz matrix.

## Items Requiring Manual Chamber Review

### 1. acme-cli handlebars template injection path (Expected Scope: unknown)

The `cli/` directory (acme-cli) uses handlebars for generating static HTML bundles from spec files. If the CLI tool processes a spec where description fields contain handlebars template syntax (`{{...}}`), and those fields reach the handlebars rendering context without escaping, server-side template injection (SSTI) resulting in RCE is possible. This surface was identified in Phase D1/D2 advisory intelligence (GHSA-2w6w-674q-4c4q, CVE-2026-33937) but was not fully traced through the CLI source in this phase because it is a build-time RCE concern, not an authz concern. Phase D10 chambers should verify whether spec `description` content reaches `hbs.compile()` or template context directly.

### 2. `allowedMdComponents` component propsSelector function (Expected Scope: unknown)

`MarkdownRenderer.renderMdWithComponents` (MarkdownRenderer.ts:156-200) dispatches spec-controlled component names and props to React components registered in `options.allowedMdComponents`. The `propsSelector` function receives the full `AppStore` (AdvancedMarkdown.tsx:47). If a host page registers a component with a `propsSelector` that exposes sensitive store state based on spec-provided props, a malicious spec could exfiltrate information. The risk depends entirely on the host-supplied component implementations. This surface is scope-dependent and requires per-deployment review.

### 3. `theme.extensionsHook` function (Expected Scope: unknown)

`AcmeNormalizedOptions.ts:283-300` extracts `raw.theme.extensionsHook` and attaches it to `this.theme.extensionsHook` after theme resolution. The function is marked `as any`. If a host page passes a theme object from partially untrusted input (e.g., from a URL hash or `localStorage`), and if `extensionsHook` is a function that is invoked during rendering, this could be a code execution path. Extent of invocation was not traced in this phase.

### 4. `$ref` external URL fetching (Expected Scope: unknown, browser-constrained)

`OpenAPIParser` fetches external `$ref` URLs. This is a browser-SSRF surface: a malicious spec can cause the visitor's browser to make GET requests to any CORS-accessible URL (same-origin or CORS-open endpoints). In contexts where Acme is embedded in an internal tool or admin panel, this could be used to probe internal network endpoints. CORS limits response reading but not the request itself. Covered partially by Phase D1/D2 architecture model; no authz finding filed because this is a SSRF-class concern handled by Phase D5/D6.

## Items Confirmed NOT a Coverage Gap

- No gRPC, GraphQL, WebSocket, message queue, or cron surfaces exist.
- No user-facing CLI subcommands operating on user-owned data exist.
- No HTTP API routes of any kind exist.
- No session tokens, JWTs, or identity objects exist.
