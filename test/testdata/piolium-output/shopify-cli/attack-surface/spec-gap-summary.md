# Stage 07 Spec Gap Summary

Authoritative specs/contracts were fetched into `piolium/tmp/specs/` and traced against the Phase 3 candidates.

## New P7 draft

- `piolium/findings-draft/p7-001-liquidjs-default-root-file-read.md` — LiquidJS default `root: ["."]` is used while rendering downloaded templates, allowing malicious templates to include files from the caller working directory.

## Covered by earlier findings, not duplicated

- RFC 6455 Origin validation gap for the extension dev WebSocket server is already covered by `piolium/findings-draft/p5-001-ui-extension-dev-server-missing-auth.md`.
- GraphiQL key/CORS/API-version issues are already covered by P4/P5 drafts.

Other OAuth2/PKCE/device-auth/token-exchange/JWT, GraphQL, SSE, TOML/schema, archive/path, Cloudflare tunnel, and OTLP candidates did not produce additional Medium+ spec-gap drafts in this pass.
