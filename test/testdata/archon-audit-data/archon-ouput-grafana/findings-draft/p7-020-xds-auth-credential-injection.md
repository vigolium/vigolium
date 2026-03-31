Phase: 7
Sequence: 020
Slug: xds-auth-credential-injection
Verdict: VALID
Rationale: The X-DS-Authorization header from any authenticated user with datasources.ActionQuery permission is forwarded verbatim as the Authorization header to backend datasources, overriding admin-configured credentials. While partially intentional for frontend plugin credential transport, the lack of server-side origin validation creates a credential injection vector that breaks OAuthPassThru per-user isolation when the attacker authenticates via non-OAuth methods.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-3-ambiguous (intentional design vs. missing validation -- Advocate presents credible evidence of intended frontend protocol but server-side enforcement is absent)
Debate: security/chamber-workspace/chamber-2/debate.md

## Summary

The Grafana datasource proxy forwards the `X-DS-Authorization` HTTP header from client requests verbatim as the `Authorization` header on outbound requests to backend datasources. Any authenticated user with `datasources.ActionQuery` RBAC permission can send this header to override the admin-configured datasource credentials (BasicAuth, API key) with arbitrary attacker-controlled values. This breaks the intended security model where datasource credentials are managed exclusively by administrators.

The most impactful variant occurs with OAuthPassThru-enabled datasources: an attacker who authenticates via session cookie or API key (instead of OAuth) causes the OAuthPassThru credential injection to be skipped, allowing the X-DS-Authorization value to persist as the outbound Authorization header. This bypasses the per-user OAuth isolation model.

## Location

- **Primary**: `pkg/api/pluginproxy/ds_proxy.go:230-234` -- X-DS-Authorization forwarding in director function
- **Entry point**: `GET/POST /api/datasources/proxy/uid/:uid/*` (authenticated, datasources.ActionQuery RBAC)
- **Frontend origin**: `public/app/core/services/backend_srv.ts:304-306` -- intentional frontend protocol for renaming Authorization headers

## Attacker Control

- **Input**: `X-DS-Authorization` HTTP request header -- fully attacker-controlled string
- **Authentication required**: Yes -- any authenticated user with `datasources.ActionQuery` permission (Viewer role by default for accessible datasources)
- **Forwarding**: Verbatim. The header value is extracted, the X-DS-Authorization header is deleted from the outbound request, and the value is set as the `Authorization` header. No validation, sanitization, or allowlist applied.

## Trust Boundary Crossed

TB4 -- Datasource Proxy credential injection. The datasource proxy is designed to inject admin-configured credentials into backend requests. This mechanism allows any authorized query user to REPLACE those credentials with arbitrary values, crossing the admin/user credential management boundary.

## Impact

- **Credential override**: User can present arbitrary credentials to the backend datasource, potentially authenticating as a different backend identity than the admin-configured one
- **OAuthPassThru bypass**: For datasources with per-user OAuth isolation, the attacker can bypass the per-user token injection by authenticating via non-OAuth methods, then injecting arbitrary credentials via X-DS-Authorization
- **Credential probing**: The backend datasource becomes a target for credential stuffing via the proxy, using the Grafana instance as an intermediary
- **Limitation**: The attacker cannot extract the admin-configured credentials; they can only replace them. The backend datasource is the final authority on accepting credentials.

## Evidence

**Code path** (from Tracer):
```
ds_proxy.go:230  dsAuth := req.Header.Get("X-DS-Authorization")
ds_proxy.go:231  if len(dsAuth) > 0 {
ds_proxy.go:232      req.Header.Del("X-DS-Authorization")
ds_proxy.go:233      req.Header.Set("Authorization", dsAuth)
ds_proxy.go:234  }
```

**Credential ordering chain** (director function ds_proxy.go:173-278):
1. Line 220-228: BasicAuth injection (if ds.BasicAuth is true)
2. Line 230-234: X-DS-Authorization override (ATTACKER CONTROLLED -- overwrites BasicAuth)
3. Line 250-263: ApplyRoute credential injection (only if a route matched -- skipped for most datasources)
4. Line 266-274: OAuthPassThru (only if OAuthPassThru enabled AND user has OAuth token -- skipped for non-OAuth auth)

**Route bypass**: Most built-in datasources (Prometheus, MySQL, PostgreSQL, InfluxDB, Elasticsearch) define no plugin routes. For these, validateRequest falls through at line 347 (return nil), matchedRoute stays nil, ApplyRoute is never called. X-DS-Authorization value persists.

## Reproduction Steps

1. Authenticate to Grafana as a user with Viewer role and datasources.ActionQuery on a target datasource (e.g., Prometheus)
2. Send: `curl -H "Cookie: grafana_session=<session>" -H "X-DS-Authorization: Bearer arbitrary-evil-token" http://grafana:3000/api/datasources/proxy/uid/<ds-uid>/api/v1/query?query=up`
3. Observe: the backend Prometheus receives `Authorization: Bearer arbitrary-evil-token` instead of the admin-configured credentials
4. For OAuthPassThru variant: authenticate via API key (not OAuth), send X-DS-Authorization -- the OAuth token injection at line 266 is skipped because GetCurrentOAuthToken returns nil for non-OAuth sessions
