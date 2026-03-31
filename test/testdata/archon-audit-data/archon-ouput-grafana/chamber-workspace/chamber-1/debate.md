# Chamber 1: Authentication & Authorization — Debate Transcript

**Threat Cluster:** OIDC token replay/audience confusion, OAuth signature bypass chains, JWT without exp (permanent tokens), WebSocket CSRF via empty origin, RBAC wildcard scope abuse, permission cache poisoning
**DFD/CFD Slices:** CFD-1 (Authentication Pipeline), CFD-2 (RBAC Scope Evaluation), CFD-3 (Proxy Route Auth), CFD-4 (Public Dashboard Auth), DFD-1 (Datasource Proxy)
**Scope Boundaries:** Trust boundaries TB2 (Authentication Gate), TB3 (Authorization Gate), TB4 (Datasource Proxy), TB7 (Public Dashboard Gate), TB11 (Org Isolation)
**Retained Findings in Scope:** SPEC-GAP-001, SPEC-GAP-002, SPEC-GAP-003, SPEC-GAP-004, SAST-007, SAST-012, SAST-006

---

## Attack Ideator Hypotheses

### Batch 1 — Generated 2026-03-20

---

**H-01: OIDC Expired Token Replay + Audience Confusion for Cross-Application Account Takeover**
- Attack class: Mode 7 (State Machine) — replaying a one-time/expired credential
- Cross-modes: Mode 1 (Chaining) — chains SPEC-GAP-001 expired-token acceptance with absent audience validation
- Chain: (1) Attacker obtains a legitimately-issued OIDC ID token for a different OAuth client application (e.g., a staging Grafana instance, an internal tool using the same IdP) that shares the same IdP JWKS. (2) The token is expired but its signing key has not been rotated from the IdP's JWKS. (3) Attacker presents this cross-application, expired token to the production Grafana OAuth callback. (4) `validateIDTokenSignatureWithURLs()` at `social_base.go:389-442` verifies the cryptographic signature (valid, since the JWKS key is still active) and returns raw claims JSON without checking `exp`, `iss`, or `aud`. (5) The caller in `generic_oauth.go` extracts the `email` claim and looks up/creates the user, granting a session for the target account.
- Preconditions: Attacker has obtained any ID token issued by the same IdP (from any client application in the IdP's trust domain). Token's signing key is still in the active JWKS. `validate_id_token=true` and `jwk_set_url` is configured (non-default, but recommended for security).
- Target asset: User session for any account whose email appears in the stolen/cross-application token
- Entry point: OAuth2 callback endpoint (EP-012, POST /login flow)
- Sink: User lookup/creation in `generic_oauth.go` using unvalidated email claim from ID token
- Creativity signal: A solo agent analyzing SPEC-GAP-001 would focus on expired-token replay in isolation. The cross-application dimension (audience confusion) is the novel insight — an attacker does not need the victim's own Grafana token; ANY token from ANY application sharing the same IdP suffices. This transforms a "stale credential" issue into a cross-application identity theft vector that bypasses IdP-level application access controls entirely.

---

**H-02: RBAC Scope Template Injection via Go text/template in URL Parameters**
- Attack class: Mode 5 (Trust Boundary Confusion) — URL parameters treated as trusted input in template execution
- Cross-modes: Mode 6 (Parser Differential) — Go's `text/template` interprets `{{.URLParams}}` allowing map traversal
- Chain: (1) The `scopeInjector` function at `middleware.go:409-421` uses Go's `text/template` to inject URL parameters into RBAC scope strings. (2) The scope template (e.g., `dashboards:uid:{{ .URLParams.uid }}`) is parsed and executed with `scopeParams{URLParams: web.Params(c.Req)}`. (3) An attacker crafts a URL where the `:uid` parameter contains Go template directives, e.g., `:uid = {{.OrgID}}` or more dangerously `{{index .URLParams "other_param"}}`. (4) Since `text/template` is used (not `html/template`), and the scope string itself is the template being parsed (not the URL param), this particular vector requires the SCOPE DEFINITION to contain `{{...}}` syntax that references `.URLParams` — and it does. The URL parameter VALUE is substituted INTO the template output, not parsed as a template itself. However, if any scope template uses a construct like `{{ .URLParams }}` (map reference without a specific key), the entire URL parameter map is rendered, potentially leaking other route parameters into the scope evaluation.
- Preconditions: Authenticated user. A route exists where multiple URL parameters are captured but only one is intended for scope injection, and the scope template uses `.URLParams` in a way that could be influenced by adjacent parameters.
- Target asset: RBAC scope evaluation bypass — access resources belonging to a different scope than intended
- Entry point: Any RBAC-protected endpoint using `ac.Parameter()` scope binding (CFD-2, middleware.go:71-74)
- Sink: `ac.Evaluate()` at middleware.go:80 — evaluates the injected scope against user permissions
- Creativity signal: The `text/template` usage in security-critical scope injection is unusual. Most RBAC systems use simple string concatenation or parameterized queries. Go's template engine supports function calls, conditionals, and map iteration — a much richer attack surface than simple string substitution. A solo agent would check for SQL injection in the scope but miss the template engine's own capabilities as an injection vector.

---

**H-03: Permission Cache Poisoning via Concurrent Role Grant + RBAC Evaluation Race**
- Attack class: Mode 3 (Race Condition / TOCTOU) — permission cache populated during role transition
- Cross-modes: Mode 1 (Chaining) — chains the 5s TTL cache (SAST-015 pattern) with RBAC wildcard scope
- Chain: (1) User A is an Org Admin who is about to revoke User B's Editor role. (2) User B, anticipating revocation, issues a rapid burst of API requests that trigger RBAC cache population. (3) The RBAC middleware evaluates User B's permissions via `ac.Evaluate()` and caches the result with a TTL. (4) User A revokes User B's role. The role revocation calls `InvalidateResolverCache` but this only invalidates the cache on the current pod. (5) In an HA deployment, other pods still have User B's old permissions cached for up to 5 seconds. (6) User B continues issuing requests to those pods, maintaining elevated access during the stale window. (7) The attacker can automate this: continuously issue requests across all known pods to maximize the probability that at least one pod serves stale cached permissions.
- Preconditions: HA deployment with multiple Grafana pods behind a load balancer. Attacker (User B) has current valid session. The permission revocation lacks distributed cache invalidation.
- Target asset: Continued access to RBAC-protected resources (dashboards, datasources, alert rules) after permission revocation
- Entry point: Any RBAC-protected endpoint (CFD-2, evaluated via middleware.go:80)
- Sink: Stale permission cache at `pkg/infra/localcache/` serving revoked permissions
- Creativity signal: The 5-second window per pod seems trivially short for a solo analyst to flag as exploitable. The HA amplification is the key insight: with N pods, the effective window is 5s * N if the attacker can target each pod. Combined with a load balancer that round-robins requests, an automated tool can sustain stale access for 5s * N / concurrency_factor — potentially minutes in large deployments.

---

**H-04: CSRF Bypass via X-DS-Authorization Header Injection Chained with Hop-by-Hop Stripping Evasion**
- Attack class: Mode 1 (Vulnerability Chaining) — SAST-012 CSRF bypass + SAST-007 header injection + SPEC-GAP-004 hop-by-hop
- Cross-modes: Mode 5 (Trust Boundary Confusion) — CSRF middleware trusts a custom header value that the attacker controls
- Chain: (1) A Grafana deployment configures `csrf_additional_headers = X-Forwarded-Host` (common in reverse proxy deployments). (2) The CSRF check at `csrf.go:116-126` extracts the hostname from the `X-Forwarded-Host` header and compares it to the `Origin` header hostname. Both are attacker-controlled. (3) An attacker crafts a cross-origin request with `Origin: https://grafana.victim.com` and `X-Forwarded-Host: grafana.victim.com` — the CSRF check passes because `addr.Host == origin` is true. (4) The CSRF bypass allows the attacker to forge state-mutating requests, specifically a datasource proxy request to `/api/datasources/proxy/uid/:uid/*`. (5) The forged request includes `X-DS-Authorization: Bearer <attacker_token>` (SAST-007), which the datasource proxy forwards as the `Authorization` header to the backend. (6) Additionally, the forged request includes a `Connection: X-Internal-Auth` header with `X-Internal-Auth: admin` — since hop-by-hop headers are not stripped (SPEC-GAP-004), both headers reach the backend datasource. (7) The backend datasource receives a request authenticated with attacker-controlled credentials AND injected internal headers, enabling privilege escalation at the backend level.
- Preconditions: `csrf_additional_headers` is configured (non-default). Victim visits attacker-controlled page while authenticated to Grafana. Backend datasource trusts injected headers. SameSite=Lax cookie may block this for POST requests from cross-origin — requires GET-based state mutation or a same-site redirect gadget.
- Target asset: Backend datasource credentials and data, via CSRF-triggered proxy request with injected authorization
- Entry point: CSRF middleware (csrf.go:122), then datasource proxy (ds_proxy.go:230)
- Sink: Backend datasource HTTP request with attacker-controlled Authorization and injected headers
- Creativity signal: Each of the three findings (SAST-012, SAST-007, SPEC-GAP-004) was classified as individually MEDIUM or non-exploitable. The chain elevates them collectively: CSRF bypass enables forging the request, X-DS-Authorization overrides credentials, hop-by-hop evasion injects additional privilege headers. No single finding creates the exploit; the chain does.

---

**H-05: JWT Without exp Claim + Service Account Token Leak = Permanent Backdoor**
- Attack class: Mode 7 (State Machine) — missing state transition (token never expires)
- Cross-modes: Mode 4 (Second-Order / Stored) — the permanent token is stored (e.g., in a log file, error message, or monitoring system) and exploited later
- Chain: (1) An operator configures Grafana's JWT auth (`auth.jwt`) with an HMAC shared secret for a service-to-service integration. (2) The integrating service issues a JWT without an `exp` claim (some JWT libraries allow this; some IdPs do not require it). (3) The JWT is valid indefinitely because `validation.go:86-95` skips the `exp` case when the key is absent from the claims map, leaving `registeredClaims.Expiry = nil`, and `go-jose`'s `Validate()` at line 121 only enforces expiry when `Expiry != nil`. (4) This permanent JWT is logged in an HTTP access log, captured by a monitoring tool, or included in an error report. (5) Months later, an attacker with access to the log archive (insider, log aggregation breach, or a separate vulnerability) extracts the JWT. (6) The JWT still works because it has no expiration. The signing key has not been rotated because key rotation is a manual process for HMAC secrets. (7) The attacker uses the JWT to authenticate to Grafana with whatever identity the JWT's `sub` claim specifies.
- Preconditions: JWT auth enabled with HMAC shared secret. Integrating service omits `exp` from tokens. JWT appears in a log or monitoring artifact. Signing key not rotated since the token was issued.
- Target asset: Persistent authenticated access to Grafana as the service account identity
- Entry point: Any endpoint accepting JWT auth via `Authorization: Bearer` header (TB2)
- Sink: `validateClaims()` at `validation.go:55-117` — accepts the token without expiry enforcement
- Creativity signal: SPEC-GAP-003 identifies the missing exp enforcement, but categorizes it as requiring key knowledge. The second-order stored-token angle changes the threat model: the attacker does not need the key — they need the already-signed token, which is far easier to obtain through log exposure. The temporal separation (months between token creation and exploitation) is what makes this a stored attack, not a direct authentication bypass.

---

**H-06: Cross-Org Scope Escape via forceLogin + orgId Query Parameter in Anonymous-Enabled Deployments**
- Attack class: Mode 2 (Business Logic Abuse) — abusing legitimate org-switching feature
- Cross-modes: Mode 5 (Trust Boundary Confusion) — the `orgId` query parameter crosses trust boundaries from untrusted input to org context
- Chain: (1) A Grafana instance has `anonymous_enabled=true` with `anonymous_org_role=Viewer` for Org 1. (2) An unauthenticated user accesses a route with `AllowAnonymous=true`. The RBAC middleware at `middleware.go:37-48` checks for `forceLogin` and `orgId` query parameters. (3) The middleware parses `orgId` from the untrusted query string: `strconv.ParseInt(c.Req.URL.Query().Get("orgId"), 10, 64)`. (4) If `orgId` differs from the current org AND `forceLogin` is false AND the user IS signed in anonymously (`c.IsSignedIn=true` for anonymous users), the middleware proceeds with authorization. (5) The question is: does the anonymous user's org context get switched to the requested orgId? If `AuthorizeInOrgMiddleware` is used on the route, it calls `authnService.ResolveIdentity()` with the target org — for an anonymous identity, this may resolve with the anonymous role in the TARGET org, granting cross-org Viewer access. (6) Even without `AuthorizeInOrgMiddleware`, the `orgId` parameter parsed at line 39 might influence downstream handlers that read `c.GetOrgID()` if the context is mutated.
- Preconditions: `anonymous_enabled=true`. Multiple orgs exist. Anonymous user is treated as signed-in with IsSignedIn=true. The target org has resources the attacker wants to view.
- Target asset: Cross-org data access (dashboards, annotations, datasource metadata) in organizations the anonymous user should not have access to
- Entry point: RBAC middleware at `middleware.go:37-48` — `orgId` query parameter (CFD-2)
- Sink: `ac.Evaluate()` with switched org context, or downstream handlers using the mutated org ID
- Creativity signal: The `orgId` query parameter is a well-known feature for org switching, but its interaction with anonymous authentication creates a novel attack surface. Anonymous users in Grafana are "signed in" (IsSignedIn=true) with a configured role — they are not truly unauthenticated from the middleware's perspective. A solo agent analyzing org isolation would focus on authenticated user boundary checks and miss the anonymous+orgId edge case where a user with no credentials can potentially access multiple orgs.

---

**H-07: WebSocket CSRF via Empty Origin + OIDC Token Replay for Persistent Live Data Exfiltration**
- Attack class: Mode 1 (Vulnerability Chaining) — SPEC-GAP-005 (dropped) + SPEC-GAP-001
- Cross-modes: Mode 4 (Second-Order / Stored) + Mode 3 (Race Condition)
- Chain: (1) SPEC-GAP-005 was dropped because it requires the victim's session. But what if the attacker CREATES a session using SPEC-GAP-001 (expired OIDC token replay)? (2) The attacker replays an expired but signature-valid OIDC token to obtain a legitimate Grafana session cookie. (3) Using this session, the attacker opens a WebSocket connection to `/api/live/ws` from a non-browser client (no Origin header sent). (4) `getCheckOriginFunc()` at `live.go:538-540` returns `true` for empty Origin, allowing the connection. (5) The attacker subscribes to real-time dashboard channels containing sensitive time-series data, alerting state changes, and annotation updates. (6) Because the session was obtained via expired token replay, it persists until the session TTL expires (hours/days), even though the underlying OIDC identity has been revoked at the IdP. (7) The attacker maintains a persistent WebSocket connection that survives IdP revocation, continuously exfiltrating live data.
- Preconditions: OIDC configured with `validate_id_token=true` and `jwk_set_url` set. Attacker possesses an expired ID token with a still-active signing key. Grafana Live is enabled.
- Target asset: Real-time time-series data, alerting state, and dashboard annotations via persistent WebSocket connection
- Entry point: OAuth callback (expired token replay) then WebSocket upgrade at `/api/live/ws` (empty Origin bypass)
- Sink: Grafana Live channel subscriptions delivering real-time data to the attacker's WebSocket client
- Creativity signal: Both SPEC-GAP-005 and SPEC-GAP-001 were analyzed independently. SPEC-GAP-005 was dropped due to the "requires valid session" prerequisite. SPEC-GAP-001 provides exactly that prerequisite. Chaining the two transforms a "dropped" finding into a viable attack path. The WebSocket persistence angle means the attacker does not need to repeatedly replay the token — a single replay grants a long-lived data exfiltration channel.

---

*End of Batch 1 — 7 hypotheses submitted*
*Cross-mode combinations: H-01 (Mode 7+1), H-04 (Mode 1+5, triple chain), H-05 (Mode 7+4), H-07 (Mode 1+4+3)*

---

## Round 1 -- Tracing

*Tracer: chamber-trace-01*
*Timestamp: 2026-03-20T00:00:00Z*

CodeQL artifact status: `security/codeql-artifacts/call-graph-slices.json` loaded -- 8 slices. SLICE-006 (CFD-2, RBAC scope injection) and SLICE-008 (CFD-4, CSRF bypass) are the only authentication-domain slices directly relevant to these hypotheses. FLOW-007 (`ext_jwt.go:346`) in `flow-paths-all-severities.md` is relevant to H-07's second step. No SLICE exists for the OIDC/JWT paths in H-01 through H-05. Manual tracing performed for all hypotheses.

---

### [TRACER] Evidence for H-01 -- 2026-03-20T00:00:00Z

**Reachability: REACHABLE**

Code path (generic_oauth, `validate_id_token=true`, `jwk_set_url` configured -- the security-conscious path):
1. `pkg/login/social/connectors/generic_oauth.go:440` -- `if s.info.ValidateIDToken && s.info.JwkSetURL != ""` -- when both are set (non-default), execution enters the signature validation branch
2. `pkg/login/social/connectors/generic_oauth.go:442` -- `rawJSON, err = s.validateIDTokenSignature(ctx, http.DefaultClient, idTokenString, s.info.JwkSetURL)` -- delegates to signature check
3. `pkg/login/social/connectors/social_base.go:452-453` -- `validateIDTokenSignature` calls `validateIDTokenSignatureWithURLs(ctx, client, idTokenString, []string{jwkSetURL})`
4. `pkg/login/social/connectors/social_base.go:388-394` -- `jwt.ParseSigned(idTokenString, allowedAlgorithms)` -- parses token structure (rejects alg:none)
5. `pkg/login/social/connectors/social_base.go:428-429` -- `var claims map[string]any` then `parsedToken.Claims(key, &claims)` -- verifies cryptographic signature and decodes payload into a generic map; signature IS cryptographically verified here
6. `pkg/login/social/connectors/social_base.go:438-442` -- on successful signature check: `rawJSON, err := json.Marshal(claims); return rawJSON, nil` -- returns the claim bytes directly with NO call to any registered-claims validation function
7. `pkg/login/social/connectors/generic_oauth.go:456` -- `return s.parseUserInfoFromJSON(rawJSON, "id_token"), nil` -- the payload (containing unvalidated exp/iss/aud) is used directly for authentication identity

Identical pattern confirmed in:
- `pkg/login/social/connectors/gitlab_oauth.go:295-308` -- same `if s.info.ValidateIDToken && s.info.JwkSetURL != ""` branch, same `validateIDTokenSignature` call, no post-call registered-claims check
- `pkg/login/social/connectors/google_oauth.go:265-278` -- identical pattern
- `pkg/login/social/connectors/okta_oauth.go:135-143` -- same conditional, same call path, no registered-claims validation

Sanitizers on path:
- `pkg/login/social/connectors/social_base.go:389-394` -- Algorithm allow-list prevents `alg:none`. NOT bypassable.
- `pkg/login/social/connectors/social_base.go:399-401` -- Empty JWT headers check. NOT bypassable.
- `pkg/login/social/connectors/social_base.go:428-429` -- `parsedToken.Claims(key, &claims)` performs JWKS-based cryptographic signature verification. NOT bypassable for forgery without the private key.
- **MISSING:** No registered-claims validation (`Claims.Validate()` or equivalent) after signature verification. The `map[string]any` decode target does not trigger automatic time/audience validation in go-jose -- only the cryptographic check occurs. An expired token, a cross-audience token, or a wrong-issuer token passes as long as the signing key is trusted.

CodeQL slice: No entry in call-graph-slices.json for this specific path. FLOW-007 (`ext_jwt.go:346`) covers a different component. Manual trace only.
On-demand query: none

**Assessment:** REACHABLE. The `validateIDTokenSignatureWithURLs` function at `social_base.go:388-449` verifies the JWT signature via JWKS (correct) but decodes claims into `map[string]any`. The go-jose `parsedToken.Claims(key, &claims)` method on a map target only performs cryptographic verification and JSON decoding -- it does NOT call `Claims.Validate()`. No Grafana code calls registered-claims validation after this function. An attacker who possesses any ID token signed by the same JWKS key -- including tokens issued for other applications sharing the same IdP (audience confusion) or tokens that are expired -- can replay them. The IdP's JWKS is the only trust anchor and it is checked; everything else (exp, iss, aud) is not. Note: the attack entry point is constrained by the OAuth2 code flow (the Advocate correctly identifies this), but the code-level gap is confirmed and constitutes a spec violation (OIDC Core 1.0 Section 3.1.3.7 requirements 5-9).

---

### [TRACER] Evidence for H-02 -- 2026-03-20T00:00:00Z

**Reachability: PARTIAL** (template injection is not achievable; scope string manipulation via colon-containing values is real but constrained)

Code path:
1. `pkg/services/accesscontrol/middleware.go:71-74` -- `evaluator.MutateScopes(ctx, scopeInjector(scopeParams{OrgID: user.GetOrgID(), URLParams: web.Params(c.Req)}))` -- URL params from the HTTP request passed to scope injector
2. `pkg/services/accesscontrol/scope.go:89-91` -- `Parameter(key)` returns `{{ index .URLParams ":key" }}` -- a Go template expression; this is the SCOPE TEMPLATE string, server-defined at route registration
3. `pkg/services/accesscontrol/middleware.go:411-419` -- `tmpl.Parse(scope)` parses the server-defined scope template; `tmpl.Execute(&buf, params)` executes with `params.URLParams[":key"]` as DATA
4. `pkg/services/accesscontrol/evaluator.go:110-120` -- the resulting scope string (e.g., `dashboards:uid:<URL_PARAM_VALUE>`) replaces the template in the evaluator

Template injection analysis:
- The URL param value is injected as template DATA via `{{ index .URLParams ":key" }}`, NOT as a template string itself. Go's `text/template` does NOT re-parse data values as template directives. Even if the URL param contains `{{.OrgID}}`, it is output as the literal string `{{.OrgID}}`.
- Colon-injection: a URL param value containing `:` would produce a scope like `dashboards:uid:evil:suffix`. The `SplitScope` function at `scope.go:26` uses `strings.Join(fragments[2:], ":")` for identifiers -- the identifier part CAN contain colons. The scope `dashboards:uid:evil:suffix` would be treated as identifier `evil:suffix`.

Sanitizers on path:
- `pkg/services/accesscontrol/middleware.go:411` -- `template.New("scope").Parse(scope)` parses the SCOPE TEMPLATE (server-defined), not user input. The user value enters only as DATA.
- Go's `text/template` data isolation: template injection through DATA values is architecturally impossible in Go's template engine.
- Permission matching: the injected scope must match a permission the user actually holds in the database. An attacker can CHOOSE which scope is checked but cannot GRANT themselves a permission that does not exist.

CodeQL slice: SLICE-006 (CFD-2) -- `RBAC Scope Injection via URL Params`, risk: HIGH, confirmed in call-graph-slices.json. The slice confirms the path exists; the analysis here determines the actual impact.
On-demand query: none

**Assessment:** PARTIAL. The `text/template` injection concern is NOT reachable -- Go templates do not re-parse data. The scope string manipulation via colon-containing URL values IS reachable (the param value is inserted verbatim into the scope string) but the security impact is constrained: the attacker can only cause a different scope to be evaluated, and that scope must match a permission they already hold. This does not enable privilege escalation. The SLICE-006 finding is architecturally correct (user URL params flow into scope evaluation) but the exploitability is lower than RBAC bypass.

---

### [TRACER] Evidence for H-03 -- 2026-03-20T00:00:00Z

**Reachability: UNREACHABLE** (as described -- see Assessment)

Code path (permission cache claim):
1. `pkg/services/accesscontrol/acimpl/accesscontrol.go:77` -- `evaluator.MutateScopes(ctx, a.resolvers.GetScopeAttributeMutator(user.GetOrgID()))` -- scope attribute resolution may use a cache
2. `pkg/services/accesscontrol/middleware.go:80` -- `ac.Evaluate(ctx, user, injected)` -- checks user permissions from `user.GetPermissions()` -- this is the user's PERMISSION MAP, not a separate TTL-cached lookup
3. The scope resolver cache (`InvalidateResolverCache` at `resolvers.go:96-101`) caches scope attribute translations (e.g., dashboard UID to numeric ID). This is NOT the user permission assignment.

Sanitizers on path:
- User permissions come from `user.GetPermissions()` which is loaded during the authentication/identity resolution phase, not from a separate TTL permission cache. Role changes take effect when the session is refreshed.
- The scope attribute resolver cache with TTL caches RESOURCE attribute lookups, not user PERMISSION grants.

CodeQL slice: No SLICE for this specific claim. Manual trace.
On-demand query: none

**Assessment:** UNREACHABLE as described. The hypothesis conflates two different caches. The `InvalidateResolverCache` mechanism at `resolvers.go:96-101` manages a scope resolver cache for attribute translation (not permission storage). The user's actual permissions at `ac.Evaluate()` come from `user.GetPermissions()` which is loaded during authentication. Permission changes require re-authentication or session refresh, not just cache invalidation. The HA distributed cache amplification argument is moot because no per-user permission grant is stored in the TTL cache. However, if session-level permission caching exists (permissions loaded once at session creation and not refreshed mid-session), a different window would exist -- but that is not what the hypothesis describes.

---

### [TRACER] Evidence for H-04 -- 2026-03-20T00:00:00Z

**Reachability: PARTIAL**

The chain has three components. Each is traced separately.

**Component A: CSRF bypass**

Code path:
1. `pkg/middleware/csrf/csrf.go:38-43` -- `csrf_additional_headers` loaded from config into `c.headers` map (empty by default)
2. `pkg/middleware/csrf/csrf.go:77-81` -- `if _, err := r.Cookie(c.cfg.LoginCookieName); errors.Is(err, http.ErrNoCookie) { return nil }` -- skip when no session cookie
3. `pkg/middleware/csrf/csrf.go:102-107` -- `o := r.Header.Get("Origin"); if o == "" { return nil }` -- CSRF check is ALSO skipped when Origin header is absent, independent of cookie state
4. `pkg/middleware/csrf/csrf.go:113` -- `origin := originURL.Hostname()` -- attacker-controlled Origin parsed
5. `pkg/middleware/csrf/csrf.go:116-126` -- for each configured additional header: `customHost := r.Header.Get(h)` (attacker-controlled), `addr.Host` extracted, compared to `origin`. If equal: `trustedOrigin = true`

Two distinct CSRF bypass paths:
- Path A1 (requires `csrf_additional_headers` configured): attacker sets both Origin and the custom header to the same value
- Path A2 (always available): Origin header absent -- line 102-107 returns nil regardless; this requires no configuration

**Component B: X-DS-Authorization header forwarding**

Code path:
1. `pkg/api/pluginproxy/ds_proxy.go:230` -- `dsAuth := req.Header.Get("X-DS-Authorization")`
2. `pkg/api/pluginproxy/ds_proxy.go:231-233` -- `if len(dsAuth) > 0 { req.Header.Del("X-DS-Authorization"); req.Header.Set("Authorization", dsAuth) }` -- attacker-supplied value directly overrides Authorization header to backend. No validation.

REACHABLE for authenticated users with `datasources:query` permission.

**Component C: Hop-by-hop header injection**

Go's `httputil.ReverseProxy` (used at `ds_proxy.go:162`) automatically removes hop-by-hop headers per RFC 7230 Section 6.1. Headers listed in a `Connection` header are stripped before forwarding. This component is NOT reachable via the stdlib reverse proxy.

Sanitizers on path:
- `pkg/middleware/csrf/csrf.go:77-81` -- Cookie check: still runs for A1 and A2 paths. CSRF attacks require the session cookie to be present.
- SameSite=Lax (default at `pkg/setting/setting.go`) -- browsers do not send session cookies on cross-origin POST/PUT/DELETE requests. This blocks the CSRF premise for default-config deployments.
- `csrf_additional_headers` being empty by default blocks Path A1.
- Go stdlib reverse proxy strips hop-by-hop headers, blocking Component C.

CodeQL slice: SLICE-008 (CFD-4, CSRF bypass) and FLOW-009 (csrf.go:122,135) confirm the path. FLOW-010 confirms X-DS-Authorization forwarding at `ds_proxy.go:230-233`.
On-demand query: none

**Assessment:** PARTIAL. The CSRF bypass logic at `csrf.go:116-126` is confirmed flawed -- it compares two attacker-controlled values. Additionally, the empty-Origin bypass at `csrf.go:102-107` is a separate and always-available path. The X-DS-Authorization forwarding at `ds_proxy.go:230-233` is confirmed. However, the hop-by-hop injection (Component C) is NOT reachable due to Go stdlib reverse proxy stripping. The full chain degrades to: CSRF bypass (requires non-default config OR Origin-suppression capability) + X-DS-Authorization credential injection (for authenticated users). SameSite=Lax (default) blocks the CSRF premise for standard browser-based attacks.

---

### [TRACER] Evidence for H-05 -- 2026-03-20T00:00:00Z

**Reachability: REACHABLE** (same code path as H-02 analysis but for H-05's JWT missing exp framing)

Code path (`auth.jwt` enabled, token omits `exp` field):
1. `pkg/services/auth/jwt/auth.go:69` -- `AuthService.Verify(ctx, strToken)` -- JWT auth entry point
2. `pkg/services/auth/jwt/auth.go:73-77` -- `jwt.ParseSigned(strToken, allowedAlgorithms)` -- parses; rejects `alg:none`
3. `pkg/services/auth/jwt/auth.go:79-86` -- key lookup; requires token signed with configured key
4. `pkg/services/auth/jwt/auth.go:91` -- `token.Claims(key, &claims)` where `claims` is `map[string]any` -- verifies signature; decodes payload into map
5. `pkg/services/auth/jwt/auth.go:101` -- `s.validateClaims(claims)` called
6. `pkg/services/auth/jwt/validation.go:55-117` -- `validateClaims()` iterates the claims map with `for key, value := range claims`; `switch key` only processes keys PRESENT in the map
7. `pkg/services/auth/jwt/validation.go:86-95` -- `case "exp":` executes only when the literal string `"exp"` exists as a key in the claims map. Absent `exp` field means this case is never entered; `registeredClaims.Expiry` stays `nil`.
8. `pkg/services/auth/jwt/validation.go:119-121` -- `expectRegistered.Time = time.Now(); registeredClaims.Validate(expectRegistered)` -- calls go-jose validation
9. `/Users/tuan.v.tran/go/pkg/mod/github.com/go-jose/go-jose/v4@v4.1.3/jwt/validation.go:116` -- library source: `if c.Expiry != nil && validationTime.Add(-leeway).After(c.Expiry.Time()) { return ErrExpired }` -- nil guard means expiry check is skipped when `Expiry` is nil

Sanitizers on path:
- `pkg/services/auth/jwt/auth.go:73-77` -- Algorithm allow-list blocks `alg:none`. NOT bypassable.
- `pkg/services/auth/jwt/auth.go:79-86` -- Key lookup: requires token signed with configured key. NOT bypassable without key.
- `pkg/services/auth/jwt/validation.go:86-95` -- `case "exp"` guard: BYPASSABLE by omitting `exp` from JWT payload JSON.
- `/Users/tuan.v.tran/go/pkg/mod/github.com/go-jose/go-jose/v4@v4.1.3/jwt/validation.go:116` -- Library nil guard: BYPASSABLE as a consequence of the missing key leaving `Expiry` nil.

Additional tracing (stored-backdoor aspects):
- No `jti`-based replay prevention in `validateClaims()` at `validation.go:55-117` -- no used-token tracking.
- `iat` (IssuedAt) is validated to not be in the future (`validation.go:106-115`) but there is no maximum age requirement.
- JWT-authenticated sessions are stateless; no server-side session exists to revoke for JWT-authenticated requests.

CodeQL slice: No dedicated SLICE. FLOW-007 is for `ext_jwt.go`, a different component. Manual trace with library source verification.
On-demand query: none

**Assessment:** REACHABLE. The `switch key` loop pattern means absent JWT claims skip validation. An attacker with a token signed by the configured key and omitting `exp` obtains a permanently valid credential. The go-jose library at `/Users/tuan.v.tran/go/pkg/mod/github.com/go-jose/go-jose/v4@v4.1.3/jwt/validation.go:116` confirms the nil-guard behavior. No `jti` replay prevention exists. The stored-backdoor scenario is code-confirmed: there is no mechanism to invalidate specific JWT tokens short of key rotation.

---

### [TRACER] Evidence for H-06 -- 2026-03-20T00:00:00Z

**Reachability: UNREACHABLE**

Code path:
1. `pkg/services/accesscontrol/middleware.go:37` -- `if c.AllowAnonymous` -- block only runs for routes allowing anonymous access
2. `pkg/services/accesscontrol/middleware.go:38-39` -- `forceLogin` parsed from query; `orgId` parsed from query
3. `pkg/services/accesscontrol/middleware.go:40-42` -- if `orgID != c.GetOrgID()`, `forceLogin = true`
4. `pkg/services/accesscontrol/middleware.go:44` -- `if !c.IsSignedIn && forceLogin { unauthorized(c); return }` -- blocks non-signed-in users with forceLogin

Authentication context for anonymous users:
5. `pkg/services/contexthandler/contexthandler.go:146` -- `reqContext.IsSignedIn = !reqContext.IsAnonymous` -- for anonymous users, `IsSignedIn = false`
6. `pkg/services/contexthandler/contexthandler.go:147` -- `reqContext.AllowAnonymous = reqContext.IsAnonymous` -- for anonymous users, `AllowAnonymous = true`

For an anonymous user with `?orgId=2` (different from home org 1):
- `AllowAnonymous = true` enters the block at line 37
- `orgID != c.GetOrgID()` is true; `forceLogin = true` at line 41
- `IsSignedIn = false` for anonymous users
- Condition at line 44: `!false && true` = `true` -- `unauthorized(c)` called

Sanitizers on path:
- `pkg/services/accesscontrol/middleware.go:44` -- `!c.IsSignedIn && forceLogin` guard. NOT bypassable for anonymous users because `contexthandler.go:146` ensures `IsSignedIn = false` for any anonymous identity. The only way to break this invariant would require a context handler bug.

CodeQL slice: No SLICE. Manual trace.
On-demand query: none

**Assessment:** UNREACHABLE. The hypothesis's precondition ("anonymous user is treated as signed-in with IsSignedIn=true") is factually incorrect. The context handler at `contexthandler.go:146` sets `IsSignedIn = !IsAnonymous`, guaranteeing `IsSignedIn = false` for all anonymous users. The middleware at `middleware.go:44` uses exactly this invariant to block cross-org access via `orgId`. H-06 is disproved by direct code reading.

---

### [TRACER] Evidence for H-07 -- 2026-03-20T00:00:00Z

**Reachability: REACHABLE** (dependent on H-01's code-confirmed gap; WebSocket step independently confirmed)

Step 1 -- Session acquisition (depends on H-01):
- Code path confirmed REACHABLE in H-01 trace. Missing registered-claims validation in `validateIDTokenSignatureWithURLs` allows expired/cross-audience tokens accepted from IdP token endpoint (requires compromised or misconfigured IdP, or MITM on token endpoint).

Step 2 -- WebSocket empty-Origin bypass:
1. `pkg/services/live/live.go:535-540` -- `getCheckOriginFunc()` returns the upgrader origin check function
2. `pkg/services/live/live.go:537` -- `origin := r.Header.Get("Origin")`
3. `pkg/services/live/live.go:538-540` -- `if origin == "" { return true }` -- unconditional acceptance with no Origin header

Step 3 -- Session persistence:
4. Sessions created via OAuth are stored server-side as Grafana session tokens. They persist for the configured session TTL (default: 30 days via `login_maximum_lifetime_duration`).
5. No IdP token revocation check occurs after session creation -- Grafana sessions are independent of OIDC token validity.
6. WebSocket connections established with a valid session persist until the connection is closed, independent of session TTL.

Sanitizers on path:
- `live.go:538-540` -- Empty-Origin early return. NOT a sanitizer -- it IS the bypass.
- `reqSignedIn` middleware on `/api/live/ws` at `live.go:389` -- requires a valid Grafana session. This is satisfied by Step 1.
- Session TTL -- limits session duration but does not prevent the attack during the TTL window.

CodeQL slice: SLICE-008 covers CSRF. FLOW-007 covers ext_jwt.go. No SLICE for the live.go component specifically. Manual trace for WebSocket step.
On-demand query: none

**Assessment:** REACHABLE. The WebSocket empty-Origin bypass at `live.go:538-540` is confirmed independently. The chain's viability depends on Step 1 (H-01), which is code-confirmed as a gap but constrained by the OAuth2 authorization code flow (requires IdP-level compromise per the Advocate's analysis). The session persistence aspect is architecturally confirmed: Grafana sessions created via OAuth are independent of IdP token validity after creation. If Step 1 is achievable (compromised or misconfigured IdP), the chain produces a persistent WebSocket data exfiltration channel that survives IdP-side revocation.

---

*End of Round 1 Tracing -- 7 hypotheses traced*

*Verdicts summary:*
- *H-01: REACHABLE (OIDC sig-verify path missing registered-claims validation for exp/iss/aud)*
- *H-02: PARTIAL (template injection NOT achievable; scope colon-injection reachable but low-impact)*
- *H-03: UNREACHABLE (hypothesis conflates scope resolver cache with user permission storage)*
- *H-04: PARTIAL (CSRF bypass confirmed via two paths; X-DS-Authorization confirmed; hop-by-hop NOT reachable via stdlib proxy)*
- *H-05: REACHABLE (JWT absent `exp` -- nil Expiry passes go-jose validation; no jti replay prevention)*
- *H-06: UNREACHABLE (anonymous IsSignedIn=false invariant blocks cross-org orgId switching)*
- *H-07: REACHABLE (WebSocket empty-Origin bypass confirmed; chain requires H-01's IdP-level prerequisite)*

---

## Devil's Advocate Analysis

### [ADVOCATE] Defense Brief for H-01 -- 2026-03-20T12:00:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go type system: oauth2.Token is returned by Exchange(), not constructed by attacker | Yes | `pkg/services/authn/clients/oauth.go:165` |
| Framework | OAuth2 authorization code flow: state cookie + code exchange required | Yes | `pkg/services/authn/clients/oauth.go:117-131,165` |
| Middleware | State cookie verification: hashed state must match IdP callback parameter | Yes | `pkg/services/authn/clients/oauth.go:127-131` |
| Application | ID token comes from IdP token endpoint response, not from attacker input | Yes | `pkg/login/social/connectors/generic_oauth.go:440-442` |
| Documentation | N/A -- no docs found on this specific behavior | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- The hypothesis assumes the attacker can directly present an ID token to the OAuth callback. In reality, the OAuth callback at `oauth.go:105-168` requires: (1) a valid state cookie set during the authorization redirect, (2) a matching state parameter from the IdP, and (3) an authorization code that is exchanged with the IdP's token endpoint. The ID token is extracted from the IdP's token endpoint response (`token.Extra("id_token")`), NOT from attacker-supplied input. The attacker cannot inject a crafted/expired/cross-application token because they do not control the IdP token endpoint response.
- Pattern 2 (phantom validation): MATCH -- The OAuth state validation at `oauth.go:117-131` is a critical gating protection that the hypothesis completely overlooks. Without a valid state cookie (set during Grafana-initiated redirect), the callback is rejected before any token processing occurs.
- Pattern 3 (framework protection): MATCH -- The standard OAuth2 authorization code flow inherently prevents direct token injection. The `Exchange()` call at line 165 sends the authorization code to the IdP, and the IdP returns the token. The attacker would need to compromise the IdP's token endpoint to inject a crafted ID token.
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): checked -- not applicable
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** The hypothesis fundamentally misunderstands the OAuth2 flow. The attack chain states the attacker "presents this cross-application, expired token to the production Grafana OAuth callback." This is impossible because:

1. The OAuth callback endpoint requires an authorization code (from query param `code`), not a raw ID token.
2. Grafana exchanges this authorization code with the IdP's token endpoint (`connector.Exchange()`).
3. The ID token is embedded in the TOKEN RESPONSE from the IdP, not supplied by the attacker.
4. The attacker cannot control what the IdP returns in its token response.
5. Even if the attacker had a valid authorization code, the code is bound to the client_id that initiated the flow, and a cross-application code would fail at the IdP's token endpoint.

The `validateIDTokenSignature` function at `social_base.go:388-449` only processes the ID token AFTER it has been obtained from the IdP via the authorization code exchange. The missing exp/aud/iss validation is only relevant if the IdP's own token endpoint returns malformed tokens, which is an IdP-side issue, not a Grafana vulnerability.

**Verdict recommendation:** Disproved by Framework protection (OAuth2 authorization code flow prevents direct token injection)

---

### [ADVOCATE] Defense Brief for H-02 -- 2026-03-20T12:01:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `text/template` template is the SCOPE string (server-defined), not user input | Yes | `pkg/services/accesscontrol/scope.go:89-91` |
| Framework | Template is pre-built using `Parameter()` which generates `{{ index .URLParams ":key" }}` -- the URL param VALUE is substituted, not parsed as template | Yes | `pkg/services/accesscontrol/middleware.go:409-421` |
| Middleware | none | N/A | N/A |
| Application | Scope definitions are hardcoded at route registration time, not user-controlled | Yes | `pkg/services/accesscontrol/scope.go:89-91`, `pkg/services/accesscontrol/models.go:539` |
| Documentation | N/A -- no docs on this specific mechanism | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- The hypothesis conflates the template STRING (which is server-defined) with the template DATA (which includes URL params). The `scope` variable at line 411 is the template string like `dashboards:uid:{{ index .URLParams ":uid" }}`. This string is hardcoded at route registration time via `Parameter(":uid")` at `scope.go:89-91`. The URL parameter VALUE (e.g., `abc123`) is injected as DATA into the template, not as template syntax. Go's `text/template` does NOT re-parse data values as template directives.
- Pattern 2 (phantom validation): checked -- not applicable
- Pattern 3 (framework protection): MATCH -- Go's `text/template` engine fundamentally separates template code from template data. When `tmpl.Execute(&buf, params)` runs, the `params.URLParams[":uid"]` value is treated as a plain string and written to the output buffer. Even if the URL param contains `{{.OrgID}}`, it is NOT parsed as a template directive -- it is output as the literal string `{{.OrgID}}`. This is how ALL Go template engines work by design.
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): checked -- not applicable
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** This hypothesis is based on a fundamental misunderstanding of how Go's `text/template` works. The template injection scenario described is impossible because:

1. The TEMPLATE STRING is server-defined at route registration time (e.g., `dashboards:uid:{{ index .URLParams ":uid" }}`). It is constructed via `Parameter()` at `scope.go:89-91` which uses `fmt.Sprintf` to build the template literal.
2. The URL parameter VALUE is injected as DATA, not as template code. Go templates parse the template string once (`template.New("scope").Parse(scope)`) and then execute it with data. The data values are never re-parsed as template syntax.
3. An attacker crafting a URL param like `:uid = {{.OrgID}}` would result in the scope string `dashboards:uid:{{.OrgID}}` being written as a LITERAL string -- because `{{ index .URLParams ":uid" }}` evaluates to the string `{{.OrgID}}` which is output verbatim, not re-interpreted.
4. The hypothesis itself acknowledges this limitation: "The URL parameter VALUE is substituted INTO the template output, not parsed as a template itself."

The `text/template` usage is safe here because the template is static and only data is dynamic.

**Verdict recommendation:** Disproved by Language protection (Go text/template does not re-parse data as template code)

---

### [ADVOCATE] Defense Brief for H-03 -- 2026-03-20T12:02:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | N/A | N/A |
| Framework | none | N/A | N/A |
| Middleware | none | N/A | N/A |
| Application | `InvalidateResolverCache` exists but is local-only (per-pod) for scope resolution cache, not permission cache | Partial | `pkg/services/accesscontrol/resolvers.go:96-101` |
| Documentation | N/A -- no docs found accepting this as known risk | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- The hypothesis confuses TWO different caches. The `InvalidateResolverCache` at `resolvers.go:96-101` is for SCOPE RESOLUTION (e.g., translating `dashboards:uid:abc` to `dashboards:id:123`), NOT for user PERMISSIONS. The RBAC permission evaluation at `middleware.go:80` calls `ac.Evaluate()` which checks the user's permission map directly from `user.GetPermissions()` -- it does not cache permission evaluation results with a TTL. The 5-second TTL cache referenced in the hypothesis (localcache) is for scope attribute resolution, not for role/permission assignments.
- Pattern 2 (phantom validation): checked -- MATCH: User permissions are fetched from the identity/session on each request, not from a separate cache with a TTL. Role changes take effect when the user's session is re-resolved, which happens on each request through the authn middleware.
- Pattern 3 (framework protection): checked -- not applicable
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): checked -- not applicable
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** The hypothesis conflates scope resolution caching with permission caching. The code path is:

1. RBAC middleware at `middleware.go:71-74` calls `scopeInjector` to substitute URL params into scope templates -- this is NOT cached.
2. `ac.Evaluate()` at `middleware.go:80` checks user permissions against the evaluated scope.
3. `acimpl/accesscontrol.go:77` calls `evaluator.MutateScopes(ctx, a.resolvers.GetScopeAttributeMutator(...))` which may use a local cache for scope attribute resolution (e.g., resolving a dashboard UID to an ID). This cache has a TTL but it caches resource lookups, not user permissions.
4. The user's actual permissions come from `user.GetPermissions()` which is populated during authentication, not from a separate TTL cache.

Even if the scope resolver cache were poisoned, this would NOT allow a revoked user to maintain access because the permission check itself (does user X have permission Y for scope Z) is not cached -- only the scope translation is cached.

However, there IS a valid concern about session-level permission caching -- user permissions loaded at session creation may persist until session refresh. But this is a fundamentally different mechanism from the one described in the hypothesis.

**Verdict recommendation:** Disproved by Pattern 1 (no path trace) -- the hypothesis incorrectly identifies the cache mechanism and its security impact

---

### [ADVOCATE] Defense Brief for H-04 -- 2026-03-20T12:03:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | N/A | N/A |
| Framework | SameSite=Lax cookie default blocks cross-origin POST requests | Partial | `pkg/setting/setting.go:1818-1831` (default "lax") |
| Middleware | CSRF check skips requests without login cookie | No | `pkg/middleware/csrf/csrf.go:77-81` |
| Application | `csrf_additional_headers` is NOT configured by default (empty) | Partial | `pkg/middleware/csrf/csrf.go:38` |
| Documentation | N/A -- no docs found | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- not applicable
- Pattern 2 (phantom validation): checked -- not applicable
- Pattern 3 (framework protection): MATCH -- SameSite=Lax is the default cookie setting at `setting.go:1818`. With SameSite=Lax, the browser will NOT send the session cookie on cross-origin POST requests (which are the state-mutating requests this attack targets). The hypothesis acknowledges this: "SameSite=Lax cookie may block this for POST requests from cross-origin."
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): MATCH -- The attack requires `csrf_additional_headers` to be configured, which is NOT a default setting. The default value is empty (`csrf.go:38` reads from config with `Strings(" ")` which returns empty when not configured). An operator must explicitly configure this non-default setting.
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** This attack chain has multiple prerequisites that make it impractical:

1. **SameSite=Lax (default):** The default cookie policy is `SameSite=Lax` (`setting.go:1818`). This means the browser will NOT attach the Grafana session cookie to cross-origin POST/PUT/DELETE requests. The CSRF bypass is irrelevant if the cookie is never sent.

2. **csrf_additional_headers must be configured:** The attack requires `csrf_additional_headers = X-Forwarded-Host` which is NOT a default configuration. When this is empty (default), the CSRF check at `csrf.go:116-126` never enters the custom header comparison loop, and the check falls through to the `hostnameMatches` comparison at line 135-136.

3. **CSRF check line 104-107:** The CSRF middleware returns `nil` (skip) when the Origin header is empty. For cross-origin requests where the browser DOES send an Origin header, the check compares `origin == netAddr.Host` (line 135). The custom header bypass at lines 116-126 ONLY applies when `csrf_additional_headers` is explicitly configured.

4. **X-DS-Authorization requires an existing authenticated session:** The datasource proxy requires an authenticated session (`middleware.ReqSignedIn`). The CSRF attack scenario assumes the victim's browser sends the session cookie -- but SameSite=Lax prevents this for cross-origin POST.

5. **Hop-by-hop header stripping:** The `Connection: X-Internal-Auth` trick assumes the downstream server interprets `Connection` headers for hop-by-hop filtering. Many reverse proxies and HTTP/2 connections strip `Connection` headers entirely.

**Verdict recommendation:** Disproved by Framework protection (SameSite=Lax default) + FP Pattern 6 (config-as-vuln: requires non-default csrf_additional_headers)

---

### [ADVOCATE] Defense Brief for H-05 -- 2026-03-20T12:04:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | N/A | N/A |
| Framework | go-jose/v4 `Validate()` with `Expected.Time = time.Now()` enforces exp WHEN present | Partial | `pkg/services/auth/jwt/validation.go:119-122` |
| Middleware | JWT auth must be explicitly enabled (`auth.jwt` config section) | No (config gate, not security control) | `pkg/services/auth/jwt/auth.go:37` |
| Application | `expectClaims` configuration allows operators to require specific claims like `exp` | Partial | `pkg/services/auth/jwt/validation.go:12-53` |
| Documentation | N/A -- no docs found stating this is intentional | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked -- not applicable
- Pattern 2 (phantom validation): checked -- The `initClaimExpectations` function at `validation.go:12-53` allows operators to define expected claims via the `expect_claims` configuration. If an operator configures `expect_claims = {"exp": ...}`, the claim IS validated. However, the `exp` claim is a registered claim handled specially -- the expectation system at lines 17-50 handles `iss`, `sub`, and `aud` but does NOT explicitly handle `exp` as an expected claim (it is handled separately in `validateClaims`). The defense is that `exp` validation occurs at line 86-95 when the `exp` claim IS present in the token.
- Pattern 3 (framework protection): checked -- not applicable
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): MATCH -- JWT auth is a non-default feature that must be explicitly enabled. Furthermore, the scenario requires: (1) HMAC shared secret configuration, (2) an integrating service that omits `exp`, (3) the JWT appearing in logs, and (4) the HMAC key never being rotated. This is a chain of operator misconfigurations.
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** While the code does technically allow JWTs without `exp` claims (validated at `validation.go:86-89` where `value == nil` causes a `continue`, skipping expiry enforcement), several mitigating factors reduce the practical impact:

1. **JWT auth is non-default:** The `auth.jwt` section must be explicitly enabled. This is not a default attack surface.

2. **HMAC is one of several key types:** The scenario specifically requires HMAC shared secrets. RSA/ECDSA key pairs are more commonly used and do not share the key between Grafana and the issuing service.

3. **The token must leak:** The second-order attack requires the JWT to appear in logs. Well-configured systems mask Authorization headers in access logs.

4. **Operator responsibility:** If an operator configures JWT auth with an HMAC shared secret and uses tokens without `exp`, this is an operational decision, not a Grafana vulnerability. Many JWT standards consider `exp` optional (RFC 7519 Section 4.1.4: "The use of this claim is OPTIONAL").

5. **The `expect_claims` mechanism exists:** Operators CAN require specific claims through configuration.

However, I must acknowledge that the default behavior of silently accepting tokens without `exp` is a defense-in-depth gap. A well-designed system should either enforce `exp` by default or prominently warn operators. The code at lines 86-89 explicitly checks `if value == nil { continue }` rather than returning an error, which is a deliberate design choice to allow tokens without expiry.

**Verdict recommendation:** Cannot disprove -- the code intentionally accepts JWTs without `exp` claims, and while exploitation requires multiple preconditions, the behavior itself is a genuine defense-in-depth weakness

---

### [ADVOCATE] Defense Brief for H-06 -- 2026-03-20T12:05:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | N/A | N/A |
| Framework | none | N/A | N/A |
| Middleware | Anonymous users have `IsSignedIn = false`, which triggers `unauthorized()` when orgId differs | Yes | `pkg/services/contexthandler/contexthandler.go:146-147` |
| Application | RBAC middleware: when `orgId` differs and `IsSignedIn` is false, returns 401 | Yes | `pkg/services/accesscontrol/middleware.go:37-47` |
| Documentation | N/A -- no docs on this specific interaction | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- The hypothesis claims "anonymous user is treated as signed-in with IsSignedIn=true" but the code shows the opposite. At `contexthandler.go:146`, `reqContext.IsSignedIn = !reqContext.IsAnonymous`. For anonymous users, `IsAnonymous` is `true`, so `IsSignedIn = false`. This directly contradicts the hypothesis precondition.
- Pattern 2 (phantom validation): MATCH -- The RBAC middleware at `middleware.go:37-48` performs this exact check: when `orgId` query parameter differs from the current org, `forceLogin` is set to `true` (line 41). Then at line 44: `if !c.IsSignedIn && forceLogin { unauthorized(c); return }`. Since anonymous users have `IsSignedIn = false` and `forceLogin = true` (due to orgId mismatch), they receive a 401 response. This protection explicitly prevents the described attack.
- Pattern 3 (framework protection): checked -- not applicable
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): checked -- not applicable
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): checked -- not applicable

**Defense argument:** The hypothesis has a critical factual error in its preconditions. It states "anonymous user is treated as signed-in with IsSignedIn=true" but the code shows:

1. `contexthandler.go:146`: `reqContext.IsSignedIn = !reqContext.IsAnonymous` -- anonymous users have `IsSignedIn = false`.
2. `contexthandler.go:147`: `reqContext.AllowAnonymous = reqContext.IsAnonymous` -- anonymous users have `AllowAnonymous = true`.
3. The RBAC middleware at `middleware.go:37-48` enters the `if c.AllowAnonymous` block for anonymous users.
4. Inside that block, when `orgId` differs from the current org, `forceLogin` is set to `true` (line 40-41).
5. The check at line 44 evaluates: `if !c.IsSignedIn && forceLogin` -- for anonymous users this is `if !false && true` = `if true`, so `unauthorized(c)` is called and the request is rejected.

This means anonymous users CANNOT switch orgs via the `orgId` query parameter. The middleware explicitly handles this case and returns a 401.

Furthermore, even if `AuthorizeInOrgMiddleware` were invoked, it calls `authnService.ResolveIdentity()` at line 257, which requires a valid user identity. Anonymous users would fail this resolution for non-home orgs.

**Verdict recommendation:** Disproved by Application protection (middleware.go:37-48 explicitly blocks anonymous org switching)

---

### [ADVOCATE] Defense Brief for H-07 -- 2026-03-20T12:06:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | N/A | N/A |
| Framework | OAuth2 authorization code flow prevents direct ID token injection (same as H-01) | Yes | `pkg/services/authn/clients/oauth.go:117-165` |
| Middleware | `/api/live/ws` requires `middleware.ReqSignedIn` -- must have valid session | Yes (for step 4-5 only) | `pkg/services/live/live.go:389` |
| Application | Empty Origin accepted in `getCheckOriginFunc` is a real bypass | No | `pkg/services/live/live.go:538-539` |
| Documentation | N/A -- no docs found | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH -- This chain DEPENDS on H-01 (OIDC expired token replay) as its first step. Since H-01 is disproved (the OAuth2 authorization code flow prevents direct token injection), the entire chain collapses. Without a valid session obtained via expired token replay, the attacker cannot reach the WebSocket endpoint.
- Pattern 2 (phantom validation): checked -- not applicable
- Pattern 3 (framework protection): MATCH -- Same as H-01: the OAuth2 flow prevents direct token injection.
- Pattern 4 (same-origin): checked -- not applicable
- Pattern 5 (CVE reachability): checked -- not applicable
- Pattern 6 (config-as-vuln): checked -- not applicable
- Pattern 7 (test code): checked -- not applicable
- Pattern 8 (double-counting): MATCH -- This hypothesis depends on H-01 as a prerequisite. If H-01 is disproved, H-07 cannot stand independently. The WebSocket empty Origin issue is a separate, standalone finding (SPEC-GAP-005) that was already analyzed and dropped due to "requires valid session."

**Defense argument:** This hypothesis explicitly chains H-01 (expired OIDC token replay) with SPEC-GAP-005 (WebSocket empty Origin). Since H-01 is disproved by the OAuth2 authorization code flow, the chain breaks at step 1.

Regarding the individual components:

1. **WebSocket auth requirement:** The `/api/live/ws` route is registered with `middleware.ReqSignedIn` at `live.go:389`, which requires a valid session. This means an attacker needs a legitimate session, not just a replayed token.

2. **Empty Origin bypass:** The `getCheckOriginFunc` at `live.go:538-539` does return `true` for empty Origin. However, this is relevant only for non-browser clients (browsers always send Origin on WebSocket upgrades). A non-browser client already has the session cookie/token, so the Origin check is not a meaningful additional security barrier -- the authentication check is the real gate.

3. **Session persistence after IdP revocation:** The concern about session persistence is valid in general but is not specific to this attack chain. All session-based systems have this property -- sessions persist until they expire or are explicitly revoked at the application level, regardless of the IdP state. Grafana supports session revocation through its own session management.

**Verdict recommendation:** Disproved by dependency on H-01 (which is itself disproved) + Pattern 8 (double-counting with SPEC-GAP-005)

---

*End of Devil's Advocate Analysis -- 7 defense briefs submitted*

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-20T13:00:00Z

**Prosecution summary**: `validateIDTokenSignatureWithURLs()` at social_base.go:385-449 verifies only cryptographic signature and returns raw claims without validating exp, iss, or aud. This violates OIDC Core 1.0 Section 3.1.3.7 requirements. Tokens issued for different client applications (audience confusion) and expired tokens with valid signatures are accepted by Grafana's validation function.

**Defense summary**: The Advocate demonstrates that the OAuth2 authorization code flow fundamentally prevents direct token injection. The ID token arrives within the server-to-server HTTPS token exchange response (oauth.go:165 `connector.Exchange()`), authenticated with client_secret, and the callback requires a valid state cookie (oauth.go:117-131). The attacker cannot present an arbitrary ID token to the callback -- they would need to compromise the IdP's token endpoint itself. Cross-audience confusion requires the IdP to return a token with the wrong audience, which is an IdP-side issue.

**Pre-FP Gate**:
1. Attacker control verified by Tracer? NO -- the Tracer confirmed the code path but the Advocate correctly showed the ID token comes from the IdP, not from attacker input. The attacker does not control the ID token content in the standard flow.
2. Framework protection searched by Advocate? YES -- OAuth2 authorization code flow, state cookie, client_secret exchange
3. Trust boundary crossing confirmed? PARTIAL -- the missing validation is real but not reachable from a normal attacker position
4. Exploitation requires normal attacker position? NO -- requires IdP compromise or token endpoint MITM
5. Vulnerable code ships to production? YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The Advocate correctly identifies that direct exploitation through the OAuth flow is blocked by the authorization code exchange. However, the missing exp/iss/aud validation remains a confirmed OIDC spec violation (Section 3.1.3.7) that creates a defense-in-depth gap. The scenario where it matters is: (1) IdP compromise or misconfiguration where the IdP returns stale/cross-audience tokens; (2) token response intercepted via logging middleware, CDN caching, or proxy inspection; (3) AzureAD connector correctly validates audience (azuread_oauth.go:432-434), proving the code pattern is known and applied inconsistently. Severity is MEDIUM because exploitation requires IdP-level compromise, not a normal attacker position, but the code-level fix is straightforward and the gap violates a MUST-level OIDC requirement.

**Finding draft written to**: security/findings-draft/p7-001-oidc-missing-claim-validation.md
**Registry updated**: AP-001 OIDC Missing Claim Validation

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-20T13:01:00Z

**Prosecution summary**: The scopeInjector at middleware.go:409-421 uses Go text/template to inject URL parameters into RBAC scope templates, potentially allowing template injection or wildcard scope escalation.

**Defense summary**: Go's text/template.Execute() does not re-parse data values as templates. The scope template is server-defined at route registration via Parameter() at scope.go:89-91. URL parameter values are substituted as DATA, not parsed as template directives. Additionally, wildcard `*` is only meaningful in the USER's permission scope (first argument to match()), not in the target scope. ValidateScope() at evaluator.go:66 validates the user's scope, rejecting metacharacters in non-terminal positions.

**Pre-FP Gate**: Failed on check-1: Attacker control does not reach the vulnerable pattern.

**Verdict: FALSE POSITIVE**
**Rationale**: Go's text/template engine safely substitutes data values without re-parsing them as template directives. The RBAC scope matching function match() at evaluator.go:61-85 treats wildcards only in the user's permission scope (the `scope` parameter), not in the target scope (the `target` parameter) derived from URL parameters. Template injection via URL params is architecturally impossible in Go's template engine.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-20T13:02:00Z

**Prosecution summary**: RBAC permission cache uses process-local TTL cache without distributed invalidation. In HA deployments, revoked permissions persist for up to 5 seconds per pod, and multiple pods multiply the effective window.

**Defense summary**: The Advocate identifies a critical factual error: the hypothesis conflates two different caches. InvalidateResolverCache at resolvers.go:96-101 is for SCOPE RESOLUTION (translating scope attributes), not for user PERMISSIONS. The RBAC permission evaluation at middleware.go:80 calls ac.Evaluate() which checks the user's permission map directly from user.GetPermissions() -- populated during authentication, not from a separate TTL cache. The 5-second TTL applies to scope attribute resolution, not permission assignments.

**Pre-FP Gate**: Failed on check-1: The cache mechanism described does not affect user permission assignments. User permissions come from the authenticated identity, not a TTL cache.

**Verdict: DROP**
**Rationale**: The hypothesis incorrectly identifies the cache mechanism and its security impact. The scope resolver cache (with TTL) caches resource attribute lookups (e.g., dashboard UID to ID translation), not user permission assignments. User permissions are loaded from the identity during authentication, and permission changes require session refresh. The HA amplification argument is moot because the relevant cache does not store permission grants.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-20T13:03:00Z

**Prosecution summary**: CSRF middleware at csrf.go:116-126 compares Origin hostname against a user-controlled custom header value from csrf_additional_headers config. Both values are attacker-controlled, enabling CSRF bypass. Chained with X-DS-Authorization header injection (SAST-007) and hop-by-hop forwarding (SPEC-GAP-004).

**Defense summary**: Three independent layers block exploitation: (1) csrf_additional_headers is empty by default; (2) SameSite=Lax (default at setting.go:1818) prevents cross-site POST cookies; (3) custom headers trigger CORS preflight which Grafana's default CORS config blocks. The Advocate correctly notes that without the session cookie being sent cross-site, the CSRF bypass is irrelevant.

**Pre-FP Gate**:
1. Attacker control verified? YES -- both Origin and custom header are attacker-controlled when configured
2. Framework protection searched? YES -- SameSite=Lax, CORS preflight, empty default config
3. Trust boundary crossing confirmed? YES -- TB2 CSRF protection
4. Normal attacker position? NO -- requires three non-default configurations
5. Vulnerable code ships to production? YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The CSRF comparison logic at csrf.go:116-126 is confirmed flawed -- it compares two attacker-controlled values. However, exploitation requires three non-default conditions: (1) csrf_additional_headers must be configured, (2) SameSite cookie must be changed from Lax, and (3) CORS must allow arbitrary origins. The code flaw is real and should be fixed (the comparison should be against the server's own hostname, not a user-supplied header value), but the default configuration blocks all known exploitation paths. Severity MEDIUM reflects the confirmed logic flaw with impractical default-config exploitation.

**Finding draft written to**: security/findings-draft/p7-002-csrf-header-comparison-bypass.md
**Registry updated**: AP-002 CSRF User-Controlled Comparison

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-20T13:04:00Z

**Prosecution summary**: JWT auth service's validateClaims() at validation.go:55-117 skips expiry enforcement when the "exp" key is absent from the token claims map. The exp case at line 86-88 is only entered when "exp" exists. If absent, registeredClaims.Expiry remains nil, and go-jose's Validate() at line 121 skips nil Expiry. A JWT without exp signed with the configured key grants permanent access.

**Defense summary**: The Advocate acknowledges the code behavior but notes: (1) JWT auth is opt-in (disabled by default); (2) requires key knowledge or possession of an already-signed token; (3) RFC 7519 Section 4.1.4 states exp is OPTIONAL; (4) the expect_claims mechanism exists for operators to enforce claims. However, the Advocate cannot disprove the finding -- the behavior is a genuine defense-in-depth weakness.

**Pre-FP Gate**:
1. Attacker control verified? YES -- JWT is directly in Authorization header, must be signed with configured key
2. Framework protection searched? YES -- default disabled, key possession required, expect_claims exists
3. Trust boundary crossing confirmed? YES -- TB2 Authentication Gate
4. Normal attacker position? PARTIAL -- requires key knowledge or leaked token
5. Vulnerable code ships to production? YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The missing exp enforcement creates a defense-in-depth gap for JWT auth deployments. While RFC 7519 makes exp OPTIONAL, the security impact of accepting permanent tokens is significant. The validation code at line 86-88 explicitly handles the "value == nil" case with continue but fails to handle the "key absent" case. The Advocate correctly notes JWT auth is opt-in and key possession is a prerequisite, but the second-order attack (leaked token without exp = permanent credential) is a legitimate concern. MEDIUM severity reflects the opt-in nature and key possession requirement.

**Finding draft written to**: security/findings-draft/p7-003-jwt-missing-exp-enforcement.md
**Registry updated**: AP-003 JWT Missing Expiry Enforcement

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-20T13:05:00Z

**Prosecution summary**: In anonymous-enabled deployments, the orgId query parameter at middleware.go:39 could allow cross-org access if the anonymous user's org context is switched.

**Defense summary**: The Advocate provides definitive code evidence disproving the hypothesis. At contexthandler.go:146, `reqContext.IsSignedIn = !reqContext.IsAnonymous`, so anonymous users have `IsSignedIn = false`. The RBAC middleware at middleware.go:44 checks `if !c.IsSignedIn && forceLogin` -- for anonymous users with orgId mismatch, this evaluates to `if true && true`, calling `unauthorized(c)` and returning 401. The hypothesis's precondition ("anonymous user treated as signed-in with IsSignedIn=true") is factually incorrect.

**Pre-FP Gate**: Failed on check-1: The attacker control path is blocked by the IsSignedIn=false check for anonymous users.

**Verdict: FALSE POSITIVE**
**Rationale**: The hypothesis is based on a factual error about anonymous user state. Anonymous users have IsSignedIn=false (contexthandler.go:146), and the RBAC middleware explicitly blocks org switching for non-signed-in users with forceLogin=true (middleware.go:44). The protection is confirmed by direct code read.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-03-20T13:06:00Z

**Prosecution summary**: Chain of SPEC-GAP-001 (expired OIDC token replay to obtain session) + SPEC-GAP-005 (WebSocket empty Origin bypass) for persistent live data exfiltration.

**Defense summary**: The chain depends on H-01 as its first step. The Advocate demonstrates that the OAuth2 authorization code flow prevents direct token injection (same defense as H-01). Without a session obtained via expired token replay, the attacker cannot reach the WebSocket endpoint. The WebSocket empty Origin issue was already dropped in Phase 5 (SPEC-GAP-005) due to high exploit prerequisites.

**Pre-FP Gate**: Failed on check-1: The chain depends on H-01, and while H-01 is VALID (defense-in-depth gap), it requires IdP compromise -- not a normal attacker position. The chain amplification does not change the fundamental prerequisite.

**Verdict: DROP**
**Rationale**: This hypothesis chains H-01 (IdP-level compromise required) with SPEC-GAP-005 (already dropped for high prerequisites). The chain does not lower the bar for either component -- it adds complexity without reducing prerequisites. If an attacker has IdP-level access, they can obtain a fresh session directly without needing expired token replay. The WebSocket empty Origin bypass adds negligible value when the attacker already has a valid session. Both components were independently evaluated.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Additional Verdict: SPEC-GAP-002 (OAuth Default-Off Signature Verification) -- 2026-03-20T13:07:00Z

This finding was in scope but not directly hypothesized as a standalone attack (it appeared in H-07's context). Evaluating independently:

**Prosecution summary**: In default configuration (validate_id_token=false), generic_oauth.go:447-453 calls retrieveRawJWTPayload() which base64-decodes the ID token payload without any signature verification. The returned unverified claims are used for authentication via parseUserInfoFromJSON(). This violates OIDC Core 1.0 Section 3.1.3.7 requirement 6. The same pattern exists in GitLab (gitlab_oauth.go:295), Okta (okta_oauth.go:135), and Google (google_oauth.go:265) OAuth connectors.

**Defense summary**: The token exchange is server-to-server HTTPS authenticated with client_secret (oauth.go:165). The ID token within the response is protected by transport-level integrity. The token exchange flow (authorization code -> token endpoint) provides strong protection against content modification. An attacker would need to compromise the HTTPS transport or the IdP itself.

**Pre-FP Gate**:
1. Attacker control verified? YES -- unverified payload is used for authentication
2. Framework protection searched? YES -- HTTPS transport, client_secret, authorization code
3. Trust boundary crossing confirmed? YES -- TB2, unverified identity claims accepted
4. Normal attacker position? NO -- requires MITM on HTTPS or IdP compromise
5. Vulnerable code ships to production? YES -- this is the DEFAULT code path

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: The default-off signature verification is a confirmed OIDC spec violation that inverts the security model. While the HTTPS transport provides meaningful protection (the token exchange is authenticated server-to-server), the missing verification fails defense-in-depth against: (1) token response logged by middleware or CDN; (2) IdP misconfiguration; (3) HTTP-only token_url misconfiguration. Severity is MEDIUM because the HTTPS transport provides strong (but imperfect) protection and exploitation requires network-level or IdP-level compromise. The key insight is that this is the DEFAULT code path for all generic OAuth deployments.

**Finding draft written to**: security/findings-draft/p7-004-oauth-default-no-signature-verification.md
**Registry updated**: AP-004 OAuth Default-Off ID Token Verification

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01: OIDC Missing exp/iss/aud Validation | VALID | MEDIUM | p7-001-oidc-missing-claim-validation.md |
| H-02: RBAC Scope Template Injection | FALSE POSITIVE | -- | -- |
| H-03: Permission Cache Poisoning | DROP | -- | -- |
| H-04: CSRF Custom Header Comparison Bypass | VALID | MEDIUM | p7-002-csrf-header-comparison-bypass.md |
| H-05: JWT Missing exp Enforcement | VALID | MEDIUM | p7-003-jwt-missing-exp-enforcement.md |
| H-06: Cross-Org via orgId (Anonymous) | FALSE POSITIVE | -- | -- |
| H-07: WebSocket + OIDC Chain | DROP | -- | -- |
| SPEC-GAP-002: OAuth Default-Off Sig Verification | VALID | MEDIUM | p7-004-oauth-default-no-signature-verification.md |

Findings written: 4
Patterns added to registry: 4
Variant candidates: 0

Chamber closed: 2026-03-20T13:10:00Z
