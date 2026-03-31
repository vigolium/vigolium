# Grafana Phase 6 Spec Gap Analysis Report

**Generated:** 2026-03-21
**Repository:** github.com/grafana/grafana (commit 40a9cd68ff8efc62da02d30bf4b3e8ae3a1017ab)
**Phase:** 6 — Spec/RFC Gap Analysis
**Audit ID:** 2026-03-21T00:00:00.000Z
**Specs Analyzed:** OpenID Connect Core 1.0, RFC 7519 (JWT), RFC 7230/9110 (HTTP Proxy), W3C CSP Level 3, RFC 6455 (WebSocket), RFC 6749 (OAuth 2.0), MySQL Reference 8.0 (SELECT INTO OUTFILE)
**Prior Phase Reference:** security/knowledge-base-report.md § Domain Attack Research, § Spec Gap Candidates

---

## Summary

| ID | Gap | RFC/Spec | Severity | Gap Type |
|----|-----|----------|----------|----------|
| SPEC-GAP-001 | Generic OAuth ID Token Claims Extracted Without Signature Validation (Default) | OIDC Core 1.0 §3.1.3.7 | HIGH | missing-check |
| SPEC-GAP-002 | OIDC ID Token Post-Signature Claims Not Validated (exp/iss/aud) | OIDC Core 1.0 §3.1.3.7 | HIGH | missing-check |
| SPEC-GAP-003 | JWT Auth Service Accepts Tokens Without `exp` Claim | RFC 7519 §4.1.4, §7.2 | MEDIUM | missing-check |
| SPEC-GAP-004 | HTTP Reverse Proxy Does Not Strip Hop-by-Hop Headers | RFC 7230 §6.1 / RFC 9110 §7.6.1 | MEDIUM | missing-check |
| SPEC-GAP-005 | SQL Expression Engine: `IsReadOnly` Does Not Prevent INTO OUTFILE | MySQL Reference 8.0 §SELECT INTO | HIGH | state-machine |
| SPEC-GAP-006 | WebSocket Origin Check Unconditionally Allows Empty Origin | RFC 6455 §4.1, §10.2 | MEDIUM | missing-check |
| SPEC-GAP-007 | Default CSP Template Contains `unsafe-eval` Alongside Nonce | W3C CSP Level 3 §4.2.5.2 | MEDIUM | normalization |

---

## Spec Gap Analysis

### Gap: Generic OAuth ID Token Claims Extracted Without Signature Validation (Default)

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.3.7, Requirement 6
- **Requirement**: "The Client MUST validate the signature of all other ID Tokens according to JWS using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer."
- **Code Path**: `pkg/login/social/connectors/generic_oauth.go:439-454` — the condition `if s.info.ValidateIDToken && s.info.JwkSetURL != ""` gates signature validation. When either condition is false (default: `validate_id_token = false`), the else branch calls `retrieveRawJWTPayload()` at `pkg/login/social/connectors/social_base.go:233-287` which base64-decodes the token payload without any signature verification. The same unenforced-by-default pattern appears in `gitlab_oauth.go:295`, `okta_oauth.go:135`, `google_oauth.go:265`.
- **Gap Type**: missing-check
- **Attack Vector**: In a network environment where the OAuth exchange can be intercepted (insecure OAuth provider HTTP endpoints, MITM capability, or a misconfigured provider), an attacker modifies the ID token payload to inject `"email": "admin@example.com"` or a target user's email. Since the signature is not verified, Grafana accepts the forged identity claims. The `email` field from the ID token is used for user lookup or new account creation.
- **Exploit Conditions**: (1) Generic OAuth connector is configured with an IdP that returns ID tokens. (2) `validate_id_token = false` (the default) OR `jwk_set_url` is not configured. (3) Attacker can modify the token — feasible via MITM, non-HTTPS OAuth endpoints, or a malicious/compromised OAuth provider. (4) Either `oauth_allow_insecure_email_lookup = true` or the IdP-side claims can be crafted to match a Grafana user's registered identity.
- **Impact**: Authentication bypass enabling impersonation of any Grafana user whose email is known. An attacker with control over the OAuth token response can forge any user's identity, gaining full access to that user's org roles, dashboards, and datasources.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // pkg/login/social/connectors/generic_oauth.go:439-454
  if s.info.ValidateIDToken && s.info.JwkSetURL != "" {
      rawJSON, err = s.validateIDTokenSignature(ctx, http.DefaultClient, idTokenString, s.info.JwkSetURL)
      // ...
  } else {
      // Default path: no signature verification
      rawJSON, err = s.retrieveRawJWTPayload(idTokenString)
      // ...
  }
  return s.parseUserInfoFromJSON(rawJSON, "id_token"), nil
  ```
  ```go
  // pkg/login/social/connectors/social_base.go:244-246
  rawJSON, err := base64.RawURLEncoding.DecodeString(matched[2])
  // ^ directly decodes payload without signature check
  ```
  OIDC Core 1.0 Section 3.1.3.7 Requirement 6: signature validation is MUST, not optional.

---

### Gap: OIDC ID Token Post-Signature Claims Not Validated (exp/iss/aud)

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.3.7
- **Requirement**: Requirement 2: "The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss Claim." Requirement 3: "The Client MUST validate that the aud (audience) Claim contains its client_id value." Requirement 9: "The current time MUST be before the time represented by the exp Claim."
- **Code Path**: `pkg/login/social/connectors/social_base.go:385-449` — `validateIDTokenSignatureWithURLs()` verifies the cryptographic signature via JWKS using `parsedToken.Claims(key, &claims)` at line 429, then at lines 438-442 marshals the raw claims map and returns them without validating `exp`, `iss`, or `aud` claims. The function name implies completeness but only performs the cryptographic step (Requirement 6), omitting Requirements 2, 3, and 9.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker replays a previously-issued, now-expired ID token obtained from browser history, network interception, or a prior session. Because `validateIDTokenSignature` only checks the cryptographic signature, an expired token with a valid signature is accepted. Additionally, a token issued by the same IdP for a different relying party (different `aud`) is accepted — cross-application token confusion enabling privilege escalation if a less-privileged application shares the same IdP.
- **Exploit Conditions**: (1) `validate_id_token = true` and `jwk_set_url` is configured (non-default; requires explicit operator configuration). (2) Attacker possesses a previously-valid ID token from a legitimate login session. (3) Token's signing key is still in the IdP's JWKS (not rotated since issuance). (4) No `iss`/`aud` checks are present — a token intended for a different audience is equally valid. Note: The AzureAD connector (`azuread_oauth.go:432-434`) performs audience validation independently, partially mitigating this for Azure deployments.
- **Impact**: Persistent authentication via replayed expired tokens. Users whose accounts are revoked at the IdP but whose old ID tokens remain cryptographically valid can re-authenticate. Cross-application token confusion allows tokens intended for other services to authenticate to Grafana, enabling impersonation.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // pkg/login/social/connectors/social_base.go:425-442
  var claims map[string]any
  if err := parsedToken.Claims(key, &claims); err == nil {
      // Cryptographic signature verified — but NO exp/iss/aud validation follows
      rawJSON, err := json.Marshal(claims)
      if err != nil {
          return nil, fmt.Errorf("failed to marshal verified claims: %w", err)
      }
      return rawJSON, nil  // Claims returned without exp/iss/aud enforcement
  }
  ```
  OIDC Core 1.0 Section 3.1.3.7 specifies 12 validation steps. Steps 2 (iss), 3 (aud), and 9 (exp) are absent after signature verification.

---

### Gap: JWT Auth Service Accepts Tokens Without `exp` Claim

- **RFC/Spec**: RFC 7519, Section 4.1.4; Section 7.2 Step 9
- **Requirement**: RFC 7519 Section 4.1.4: "The `exp` (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing." Section 7.2 Step 9: "If a `exp` claim is present, the current date/time MUST be before the expiration date/time listed in the `exp` claim." (The spec makes the claim itself optional but mandates enforcement when present; implementations SHOULD require it to prevent unbounded tokens.)
- **Code Path**: `pkg/services/auth/jwt/validation.go:55-136` — `validateClaims()` iterates the claims map and at lines 86-95 only sets `registeredClaims.Expiry` when the `"exp"` key exists. When `exp` is absent entirely, `registeredClaims.Expiry` remains `nil`. At line 121, `registeredClaims.Validate(expectRegistered)` is called but go-jose/v4's `Validate()` only enforces expiry when `Expiry != nil`, so tokens without `exp` pass validation unconditionally. The `ExpectClaims` configuration defaults to `{}` — no `exp` requirement is imposed.
- **Gap Type**: missing-check
- **Attack Vector**: An operator configures JWT auth (`[auth.jwt]`) with an HMAC or asymmetric key. Some IdPs issue service account tokens or internal tokens without `exp` fields — these become permanent Grafana credentials. Additionally, an attacker who obtains an HMAC key crafts a JWT omitting `exp` for indefinite validity.
- **Exploit Conditions**: (1) `auth.jwt.enabled = true`. (2) JWT is cryptographically valid (correctly signed). (3) JWT payload does not contain the `exp` key. (4) No `expect_claims` configuration forces `exp` to be present (it defaults to empty). This primarily affects deployments where IdPs or service integrations issue JWTs without expiry fields.
- **Impact**: JWT tokens without expiry become permanent authentication credentials. If such a token is leaked (log files, browser history, network capture), it grants indefinite access until the signing key is rotated. This defeats time-bounded access control and token revocation models.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // pkg/services/auth/jwt/validation.go:86-95
  case "exp":
      if value == nil {
          continue  // nil value skipped; absent key never reaches this case
      }
      if floatValue, ok := value.(float64); ok {
          out := jwt.NumericDate(floatValue)
          registeredClaims.Expiry = &out  // only set when "exp" key present
      }
  // ...
  // registeredClaims.Expiry is nil when "exp" is absent from the token
  if err := registeredClaims.Validate(expectRegistered); err != nil {
      return err  // passes when Expiry is nil — no expiry enforced
  }
  ```

---

### Gap: HTTP Reverse Proxy Does Not Strip Hop-by-Hop Headers From Inbound Requests

- **RFC/Spec**: RFC 7230, Section 6.1 (HTTP/1.1 Connection Header); RFC 9110, Section 7.6.1
- **Requirement**: RFC 7230 §6.1: "A proxy or gateway MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own connection options for the forwarded message)."
- **Code Path**: `pkg/util/proxyutil/proxyutil.go:26-48` — `PrepareProxyRequest()` strips a fixed set of headers (`X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto`, `Origin`, `Referer`) but does not parse or remove the `Connection` header or the headers it lists. This function is invoked via `wrapDirector` at `pkg/util/proxyutil/reverse_proxy.go:79-81` for all datasource proxy requests. By contrast, `pkg/plugins/manager/client/client.go:319-372` correctly implements `removeConnectionHeaders()` and `removeHopByHopHeaders()` for the plugin proxy path — the datasource proxy path lacks equivalent stripping.
- **Gap Type**: missing-check
- **Attack Vector**: An authenticated user (any role with `datasources:query` permission) sends a datasource proxy request with crafted headers:
  ```
  GET /api/datasources/proxy/uid/abc123/api/query HTTP/1.1
  Connection: X-Internal-Token, Authorization
  X-Internal-Token: superuser-secret
  ```
  The `Connection` header and `X-Internal-Token` are forwarded verbatim to the backend datasource. If the backend (InfluxDB, a custom API, Prometheus with internal auth) trusts `X-Internal-Token` for privilege elevation, the attacker gains elevated access within that backend system.
- **Exploit Conditions**: (1) Backend datasource trusts custom headers for internal privilege elevation or authentication. (2) Attacker has `datasources:query` RBAC permission (default for any role that can query datasources). (3) The specific header name to inject is known or guessable. Backend header injection is a common attack against internal services that assume inbound requests from a proxy have already been sanitized.
- **Impact**: Header injection into backend datasource requests enabling unauthorized privilege escalation within backend systems. Depending on backend behavior, this can enable admin access to InfluxDB, bypass authentication on internal APIs, or inject internal context headers that modify query behavior.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // pkg/util/proxyutil/proxyutil.go:26-48 - PrepareProxyRequest does NOT handle Connection header
  func PrepareProxyRequest(req *http.Request) {
      req.Header.Del("X-Forwarded-Host")
      req.Header.Del("X-Forwarded-Port")
      req.Header.Del("X-Forwarded-Proto")
      req.Header.Del("Origin")
      req.Header.Del("Referer")
      // Connection header and headers it lists are NOT stripped
  }
  ```
  ```go
  // pkg/util/proxyutil/reverse_proxy.go:70-82 - wrapDirector calls PrepareProxyRequest
  func wrapDirector(d func(*http.Request)) func(req *http.Request) {
      return func(req *http.Request) {
          // ...
          d(req)
          PrepareProxyRequest(req)  // No hop-by-hop stripping
      }
  }
  ```

---

### Gap: SQL Expression Engine — `IsReadOnly` Config Does Not Prevent INTO OUTFILE File Write

- **RFC/Spec**: MySQL Reference Manual 8.0, "SELECT ... INTO Syntax"; go-mysql-server `IsReadOnly` configuration semantics
- **Requirement**: The go-mysql-server library's `IsReadOnly: true` engine configuration is documented as: "IsReadOnly sets the engine to disallow modification queries." The expected behavior (matching MySQL's read-only mode) is that file-writing operations like `SELECT ... INTO OUTFILE` and `SELECT ... INTO DUMPFILE` are blocked. The library provides `sql.WithDisableFileWrites(true)` context option to explicitly disable file writes, and `secure_file_priv` to restrict write paths.
- **Code Path**: `pkg/expr/sql/db.go:82-84` — the engine is created with `IsReadOnly: true` but without `WithDisableFileWrites(true)`. The context is created at line 71: `mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))` without `mysql.WithDisableFileWrites(true)`. The parser allowlist at `pkg/expr/sql/parser_allow.go:113-114` explicitly includes `*sqlparser.Into` as an allowed node. The enforcement path in the library (`go-mysql-server@v0.20.2-grafana/sql/rowexec/rel.go:599-608`) checks `ctx.DisableFileWrites()` (returns `false`) and `secure_file_priv` system variable (defaults to `""` = unrestricted path). The `IsReadOnly` engine check at `engine.go:787` calls `plan.IsReadOnly(node)` which for the `*Into` node delegates to `i.Child.IsReadOnly()` (the child SELECT), which returns `true` — making the engine's read-only check a no-op for INTO OUTFILE.
- **Gap Type**: state-machine
- **Attack Vector**: An authenticated user with access to the SQL Expressions feature (`sqlExpressions` feature flag must be enabled) submits a SQL expression query:
  ```sql
  SELECT 'evil content' INTO OUTFILE '/etc/cron.d/grafana-backdoor'
  ```
  or
  ```sql
  SELECT sensitive_column FROM A INTO OUTFILE '/tmp/exfiltrated.csv'
  ```
  The query passes the `AllowQuery` parser check (since `*sqlparser.Into` is allowed), bypasses the engine `IsReadOnly` check (since Into delegates IsReadOnly to the child SELECT), passes the `DisableFileWrites` check (false by default), and succeeds because `secure_file_priv` defaults to `""` (no path restriction). Files are written at the path specified by the attacker, running as the Grafana process user.
- **Exploit Conditions**: (1) Feature flag `sqlExpressions` is enabled (non-default; requires explicit operator configuration or admin API call). (2) Attacker has Editor or Admin role (minimum required to create/run SQL Expressions). (3) Grafana process has filesystem write permissions at the target path (likely for paths under the Grafana working directory, cron directories, or plugin directories if running as root/with elevated permissions). (4) The database tables referenced (frame refIDs) can be any values — the INTO OUTFILE clause does not require a table to exist for the write to proceed.
- **Impact**: Arbitrary file write as the Grafana process user. Depending on the process's permissions and the target path, this enables: (a) writing backdoor scripts to cron directories enabling RCE, (b) overwriting Grafana configuration files (`grafana.ini`) to disable authentication, (c) writing to plugin directories to inject malicious plugin code, (d) exfiltrating query results (datasource data) to accessible file paths. This is a HIGH severity gap because when `sqlExpressions` is enabled, any Editor can achieve arbitrary file write, which is typically a path to full system compromise.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // pkg/expr/sql/db.go:68-84 — context and engine creation WITHOUT DisableFileWrites
  session := mysql.NewBaseSession()
  mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))
  // ^ WithDisableFileWrites(true) is ABSENT
  // ctx.SetSessionVariable(ctx, "secure_file_priv", "")  // COMMENTED OUT
  a := analyzer.NewDefault(pro)
  engine := sqle.New(a, &sqle.Config{
      IsReadOnly: true,  // Does NOT block INTO OUTFILE — Into.IsReadOnly() delegates to child SELECT
  })
  ```
  ```go
  // go-mysql-server@v0.20.2-grafana/sql/plan/into.go:82-84
  func (i *Into) IsReadOnly() bool {
      return i.Child.IsReadOnly()  // Delegates to SELECT — returns true, bypassing read-only check
  }
  ```
  ```go
  // go-mysql-server@v0.20.2-grafana/sql/rowexec/rel.go:599-613
  if n.Outfile != "" || n.Dumpfile != "" {
      if ctx.DisableFileWrites() {  // Returns false — not set by Grafana
          return nil, sql.ErrFileWritesDisabled.New()
      }
      _, secureFileDir, ok = sql.SystemVariables.GetGlobal("secure_file_priv")
      // secureFileDir == "" (default) — no path restriction
  }
  // isUnderSecureFileDir("", path) returns nil immediately — all paths allowed
  ```
  ```go
  // go-mysql-server@v0.20.2-grafana/sql/rowexec/rel.go:547-549
  func isUnderSecureFileDir(secureFileDir interface{}, fileStr string) error {
      if secureFileDir == nil || secureFileDir == "" {
          return nil  // Empty secureFileDir = no restriction
      }
  ```
  ```go
  // pkg/expr/sql/parser_allow.go:113-114 — Into is on the allowlist
  case *sqlparser.Into:
      return  // Allowed — AllowQuery returns true for INTO OUTFILE
  ```

---

### Gap: WebSocket Origin Check Unconditionally Allows Empty Origin Header

- **RFC/Spec**: RFC 6455, Section 10.2 ("Origin Considerations"); RFC 6455, Section 4.1 (Client Requirements)
- **Requirement**: RFC 6455 §10.2: "The server is informed of the script origin generating the WebSocket connection request through the |Origin| header field. If the server does not validate the origin, it will accept connections from anywhere... The server SHOULD validate the |Origin| field." RFC 6455 §4.1: The `Origin` header is REQUIRED for browser-generated WebSocket upgrade requests. An empty Origin from a browser indicates a spoofed or proxied request.
- **Code Path**: `pkg/services/live/live.go:535-563` — `getCheckOriginFunc()` at lines 538-539 explicitly returns `true` for absent Origin: `if origin == "" { return true }`. This function is used as the `CheckOrigin` handler for all three WebSocket upgrader configurations at lines 340, 349, 355. The push pipeline WebSocket at `pkg/services/live/pushws/ws.go:56-58` has the same pattern: `if origin == "" { return nil }` (treated as allowed).
- **Gap Type**: missing-check
- **Attack Vector**: Cross-site WebSocket hijacking (CSWSH): an attacker-controlled page causes a victim's authenticated browser to make a cross-origin WebSocket connection to `/api/live/ws`. In some configurations (WebSocket libraries, reverse proxies like nginx, or SSE-to-WS bridging) the Origin header may be absent or stripped. With an empty Origin, the check returns `true` unconditionally, regardless of configured `allowed_origins`. The attacker's script receives real-time data pushed over the victim's Live WebSocket channel.
- **Exploit Conditions**: (1) Grafana Live is active (default when Live feature is enabled). (2) Authentication is by session cookie (the WebSocket upgrade includes cookies via `withCredentials`). (3) Either: (a) a reverse proxy or WebSocket library strips the Origin header before forwarding, (b) non-browser integrations using Grafana Live API with stolen session cookies, or (c) WebSocket connections from server-side clients that omit Origin. The `reqSignedIn` requirement prevents fully unauthenticated exploitation.
- **Impact**: Unauthorized subscription to real-time Grafana Live channels. An attacker can receive live metric streams, alert state updates, and dashboard refresh events from channels the victim user is subscribed to. The data exposure depends on which Live channels the victim has access to.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // pkg/services/live/live.go:535-563
  func getCheckOriginFunc(appURL *url.URL, originPatterns []string, originGlobs []glob.Glob) func(r *http.Request) bool {
      return func(r *http.Request) bool {
          origin := r.Header.Get("Origin")
          if origin == "" {
              return true  // Empty Origin unconditionally allowed
          }
          // ... validation only runs when Origin is non-empty
      }
  }
  ```
  ```go
  // pkg/services/live/pushws/ws.go:54-58
  func checkSameHost(r *http.Request) error {
      origin := r.Header.Get("Origin")
      if origin == "" {
          return nil  // Empty Origin allowed
      }
  ```

---

### Gap: Default CSP Template Contains `unsafe-eval` Alongside Nonce

- **RFC/Spec**: W3C Content Security Policy Level 3, Section 4.2.5.2 (`unsafe-eval` keyword); CSP Level 3 §8.2 (nonce-based policy intent)
- **Requirement**: W3C CSP Level 3 §4.2.5.2 defines `unsafe-eval` as allowing execution of strings as code via `eval()`, `setTimeout(string)`, `new Function(string)`. The spec design intent of nonce-based CSP (`'strict-dynamic'` + `'nonce-<random>'`) is to restrict script execution to only explicitly trusted scripts. The `unsafe-eval` directive creates an uncontrolled code execution channel that nonces cannot restrict. Strict CSP guidelines (also codified in the spec's §8.2 recommendations) require `unsafe-eval` NOT be present.
- **Code Path**: `conf/defaults.ini:451` — the `content_security_policy_template` includes `'unsafe-eval'` and `'unsafe-inline'` in `script-src`. Applied by `pkg/middleware/csp.go` which performs only `$NONCE` and `$ROOT_PATH` substitution without removing insecure keywords. Both `content_security_policy_template` (line 451) and `content_security_policy_report_only_template` (line 460) contain `'unsafe-eval'`.
- **Gap Type**: normalization
- **Attack Vector**: An operator enables CSP (`content_security_policy = true`) believing nonce-based policy provides XSS protection. The active policy includes `'unsafe-eval'`, meaning any DOM XSS sink that passes attacker-controlled strings to `eval()`, `new Function()`, `setTimeout(string)`, or `setInterval(string)` executes arbitrary JavaScript, bypassing the nonce entirely. This is particularly relevant given Grafana's plugin ecosystem and Vega visualization support which may involve eval-like constructs.
- **Exploit Conditions**: (1) `content_security_policy = true` (non-default; must be explicitly enabled by operator). (2) A DOM XSS injection point exists (e.g., panel title rendering, annotation HTML, plugin-rendered content). (3) The injection reaches an eval-like sink. CSP is disabled by default, so this gap only affects deployments that have explicitly enabled CSP believing it provides XSS protection.
- **Impact**: The `unsafe-eval` directive nullifies a significant portion of nonce-based XSS protection. Operators who enable CSP to harden their Grafana instance receive materially weaker protection than expected. Any stored or reflected XSS via an eval sink executes arbitrary JavaScript, enabling session hijacking and account takeover.
- **Severity**: MEDIUM
- **Evidence**:
  ```ini
  # conf/defaults.ini:451
  content_security_policy_template = """script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE;object-src 'none';font-src 'self';style-src 'self' 'unsafe-inline' blob:;img-src * data:;base-uri 'self';connect-src 'self' grafana.com ws://$ROOT_PATH wss://$ROOT_PATH;manifest-src 'self';media-src 'none';form-action 'self';"""
  ```
  `'unsafe-eval'` and `'unsafe-inline'` present alongside `'strict-dynamic'`. `'strict-dynamic'` overrides `'unsafe-inline'` in CSP3-supporting browsers but cannot override `'unsafe-eval'`.

---

## Methodology Notes

### Specs Not Producing High/Medium Findings

**SCIM 2.0 (RFC 7643/7644):** CVE-2025-41115 (numeric externalId privilege escalation) is patched in Enterprise versions and confirmed in CHANGELOG.md. The SCIM implementation is Enterprise-only — `pkg/services/scimutil/` in OSS only contains dynamic configuration utilities, not the SCIM provisioning protocol itself. No additional OSS-accessible spec gaps beyond CVE-2025-41115.

**OAuth 2.0 State Parameter (RFC 6749 §10.12):** The state parameter is correctly implemented. `oauth.go` validates the state cookie against an HMAC-SHA256 hash using `ClientSecret` as the signing key. No spec gap.

**OAuth 2.0 Redirect URI (RFC 6749 §10.6):** Redirect URI validation is delegated to the `golang.org/x/oauth2` library and the IdP's registered redirect URI enforcement. No Grafana-side bypass identified.

**SAML 2.0:** Enterprise-only, not present in the OSS codebase. The Enterprise implementation uses `crewjam/saml` library which handles XML signature verification per spec.

**WebSocket RFC 6455 Protocol Negotiation:** Centrifuge library handles WebSocket protocol negotiation. The gap documented (empty Origin) is at the application security layer. Subprotocol negotiation follows RFC 6455 correctly.

**HTTP/1.1 Response Splitting (RFC 7230):** Go's `net/http` library normalizes response headers, preventing HTTP response splitting.
