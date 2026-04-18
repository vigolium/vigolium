# Spec Gap Analysis Report
**Repository**: grafana/grafana  
**Commit**: bb41ac0c85d854e32cb19874fb4b3f17163179a8  
**Report Date**: 2026-04-11  
**Phase**: 6 — Spec Gap Analyst  
**Analyst**: Spec Gap Agent (claude-sonnet-4-6)

---

## Spec Gap Analysis

The following gaps were identified between RFC/spec requirements and Grafana's implementation. Findings are ordered by severity. All gaps are Medium or higher with credible exploit paths. Gaps already fully covered by Phase 3 Domain Attack Research are excluded.

---

### Gap 1: OpenID Connect ID Token Missing Mandatory Claim Validation

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.3.7 — "ID Token Validation"
- **Requirement**: The spec mandates that after signature verification, the RP (Relying Party) MUST validate the following claims: (1) `iss` — issuer MUST match the provider's issuer; (2) `aud` — audience MUST contain the client_id; (3) `exp` — token MUST NOT be expired; (4) `iat` — issued-at MAY be validated; (5) `nonce` — MUST be validated if sent in the authentication request. The spec states: "The ID Token MUST be rejected if any of these validations fail."
- **Code Path**: `pkg/login/social/connectors/social_base.go:385-454` — `validateIDTokenSignatureWithURLs()` verifies the JWT signature via JWKS lookup but immediately marshals and returns raw claims (`json.Marshal(claims)`) without calling any claim validation function. The caller `extractFromToken()` in `pkg/login/social/connectors/gitlab_oauth.go:295-308` receives these claims and only checks `email_verified`.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker who controls or has stolen a valid but expired ID token from a GitLab OAuth provider (e.g., via browser history, logs, or proxy interception) can replay it against Grafana. Because `validateIDTokenSignature` only checks the cryptographic signature and not `exp`, the expired token will be accepted. Additionally, if an attacker can obtain a legitimately signed ID token from a different relying party sharing the same IdP (but with a different `aud`), they can use it to authenticate to Grafana because `aud` is not validated. The same logic applies to any provider using `validateIDToken`/`validate_id_token = true` with a JWK URL.
- **Exploit Conditions**: (1) GitLab OAuth connector with `validate_id_token = true` and `jwk_set_url` configured. (2) Attacker possesses a validly signed ID token (expired, or issued for a different `aud`) from the same IdP. (3) Default configuration (without `validate_id_token`) skips all validation entirely via `retrieveRawJWTPayload` — no signature check at all.
- **Impact**: Authentication bypass — an attacker with a stolen/expired/mis-scoped but cryptographically valid ID token can log in as the token subject. In the default `validate_id_token = false` case (the common path), the ID token payload is accepted without any signature or claim verification, allowing an attacker to forge identity by crafting a JWT with a valid-looking format and forged claims.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // social_base.go:428-442
  var claims map[string]any
  if err := parsedToken.Claims(key, &claims); err == nil {
      // Successfully verified, cache the keyset...
      rawJSON, err := json.Marshal(claims)
      if err != nil {
          return nil, fmt.Errorf("failed to marshal verified claims: %w", err)
      }
      return rawJSON, nil  // ← returns without exp/aud/iss/nonce validation
  }
  
  // gitlab_oauth.go:301-307 (default path — no signature check at all)
  } else {
      // Otherwise, just extract the payload without signature validation
      rawJSON, err = s.retrieveRawJWTPayload(idTokenString)
  }
  ```

---

### Gap 2: OpenID Connect — Nonce Parameter Not Generated or Validated

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.2.1 (Authentication Request) and Section 3.1.3.7 step 11: "If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request."
- **Requirement**: The RP MUST include a cryptographically random `nonce` in the authentication request and MUST verify that the returned ID token contains a matching `nonce` claim.
- **Code Path**: `pkg/services/authn/clients/oauth.go:253-296` — `RedirectURL()` constructs the authorization URL via `connector.AuthCodeURL(state, opts...)`. No `nonce` parameter is generated or added to `opts`. `pkg/login/social/connectors/social_base.go` — no nonce validation exists in any ID token extraction path.
- **Gap Type**: missing-check
- **Attack Vector**: A replay attack against ID token injection. If an attacker can intercept a valid OIDC authentication response (e.g., via a network proxy, log injection, or browser extension), they can replay the `id_token` from a previous legitimate authentication session without detection. Without nonce binding, the ID token can be reused across multiple authentication attempts, and token substitution attacks (where a token issued for one session is injected into another) cannot be detected.
- **Exploit Conditions**: (1) Any OAuth connector using OIDC-compatible ID tokens (GitLab, generic_oauth, Okta, etc.) with `validate_id_token = true`. (2) Attacker can intercept or obtain a previously issued ID token (e.g., from logs, MITM, or compromised IdP session). (3) Token replay must occur within the ID token's `exp` window (or `exp` is not validated — see Gap 1, making this unrestricted).
- **Impact**: Authentication bypass via ID token replay or injection. Combined with Gap 1 (no expiry check), an attacker can reuse any captured ID token indefinitely. This is a standard implementation weakness covered by OIDC spec Section 3.1.3.7 as a mandatory control.
- **Severity**: HIGH
- **Evidence**: Search for `nonce` in `pkg/login/social/connectors/` returns zero matches. The `RedirectURL()` function adds `oauth2.S256ChallengeOption` for PKCE but no nonce parameter. OIDC spec explicitly states nonces are a mandatory anti-replay mechanism for ID tokens.

---

### Gap 3: JWT Authentication — TLS Certificate Validation Disabled by Configuration Without Warning

- **RFC/Spec**: RFC 7519 (JWT), Section 10.1 ("Trust Decisions"); RFC 7517 (JWK), Section 5 ("SHOULD" protect key material); NIST SP 800-52 Rev 2 (TLS) — MUST NOT disable certificate validation in production
- **Requirement**: RFC 7519 Section 10.1: "A JWT is only as trustworthy as the transport-level security used to deliver it. Therefore, JWT implementations SHOULD use TLS when delivering JWTs." IETF BCP 195 (RFC 7525) explicitly states TLS MUST verify the server's certificate in security-critical applications.
- **Code Path**: `pkg/services/auth/jwt/key_sets.go:187-213` — The `keySetHTTP` transport is configured with `InsecureSkipVerify: s.Cfg.JWTAuth.TlsSkipVerify`. `pkg/setting/setting_jwt.go:83` — `TlsSkipVerify = authJWT.Key("tls_skip_verify_insecure").MustBool(false)`. This feature was added via commit `561156c4da9` (identified in Phase 3 as "Dangerous Pattern").
- **Gap Type**: missing-check
- **Attack Vector**: When `tls_skip_verify_insecure = true` is set, an on-path attacker (or operator with network access) can intercept the JWK Set fetch over HTTPS and return attacker-controlled public keys. Grafana will use these attacker-controlled keys to validate JWT tokens, enabling the attacker to sign arbitrary JWTs that Grafana will accept as valid authentication tokens.
- **Exploit Conditions**: (1) Grafana configured with `[auth.jwt] jwk_set_url` and `tls_skip_verify_insecure = true`. (2) Attacker has network-layer access between Grafana and the JWK endpoint (e.g., via ARP spoofing, DNS poisoning, or compromised network infrastructure). (3) Feature is opt-in but has no runtime warning or alert.
- **Impact**: Complete JWT authentication bypass — attacker can impersonate any user by signing JWTs with attacker-controlled keys that Grafana fetches and trusts. This is a key confusion attack at the JWKS fetch layer rather than the token parsing layer.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // key_sets.go:192-196
  TLSClientConfig: &tls.Config{
      Renegotiation:      tls.RenegotiateFreelyAsClient,
      InsecureSkipVerify: s.Cfg.JWTAuth.TlsSkipVerify,  // ← disables cert verification
      RootCAs:            caCertPool,
  },
  ```

---

### Gap 4: OAuth 2.0 State Parameter — HMAC Construction Uses String Concatenation (Canonicalization Gap)

- **RFC/Spec**: RFC 6749, Section 10.12: "The binding value used for CSRF protection MUST contain a non-guessable value... and MUST be validated." RFC 9700 (OAuth 2.0 Security BCP), Section 4.7.
- **Requirement**: The state parameter binding must be cryptographically sound. Key derivation using concatenation of variable-length inputs (state + secret + seed) without a separator or fixed-length encoding creates a canonicalization vulnerability: two distinct inputs can produce the same concatenated string.
- **Code Path**: `pkg/services/authn/clients/oauth.go:372-375` — `hashOAuthState(state, secret, seed string)` computes `sha256(state + secret + seed)`. The inputs are concatenated as raw strings without length prefixing or delimiters. The state is 44 base64url characters (32 random bytes), and both `secret` and `seed` are variable-length operator-configured strings.
- **Gap Type**: canonicalization
- **Attack Vector**: If an attacker can influence the `ClientSecret` (e.g., via SSO settings API with admin access) or if the `SecretKey` contains characters that overlap with the state alphabet, prefix/suffix manipulation can potentially produce the same HMAC for a different state value. More concretely: if `state1 = "A"`, `secret1 = "B"`, `seed1 = "C"`, then `hash("ABC")` equals `hash("A" + "BC" + "")` — meaning an empty `seed` with state `"ABC"` produces the same hash as state `"A"` with seed `"BC"`. While the state is random, this means the security of state validation depends on the secrecy AND non-manipulability of both `SecretKey` and `ClientSecret`.
- **Exploit Conditions**: (1) Attacker has write access to SSO settings (which requires `settings:write` permission, typically Admin level). (2) Attacker wants to mount a CSRF attack and manipulate the state validation. The more immediate concern is that the construction does not follow HMAC key-separation best practices, which could be exploited if `SecretKey` is weak or if there is a length-extension concern.
- **Impact**: Potential CSRF token bypass if state values can be forged through the concatenation ambiguity. The practical exploitability is low without Admin-level access, but the construction violates RFC 9700's requirement for cryptographically sound state binding.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // oauth.go:372-375
  func hashOAuthState(state, secret, seed string) string {
      hashBytes := sha256.Sum256([]byte(state + secret + seed))
      return hex.EncodeToString(hashBytes[:])
  }
  ```

---

### Gap 5: CSRF Protection Bypassed for Requests Without Login Cookie (OWASP CSRF Standard)

- **RFC/Spec**: OWASP CSRF Prevention Cheat Sheet v2; W3C Fetch specification, Section 3.1 (CORS-safelisted methods). The relevant standard is that CSRF protection MUST apply to all state-changing operations regardless of authentication method.
- **Requirement**: CSRF protection should apply to all state-changing requests that can be made cross-origin, including those authenticated via API keys, Basic auth, or other non-cookie mechanisms. OWASP CSRF guidance states: "If an application uses both cookie-based and non-cookie-based authentication, both MUST be protected."
- **Code Path**: `pkg/middleware/csrf/csrf.go:77-80` — The CSRF check is skipped when `c.alwaysCheck == false` (the default, `csrf_always_check = false` in `conf/defaults.ini`) AND the request has no login cookie. This allows requests authenticated via `Authorization: Bearer <api_key>` or `X-Api-Key` headers to bypass CSRF checks entirely.
- **Gap Type**: missing-check
- **Attack Vector**: A cross-origin form or XHR request targeting a Grafana API endpoint, authenticated via an API key that is embedded in a web page or accessible via another vulnerability, bypasses CSRF validation. The attacker crafts a cross-origin request that includes the API key in a custom header or query parameter (if `url_login = true` in JWT config), and since there is no login cookie, CSRF is not checked. This could be combined with XSS on a different site to trigger state-changing operations.
- **Exploit Conditions**: (1) Grafana instance with API key authentication enabled (default). (2) `csrf_always_check = false` (default). (3) An XSS or social engineering vector that can send cross-origin requests with an API key. Note: custom headers (`X-Api-Key`) are preflighted by browsers and blocked by CORS unless `Access-Control-Allow-Origin` is misconfigured — however, `url_login` mode (query parameter JWT token) is not preflighted.
- **Impact**: If an attacker can use JWT-in-URL mode (`url_login = true`) or finds a way to embed an API key in a cross-origin form submission, they can perform CSRF attacks on state-changing Grafana API endpoints without CSRF token validation.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // csrf.go:77-80
  if !c.alwaysCheck {
      // If request has no login cookie - skip CSRF checks
      if _, err := r.Cookie(c.cfg.LoginCookieName); errors.Is(err, http.ErrNoCookie) {
          return nil  // ← CSRF check bypassed for all non-cookie-auth requests
      }
  }
  ```
  ```ini
  # conf/defaults.ini:40
  csrf_always_check = false  # default, per configuration
  ```

---

### Gap 6: Content Security Policy Default Template Contains `unsafe-eval` and `unsafe-inline`

- **RFC/Spec**: W3C Content Security Policy Level 3, Section 8.2 ("strict-dynamic") and Section 6.1.1 ("script-src"); OWASP CSP guidance
- **Requirement**: CSP Level 3 specifies that `strict-dynamic` makes `'self'`, `'unsafe-inline'`, and host allowlists ignored in supporting browsers (Chrome, Firefox, Safari) when a valid nonce or hash is present. However, `'unsafe-eval'` is NOT superseded by `strict-dynamic` and remains active even in strict-dynamic mode. W3C CSP Level 3 Section 4.2.2 explicitly states: "Authors MUST NOT use `unsafe-eval` in a policy intended to reduce the risk of XSS."
- **Code Path**: `conf/defaults.ini:461` — The CSP template is `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE`. The template includes both `strict-dynamic` (which is good) AND `unsafe-eval` (which is explicitly prohibited by the spec for XSS prevention). `pkg/middleware/csp.go:45-52` — The template is used as-is.
- **Gap Type**: missing-check
- **Attack Vector**: An XSS payload using `eval()`, `new Function()`, `setTimeout(string)`, or `setInterval(string)` will execute in browsers that receive the CSP header, because `unsafe-eval` whitelists all of these execution patterns. Since `content_security_policy = false` by default (line 456), this only affects instances that have explicitly enabled CSP — but these are precisely the instances relying on CSP as a security control.
- **Exploit Conditions**: (1) Grafana instance with `content_security_policy = true` configured. (2) An existing XSS vulnerability (of which 8 are confirmed in 2022–2026) that uses `eval()`-based execution. When CSP is enabled, operators expect it to block XSS — but the `unsafe-eval` keyword defeats that expectation.
- **Impact**: CSP provides no protection against `eval()`-based XSS. Any XSS vulnerability exploitable via `eval()` or `Function()` constructor bypasses the CSP even when it is explicitly enabled. This violates the CSP spec's stated purpose for operators who have enabled CSP for XSS mitigation.
- **Severity**: MEDIUM
- **Evidence**:
  ```ini
  # conf/defaults.ini:461
  content_security_policy_template = """script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE;..."""
  #                                                   ^^^^^^^^^^^^ prohibited by W3C CSP Level 3 for XSS prevention
  ```

---

### Gap 7: WebSocket RFC 6455 — Origin Bypass via Empty Origin Header (Unchecked Accept)

- **RFC/Spec**: RFC 6455 (WebSocket Protocol), Section 10.2: "The WebSocket Protocol, by itself, does not place any special significance on the value of the Origin header. This header is sent by browser clients; for non-browser clients, this header may be sent or omitted. The server may include additional logic to validate the Origin... The server SHOULD reject WebSocket connections from unexpected origins."
- **Requirement**: RFC 6455 Section 10.2 and the centrifuge library's security documentation state that the server SHOULD reject connections from unexpected origins. The Grafana implementation accepts connections with an empty `Origin` header without restriction.
- **Code Path**: `pkg/services/live/live.go:537-540` — `getCheckOriginFunc()` returns `true` immediately when `origin == ""`. `pkg/services/live/pushws/ws.go:55-57` — `checkSameHost()` also returns `nil` (allow) when `origin == ""`. This means any WebSocket connection without an Origin header is accepted regardless of configured origin restrictions.
- **Gap Type**: missing-check
- **Attack Vector**: A non-browser WebSocket client (e.g., a server-side script, a native app, or a browser extension that can suppress headers) can connect to Grafana's Live WebSocket endpoint (`/api/live/ws`) without sending an `Origin` header. This bypasses all configured origin restrictions, including `[live] allowed_origins` patterns. While cross-origin browser attacks are the primary threat model for origin validation, server-to-server pivoting scenarios (e.g., from a compromised internal service or via SSRF chain) could leverage this gap.
- **Exploit Conditions**: (1) Grafana Live is enabled (default in most deployments). (2) Attacker has a non-browser WebSocket client (or is operating server-side). (3) Standard authentication still applies — the WebSocket must have valid session credentials. The gap is that origin restriction provides no additional defense for non-browser clients.
- **Impact**: The origin-based WebSocket restriction is defeated for any non-browser client. While Grafana's authentication middleware still protects the endpoint, the defense-in-depth control mandated by RFC 6455 Section 10.2 is ineffective for server-side attackers. In a compromised internal network, this allows WebSocket connections from unexpected origins to receive real-time dashboard updates, channel data, and live query results.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // live.go:537-540
  func getCheckOriginFunc(...) func(r *http.Request) bool {
      return func(r *http.Request) bool {
          origin := r.Header.Get("Origin")
          if origin == "" {
              return true  // ← accepts all connections without Origin header
          }
  ```

---

### Gap 8: HTTP/1.1 Proxy — `Connection` Header Not Stripped Before Forwarding (RFC 7230 Hop-By-Hop)

- **RFC/Spec**: RFC 7230, Section 6.1: "A proxy or gateway MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header field(s) from the message with the same field-name as the connection-option, and then remove the Connection header field itself."
- **Requirement**: The proxy MUST remove `Connection` and all headers listed in `Connection` from the forwarded request. Failure to do so is a request smuggling and header injection vector.
- **Code Path**: `pkg/util/proxyutil/proxyutil.go:26-48` — `PrepareProxyRequest()` removes `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto`, `Origin`, and `Referer`, but does NOT remove `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, or `Upgrade` headers that RFC 7230 §6.1 mandates be stripped. The `httputil.ReverseProxy` (used in `pkg/util/proxyutil/reverse_proxy.go`) does strip hop-by-hop headers at the Go standard library level — but the `ds_proxy.go` director function in `pkg/api/pluginproxy/ds_proxy.go` modifies request headers after `httputil.ReverseProxy` processing, potentially re-introducing headers. Additionally, the plugin proxy routes use a custom transport that may not apply the same stripping.
- **Gap Type**: normalization
- **Attack Vector**: An authenticated Grafana user sends a request to the datasource proxy with a crafted `Connection: X-Custom-Header` and `X-Custom-Header: malicious-value` pair. If Grafana forwards the `Connection` header and the listed custom header, the backend datasource receives the custom header, potentially overriding authentication headers, security controls, or triggering backend-specific behaviors. In a request smuggling scenario where the backend uses HTTP/1.1 keep-alive, forwarding `Transfer-Encoding` or `Content-Length` discrepancies can desync the connection.
- **Exploit Conditions**: (1) Grafana datasource proxy in use (default for any datasource). (2) Authenticated user (any role with datasource access). (3) Backend datasource server is vulnerable to specific header injection. Note: Go's `httputil.ReverseProxy` does strip hop-by-hop headers in the standard path — the residual risk is in custom director code paths and edge cases where headers are re-added after proxy processing.
- **Impact**: Header injection into upstream datasource servers; potential request smuggling if the backend is a vulnerable HTTP/1.1 server. The impact depends heavily on the specific backend behavior.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // proxyutil.go:26-48 — PrepareProxyRequest strips X-Forwarded-* but NOT Connection or hop-by-hop headers
  func PrepareProxyRequest(req *http.Request) {
      req.Header.Del("Origin")
      req.Header.Del("Referer")
      req.Header.Del("X-Forwarded-Host")
      req.Header.Del("X-Forwarded-Port")
      req.Header.Del("X-Forwarded-Proto")
      // ← Connection, Keep-Alive, Transfer-Encoding, TE, Upgrade NOT removed
  }
  ```

---

### Gap 9: Render Key — `gob` Deserialization from Remote Cache Without Type Safety (Deserialization from Untrusted Source)

- **RFC/Spec**: Go `encoding/gob` documentation: "Gob is not safe for use with untrusted data. If you need to encode/decode untrusted data, consider using encoding/json." OWASP Deserialization Cheat Sheet.
- **Requirement**: Deserialization of data from a shared cache MUST be treated as untrusted input if the cache can be written by parties other than the application itself.
- **Code Path**: `pkg/services/rendering/auth.go:98-113` — `perRequestRenderKeyProvider.validate()` fetches a value from `remotecache` using `cache.Get()` and then calls `gob.NewDecoder(buf).Decode(&ru)` where `ru` is `*RenderUser`. The `RenderUser` struct contains `OrgID int64`, `UserID int64`, and `OrgRole string`.
- **Gap Type**: parsing
- **Attack Vector**: If the remote cache (Redis) is shared with other services or is accessible to an attacker (via network exposure, credentials leakage, or SSRF to the Redis port), the attacker can write a crafted gob-encoded payload to the render key cache namespace (`render-<key>`) with arbitrary `OrgID`, `UserID`, and `OrgRole` values. When Grafana's renderer authenticates with this key, it will receive the injected identity — including `OrgRole = "Admin"`. The key prefix `render-<random32>` provides guessing resistance but Redis commands like `SCAN` with pattern matching would allow enumeration.
- **Exploit Conditions**: (1) Grafana configured with a shared Redis remote cache (`[remote_cache] type = redis`). (2) Attacker has write access to the Redis instance (via exposed port, credential leakage, SSRF chain). (3) Image rendering is configured (`renderer_server_url` is set). (4) The gob type system does not validate field ranges, so an `OrgRole` value of `"Admin"` in the cache entry would be accepted without additional validation.
- **Impact**: Authentication bypass — attacker injects a render key with arbitrary org/user/role, causing the renderer to execute authenticated requests as any user or admin.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // rendering/auth.go:98-113
  func (r *perRequestRenderKeyProvider) validate(ctx context.Context, key string) (*RenderUser, bool) {
      val, err := r.cache.Get(ctx, fmt.Sprintf(renderKeyPrefix, key))  // ← reads from remote cache
      // ...
      err = gob.NewDecoder(buf).Decode(&ru)  // ← gob decode of potentially attacker-controlled data
      // ...
      return ru, ru != nil  // ← no additional validation of OrgRole/OrgID values
  }
  ```

---

### Gap 10: OpenFGA/Zanzana Authorization — Rollout Routing by First Batch Item Allows Mixed-Resource Bypass

- **RFC/Spec**: OpenFGA Authorization Model specification; Grafana internal Zanzana design (pkg/services/authz/rollout.go); OWASP Authorization Testing Guide
- **Requirement**: Authorization decisions MUST be made on each individual resource check. Routing an entire batch to one authorization backend based solely on the first item's group/resource, when the batch may contain items with different resource types, can cause authorization decisions for some items to be evaluated by the wrong backend.
- **Code Path**: `pkg/services/authz/rollout.go:72-88` — `rolloutAccessClient.BatchCheck()` routes the entire batch to a single client based on `req.Checks[0].Group` and `req.Checks[0].Resource`. A warning is logged if mixed group/resource is detected, and the batch falls back to RBAC. However, this fallback is based on detection of a mixed batch at the Go level — if all items have the same declared group/resource but represent different semantic resource types due to naming conventions or mapping ambiguity, they would be routed to Zanzana even though only some of them are in the Zanzana rollout.
- **Gap Type**: state-machine
- **Attack Vector**: An attacker who can construct batch authorization requests (e.g., via a compromised API or by triggering batch ACL evaluation through a specially crafted dashboard load) could potentially influence which backend evaluates their requests. If Zanzana and the legacy RBAC system have diverged permissions (a known risk during the transition period identified in Phase 3), routing a batch to Zanzana when it should be evaluated by RBAC could produce an over-permissive result.
- **Exploit Conditions**: (1) Zanzana rollout is partially enabled (`rollout` map has non-zero fractions for any resource). (2) A batch request contains a mix of resource types where the first item would route to Zanzana but subsequent items should route to RBAC. (3) Zanzana's permission model has not been fully synchronized with RBAC (reconciler lag). The vulnerability requires a specific state of the dual-write transition.
- **Impact**: Authorization bypass in the dual-write transition state — a user denied by RBAC but permitted by a stale or incorrectly migrated Zanzana model may gain access by having their request routed to Zanzana via the batch routing heuristic.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // rollout.go:72-88
  func (c *rolloutAccessClient) BatchCheck(...) (...) {
      if len(req.Checks) == 0 {
          return c.rbac.BatchCheck(ctx, id, req)
      }
      group, resource := req.Checks[0].Group, req.Checks[0].Resource  // ← routing based on first item only
      for _, check := range req.Checks[1:] {
          if check.Group != group || check.Resource != resource {
              rolloutLog.Warn("batch contains mixed group/resource combinations, falling back to RBAC", ...)
              return c.rbac.BatchCheck(ctx, id, req)  // ← fallback only for type-heterogeneous batches
          }
      }
      return c.clientFor(req.Namespace, group, resource).BatchCheck(ctx, id, req)
  }
  ```

---

## Summary Table

| # | Gap | Spec | Severity | Gap Type |
|---|-----|------|----------|----------|
| 1 | OIDC ID Token — No claim validation (exp/aud/iss/nonce) after signature verify | OpenID Connect Core 1.0 §3.1.3.7 | HIGH | missing-check |
| 2 | OIDC — Nonce not generated or validated | OpenID Connect Core 1.0 §3.1.2.1 | HIGH | missing-check |
| 3 | JWT Auth JWKS fetch — TLS verification disabled by config | RFC 7519 §10.1 / BCP 195 | HIGH | missing-check |
| 4 | OAuth 2.0 state HMAC — Concatenation without canonical encoding | RFC 6749 §10.12 / RFC 9700 §4.7 | MEDIUM | canonicalization |
| 5 | CSRF check bypassed for non-cookie auth (API key / JWT-URL) | OWASP CSRF Prevention | MEDIUM | missing-check |
| 6 | CSP template contains `unsafe-eval` defeating XSS protection | W3C CSP Level 3 §4.2.2 | MEDIUM | missing-check |
| 7 | WebSocket origin validation skipped for empty Origin header | RFC 6455 §10.2 | MEDIUM | missing-check |
| 8 | HTTP proxy does not strip Connection/hop-by-hop headers | RFC 7230 §6.1 | MEDIUM | normalization |
| 9 | Render key gob deserialization from remote cache (Redis) | OWASP Deserialization | MEDIUM | parsing |
| 10 | OpenFGA batch routing by first item allows mixed-resource bypass | OpenFGA spec / Zanzana design | MEDIUM | state-machine |

---

*This report was produced by the Spec Gap Analyst agent (Phase 6). Findings feed into Phase 8 review chambers. Do NOT re-research domains already in Phase 3 Domain Attack Research.*
