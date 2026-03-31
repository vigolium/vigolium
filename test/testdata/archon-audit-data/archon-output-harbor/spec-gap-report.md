# Harbor Spec Gap Analysis Report

**Audit Date:** 2026-03-27
**Repository:** goharbor/harbor v2.15.0 (commit 1c7d83141)
**Phase:** 6 - Spec Gap Analysis

---

## Spec Gap Analysis

### Gap: LDAP RFC 4511 Null Bind Bypass — Empty Password Accepted as Valid Credential

- **RFC/Spec**: RFC 4511, Section 4.2 (Bind Operation); also LDAP: Authentication Best Practices
- **Requirement**: RFC 4511 §4.2 states that a SimpleCredentials bind with an empty string password is an *unauthenticated* (anonymous) bind, not an authentication of the named DN. Implementations MUST NOT treat an unauthenticated bind as a successful authentication of the presented DN.
- **Code Path**: `src/core/auth/ldap/ldap.go:87` — `ldapSession.Bind(dn, m.Password)` is called with whatever password value arrives in `m.Password`, including an empty string. The `Bind` implementation at `src/pkg/ldap/ldap.go:190` passes the value directly to `goldap.Conn.Bind()` with no empty-password guard. `ErrEmptyPassword` is declared (`ldap.go:39`) but never used in the authentication path.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker sends a login request with a valid username and an empty password (`""`) to Harbor's `/c/login` endpoint while Harbor is in LDAP authentication mode. The LDAP search succeeds because the service-account bind searches by username (step 1). Harbor then calls `ldapSession.Bind(dn, "")`. If the target LDAP server (Active Directory, OpenLDAP with default config, etc.) permits unauthenticated binds, the bind succeeds and Harbor logs in the user as fully authenticated.
- **Exploit Conditions**: (1) Harbor configured to use LDAP auth mode. (2) Target LDAP server permits unauthenticated binds (default in many OpenLDAP and some AD configurations unless `disallowAnonBind` is set). (3) Attacker knows a valid username or can enumerate usernames via login error message timing.
- **Impact**: Authentication bypass — any LDAP user's account can be accessed with an empty password, granting access to all projects and resources the user is authorized for, up to and including system administrator accounts if the LDAP admin group is configured.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // src/core/auth/ldap/ldap.go:55-90
  func (l *Auth) Authenticate(ctx context.Context, m models.AuthModel) (*models.User, error) {
      p := m.Principal
      if len(strings.TrimSpace(p)) == 0 {   // username empty check exists
          ...
          return nil, auth.NewErrAuth("Empty user id")
      }
      // ... search user ...
      dn := ldapUsers[0].DN
      if err = ldapSession.Bind(dn, m.Password); err != nil {  // NO empty-password check
          return nil, auth.NewErrAuth(err.Error())
      }
  ```
  The declared sentinel error `ErrEmptyPassword` in `src/pkg/ldap/ldap.go:39` is never raised in any authentication code path. The fix pattern (checking `len(m.Password) == 0` before bind) is absent.

---

### Gap: OIDC Core 1.0 — Nonce Claim Not Bound to Authorization Request

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.2.1 (Authentication Request), Section 3.1.3.7 (ID Token Validation), Step 11
- **Requirement**: OIDC Core §3.1.2.1 REQUIRES that the Client MUST include a `nonce` parameter in the Authorization Request for flows where replay protection is needed. §3.1.3.7 Step 11 REQUIRES that the nonce claim value in the ID Token MUST match the nonce value sent in the Authentication Request. Failure to validate the nonce enables ID token replay attacks.
- **Code Path**: `src/core/controllers/oidc.go:68-105` (`RedirectLogin`) and `src/core/controllers/oidc.go:109-247` (`Callback`). The `RedirectLogin` function generates a `state` and a PKCE code but does **not** generate or store a `nonce` value. The `AuthCodeURL` call at `src/pkg/oidc/helper.go:164-188` adds state and PKCE challenge options but no `nonce` option. The `Callback` function verifies state (line 110) and verifies the ID token via `oidc.VerifyToken` (line 146), but since no nonce was included in the request, `go-oidc`'s verifier has no nonce to check — nonce validation is silently skipped.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker who has obtained a valid Harbor ID token (e.g., intercepted via log exposure, earlier session, or compromised OIDC provider) can replay that token during a new callback request. Because there is no nonce binding, Harbor cannot distinguish a fresh ID token from a replayed one. Combined with a CSRF or network position to inject the `id_token` parameter into the callback, an attacker can authenticate as another user without knowing their credentials.
- **Exploit Conditions**: (1) Harbor is configured with OIDC auth. (2) Attacker obtains a prior valid ID token for a target user (possible via audit log exposure, CVE identified in Phase 3). (3) Attacker can trigger a new callback with the replayed token.
- **Impact**: Session fixation / account takeover — attacker obtains a valid Harbor session as the target user.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/core/controllers/oidc.go:69-97
  func (oc *OIDCController) RedirectLogin() {
      state := utils.GenerateRandomString()   // state generated
      pkceCode, err := pkce.Generate()        // PKCE generated
      // NO nonce generated or stored
      url, err := oidc.AuthCodeURL(oc.Context(), state, pkceCode)
      ...
      oc.SetSession(pkceCodeKey, string(pkceCode))
      oc.SetSession(stateKey, state)           // state stored, nonce not stored
  }
  
  // src/core/controllers/oidc.go:146
  _, err = oidc.VerifyToken(ctx, token.RawIDToken)
  // VerifyToken calls go-oidc verifier with no nonce option — nonce check is skipped
  ```

---

### Gap: OIDC Core 1.0 — ID Token Parsed with SkipExpiryCheck for Claim Extraction

- **RFC/Spec**: OpenID Connect Core 1.0, Section 3.1.3.7 (ID Token Validation), Step 9; RFC 7519 §4.1.4 (exp claim)
- **Requirement**: OIDC Core §3.1.3.7 Step 9 REQUIRES that the current time MUST be before the time represented by the `exp` Claim. RFC 7519 §4.1.4 states processors MUST reject tokens past their expiration time.
- **Code Path**: `src/pkg/oidc/helper.go:214-217` — `parseIDToken` is called with `SkipExpiryCheck: true`. This function is the one used for claim extraction from ID tokens stored in the database (`UserInfoFromIDToken` at line 366). When Harbor refreshes a stored OIDC token and re-derives user info (e.g., for CLI auth), it parses the ID token with expiry checking disabled.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker who has obtained a user's OIDC token (via audit log exposure as identified in Phase 3, or a stolen session) can present an expired ID token to Harbor's OIDC CLI authentication path. Because `parseIDToken` skips expiry, the expired token's claims (subject, groups, admin membership) are accepted as valid, granting access for an indeterminate period past the token's intended lifetime.
- **Exploit Conditions**: (1) OIDC auth mode. (2) Attacker has a copy of an expired but otherwise valid ID token for a target user. (3) Access is via the OIDC CLI path that calls `UserInfoFromIDToken`.
- **Impact**: Authentication with expired credentials; token lifetime controls are bypassed, enabling extended unauthorized access.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/pkg/oidc/helper.go:214-217
  func parseIDToken(ctx context.Context, rawIDToken string) (*gooidc.IDToken, error) {
      conf := &gooidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true}
      return verifyTokenWithConfig(ctx, rawIDToken, conf)
  }
  
  // src/pkg/oidc/helper.go:362-371
  func UserInfoFromIDToken(ctx context.Context, token *Token, setting cfgModels.OIDCSetting) (*UserInfo, error) {
      if token.RawIDToken == "" {
          return nil, nil
      }
      idt, err := parseIDToken(ctx, token.RawIDToken)  // expiry NOT checked
      ...
  }
  ```

---

### Gap: OCI Distribution Spec v1.1 — PUT Manifest Accepts Any Content-Type Without Validation

- **RFC/Spec**: OCI Distribution Spec v1.1, Section 4.4 (Pushing Manifests); OCI Image Spec v1.1, Appendix A (Media Types)
- **Requirement**: OCI Distribution Spec §4.4 states the client MUST set the `Content-Type` of the manifest to a recognized media type. The registry SHOULD validate the `Content-Type` header and MUST reject manifests with an invalid or unsupported media type. This prevents manifest type confusion where a client pushes a manifest with a mismatched content-type, causing the registry to store and serve it with incorrect type metadata.
- **Code Path**: `src/server/registry/manifest.go:175-238` (`putManifest`) — the function reads the body to compute digest, rewrites the URL path, and proxies to the backend distribution daemon. It performs no validation of the `Content-Type` header before proxying. The `art.ManifestMediaType` stored in Harbor's database is populated from what the backend distribution daemon records after the push (line 227: `artifact.Ctl.Ensure`), meaning Harbor accepts whatever type the client claims.
- **Gap Type**: missing-check
- **Attack Vector**: An authenticated user with push access sends `PUT /v2/<repo>/manifests/<tag>` with `Content-Type: application/vnd.oci.image.index.v1+json` but a body that is actually a single-platform manifest. Harbor's database records `ManifestMediaType` as `image.index` while the actual content is a single manifest. Subsequent operations that rely on the stored media type (content-trust enforcement, vulnerability scanning triggering, referrers API responses) may behave incorrectly — for example, cosign signature verification or referrers resolution may be skipped if the manifest is treated as an index, bypassing security policy controls.
- **Exploit Conditions**: (1) Authenticated user with push permission on any project. (2) Target policy enforcement (content-trust, vulnerability scanning) uses media type for routing decisions.
- **Impact**: Security policy bypass — content-trust or vulnerability scan enforcement may be skipped due to media type mismatch; referrers API returns incorrect index entries.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/server/registry/manifest.go:175-238
  func putManifest(w http.ResponseWriter, req *http.Request) {
      // No Content-Type validation here
      if _, err := digest.Parse(reference); err != nil {
          data, err := io.ReadAll(req.Body)
          dgst := digest.FromBytes(data)     // digest computed from raw bytes
          req.Body = io.NopCloser(bytes.NewReader(data))
          // Content-Type from original request header is passed through unchanged
      }
      proxy.ServeHTTP(buffer, req)           // proxied to backend with original Content-Type
      ...
      artifact.Ctl.Ensure(req.Context(), repo, dgt, ...)  // stores whatever backend returns
  }
  ```

---

### Gap: OCI Distribution Spec v1.1 — Referrers API Pagination Ignores Spec-Required Cursor Token

- **RFC/Spec**: OCI Distribution Spec v1.1, Section 8.5 (Listing Referrers)
- **Requirement**: The OCI Distribution Spec §8.5 states that when pagination is needed for the referrers API, the registry MUST use the `Link` header with `rel="next"` to indicate subsequent pages, and the cursor MUST be opaque to the client. The spec does not define a numeric page-number model; it requires that the implementation be stateless and use a cursor or digest-based token.
- **Code Path**: `src/server/registry/referrers.go:157-163` — the `WriteResponse` method calls `baseAPI.Links(ctx, req.URL, total, query.PageNumber, query.PageSize)` which generates Harbor's standard numeric pagination link headers using page number and page size query parameters. This is the Harbor v2.0 REST API pagination model, not the OCI Distribution Spec referrers pagination model.
- **Gap Type**: normalization
- **Attack Vector**: A client that correctly follows the OCI Distribution Spec referrers pagination protocol (expecting an opaque next-page token in a `Link` header using OCI spec format) will not be able to retrieve paginated referrer lists. More critically, the use of numeric page numbers means the page boundaries are computed on a sorted, in-memory list loaded in full from the database (see `accessoryManager.List` with no server-side cursor), creating a potential for referrer enumeration via out-of-bounds page numbers and exposing the total count via `X-Total-Count` regardless of authorization. An attacker with read access to any artifact can discover how many signatures, SBOMs, or attestations are attached even if the referrers are in restricted repositories.
- **Exploit Conditions**: (1) OCI-compliant client tries to use the referrers API. (2) More than one page of referrers exists (beyond default page size).
- **Impact**: Information disclosure of referrer count across page boundaries; OCI-compliant clients cannot reliably enumerate referrers; potential DoS if a large number of accessories causes full in-memory load on each request.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/server/registry/referrers.go:76-86
  query := q.New(q.KeyWords{"SubjectArtifactDigest": reference, "SubjectArtifactRepo": repository})
  total, err := r.accessoryManager.Count(ctx, query)  // total always exposed
  accs, err := r.accessoryManager.List(ctx, query)    // full list loaded into memory
  
  // src/server/registry/referrers.go:158-163
  newListReferrersOK().
      WithXTotalCount(total).
      WithFilter(filter).
      WithLink(baseAPI.Links(ctx, req.URL, total, query.PageNumber, query.PageSize).String()).
      // ^^^ Uses Harbor numeric page model, not OCI spec opaque cursor
  ```

---

### Gap: Docker Registry HTTP API V2 — Scope Grammar Colon Splitting Vulnerable to Resource Name Containing Colons

- **RFC/Spec**: Docker Registry Token Scope Grammar (Docker Distribution Spec), Section "Token Scope" grammar definition
- **Requirement**: The Docker Registry V2 token scope grammar defines the format as `resource-type ":" resource-name ":" actions`. The resource-name component is defined to allow colons only in specific encoded forms. The implementation MUST correctly parse scopes where the resource name itself contains colons (e.g., encoded digest references).
- **Code Path**: `src/core/service/token/authutils.go:50-83` (`GetResourceActions`) — the function splits the scope string on `:` to extract `type`, `name`, and `actions`. For a scope with more than 3 colon-separated items, it uses `strings.Join(items[1:length-1], ":")` to reconstruct the name and takes `items[length-1]` as the actions string. This means a scope like `repository:project/repo:sha256:abc123:pull` would be parsed as name=`project/repo:sha256:abc123` and actions=`pull`, which is correct. However, the actions parsing uses `strings.Split(items[length-1], ",")` which only takes the *last* colon-separated segment as the action list. If an attacker crafts a scope string where the desired action is not the last colon-segment, the action list is silently discarded and set to an empty slice.
- **Gap Type**: parsing
- **Attack Vector**: An attacker with an account on Harbor requests a token with a crafted scope parameter that embeds a colon in the actions position: `scope=repository:project/image:pull:extra`. The parser assigns `actions = ["extra"]` instead of `["pull"]`. The `repositoryFilter` then checks whether the user has permission for `extra` — an unknown action. Since `extra` does not appear in `actionScopeMap`, the token is issued with *no* access for that resource (actions cleared). This is a denial-of-service against legitimate scope requests rather than a privilege escalation, but it could also be used to enumerate which scope parsing behaviors are exploitable.
- **Exploit Conditions**: (1) Attacker controls the `scope` parameter in the token request URL. (2) Scope parameter contains embedded colons in the actions segment.
- **Impact**: Denial of service for token issuance — legitimate registry operations fail because the issued token contains no access for the requested resource; potential to probe authorization logic behavior.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/core/service/token/authutils.go:57-76
  items := strings.Split(s, ":")
  length := len(items)
  if length == 1 {
      typee = items[0]
  } else if length == 2 {
      typee = items[0]
      name = items[1]
  } else {
      typee = items[0]
      name = strings.Join(items[1:length-1], ":")   // all middle segments as name
      if len(items[length-1]) > 0 {
          actions = strings.Split(items[length-1], ",")  // ONLY last segment as actions
      }
  }
  ```
  For scope `repository:project/img:sha256:abc:pull`, `length=5`, `name="project/img:sha256:abc"`, `actions=["pull"]` — correct. But for `repository:project/img:pull:delete`, `name="project/img:pull"`, `actions=["delete"]` — the `pull` action is silently dropped from the issued token, producing a token with only `delete` access even though the client requested both.

---

### Gap: OIDC Callback — Unencoded Username Injected into Redirect URL Query String (Open Redirect Amplification)

- **RFC/Spec**: RFC 6749, Section 10.6 (Cross-Site Request Forgery); RFC 3986, Section 3.4 (Query Component Encoding)
- **Requirement**: RFC 3986 §3.4 requires that query parameter values containing reserved characters MUST be percent-encoded. RFC 6749 §10.15 requires that all redirect URIs be validated and that parameters embedded in redirect URIs not allow injection of additional parameters.
- **Code Path**: `src/core/controllers/oidc.go:203` — when a new OIDC user requires onboarding (auto-onboard disabled), the code does:
  ```go
  oc.Controller.Redirect(fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr), http.StatusFound)
  ```
  `username` is the OIDC-provider-supplied `name` claim, processed only by `strings.Replace(username, " ", "_", -1)` (line 176). It is not URL-encoded before being interpolated into the query string.
- **Gap Type**: normalization
- **Attack Vector**: A malicious OIDC provider (or a provider where usernames are user-controlled) supplies a username claim containing `&redirect_url=https://evil.com` or `&admin=true`. When Harbor redirects to `/oidc-onboard?username=<injected>`, the injected parameters are interpreted by the Angular portal's route handling. Specifically, the injected `redirect_url` parameter overrides the legitimate one stored in the original `redirect_url` query parameter, creating a post-onboard open redirect to an attacker-controlled site. This can be used to steal the just-created Harbor session token if the SPA processes the redirect without validation.
- **Exploit Conditions**: (1) Harbor configured with OIDC auto-onboard disabled. (2) OIDC provider is attacker-controlled or permits arbitrary username claims. (3) A new user logs in for the first time (onboarding flow).
- **Impact**: Open redirect amplification at the onboard step — attacker can redirect new users to a phishing site after onboarding, potentially harvesting sessions; parameter injection may also override other query parameters used by the onboarding page.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // src/core/controllers/oidc.go:175-203
  username := info.Username
  username = strings.Replace(username, " ", "_", -1)  // only spaces replaced, not & = ? # etc.
  ...
  oc.Controller.Redirect(
      fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr),
      http.StatusFound,
  )
  // username is NOT url.QueryEscape()'d
  ```

---

## Summary Table

| Gap | Spec | Severity | Exploit Conditions |
|-----|------|----------|--------------------|
| LDAP Null Bind (empty password) | RFC 4511 §4.2 | HIGH | LDAP mode + server allows anon bind |
| OIDC Nonce Not Bound | OIDC Core §3.1.2.1, §3.1.3.7 | MEDIUM | OIDC mode + prior ID token obtained |
| ID Token Expiry Skipped | OIDC Core §3.1.3.7, RFC 7519 §4.1.4 | MEDIUM | OIDC CLI + expired token in hand |
| PUT Manifest Missing Content-Type Validation | OCI Dist Spec v1.1 §4.4 | MEDIUM | Push access + policy relies on media type |
| Referrers API Non-OCI Pagination | OCI Dist Spec v1.1 §8.5 | MEDIUM | Read access + many referrers |
| Token Scope Colon Ambiguity | Docker Dist Spec Token Scope Grammar | MEDIUM | Control of scope parameter |
| OIDC Onboard Username Injection | RFC 3986 §3.4, RFC 6749 §10.15 | MEDIUM | OIDC mode + new user + controlled IdP |

---

**Report Status:** Phase 6 Complete
**Generated:** 2026-03-27
**Next Phase:** Phase 7 / Phase 8 (Finding Chambers)
