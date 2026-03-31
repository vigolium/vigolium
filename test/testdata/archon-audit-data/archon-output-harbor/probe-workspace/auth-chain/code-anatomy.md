# Code Anatomy: auth-chain

## 1. Security Context Generator Chain Call Graph

### Entry: `security.Middleware` (security.go:47)

```
security.Middleware()
  for each generator in [secret, oidcCli, v2Token, idToken, authProxy, robot, basicAuth, session, proxyCacheSecret]:
    ctx = generator.Generate(req)
    if ctx != nil:
      set security context in request context
      break
  next.ServeHTTP(w, r)
```

**First-match-wins semantics**: If `secret.Generate` matches, all subsequent generators are skipped.

---

### Path 1: secret.Generate (secret.go:29)

```
secret.Generate(req)
  sec = commonsecret.FromRequest(req)         // reads "Authorization: Harbor-Secret <val>"
  if len(sec) == 0: return nil
  return securitysecret.NewSecurityContext(sec, config.SecretStore)
    // SecretStore.IsValid(sec) checked at access time
    // If valid: IsAuthenticated=true, GetUsername=commonsecret.JobserviceUser, IsSystemAdmin=true
```

**Key risk**: No path validation. Any request to any endpoint with a valid secret header gets full internal trust. There is no enforcement that Nginx strips this header for external requests.

---

### Path 2: oidcCli.Generate (oidc_cli.go:48)

```
oidcCli.Generate(req)
  if authMode != OIDCAuth: return nil
  username, secret = req.BasicAuth()          // attacker-controlled
  if !o.valid(req): return nil                // path whitelist check
  if strings.HasPrefix(username, robotPrefix): return nil
  u = uctl.GetByName(ctx, username)           // DB lookup
  info = oidc.VerifySecret(ctx, username, secret)
    -> defaultManager.VerifySecret(ctx, username, secret)
       oidcUser = dm.metaDao.GetByUsername(ctx, username)
       key = keyLoader.encryptKey()           // AES key from config
       plainSecret = utils.ReversibleDecrypt(oidcUser.Secret, key)
       if secret != plainSecret: return error  // timing-safe? utils.ReversibleDecrypt
       tokenStr = utils.ReversibleDecrypt(oidcUser.Token, key)
       token = json.Unmarshal(tokenStr)
       if !token.Valid():
         token = refreshToken(ctx, token)     // outbound call to OIDC provider
         persist updated token to DB
       info = UserInfoFromToken(ctx, token)   // may make outbound userinfo call
       return info
  oidc.InjectGroupsToUser(info, u)
  return local.NewSecurityContext(u)
```

**Key risk at line 74**: Admin user (UserID==1) skips the error log on failed VerifySecret (`if u.UserID != 1 { logger.Errorf(...) }`) — but the function still returns `nil` security context on error. This is benign for context but means failed admin auth is not logged.

**Key risk**: `VerifySecret` decrypts the OIDC token stored in DB and calls `UserInfoFromToken` which may call the remote userinfo endpoint. If the token has expired, `refreshToken` is called — triggering an outbound OAuth2 token refresh flow. The fresh token is then persisted. An attacker knowing the OIDC CLI secret can thus force token refreshes.

---

### Path 3: v2Token.Generate (v2_token.go:44)

```
v2Token.Generate(req)
  if !strings.HasPrefix(req.URL.Path, "/v2"): return nil
  tokenStr = bearerToken(req)                 // reads "Authorization: Bearer <val>"
  opt = token.DefaultTokenOptions()           // RS256, reads private key from filesystem
  cl = &v2TokenClaims{}
  t, err = token.Parse(opt, tokenStr, cl)     // validates RS256 signature
    -> jwt.NewParser(jwt.WithLeeway(JwtLeeway), jwt.WithValidMethods(["RS256"]))
    -> parser.ParseWithClaims(rawToken, claims, keyFunc)
       keyFunc returns: privateKey.PublicKey (RSA public from filesystem)
  v = jwt.NewValidator(jwt.WithLeeway(JwtLeeway), jwt.WithAudience(token.Registry))
  v.Validate(t.Claims)                        // validates exp (with leeway) and audience
  claims = t.Claims.(*v2TokenClaims)
  tokenIssuedAfterProjectCreation(ctx, logger, claims)
    info = lib.GetArtifactInfo(ctx)           // reads from context (set by ArtifactInfo middleware)
    if info.ProjectName == "": return true   // BYPASS: no project name = skip check
    p = project_ctl.GetByName(ctx, info.ProjectName)
    iat = claims.IssuedAt.Time
    if iat.Add(JwtLeeway).Before(p.CreationTime): reject
    return true
  return v2token.New(ctx, claims.Subject, claims.Access)
```

**Key risk (line 85-87)**: If `ArtifactInfo` middleware is not invoked before `v2Token.Generate` (e.g., for the `/v2/` base path or when `ArtifactInfo` parsing fails), `ProjectName` is empty and the timestamp check is completely skipped.

**Key risk**: `common.JwtLeeway` is used both in `Parse` (signature validation leeway) and `Validate` (audience/expiry leeway). The leeway window defines the grace period during which an expired or not-yet-valid token is accepted.

---

### Path 4: idToken.Generate (idtoken.go:33)

```
idToken.Generate(req)
  if authMode != OIDCAuth: return nil
  if !strings.HasPrefix(req.URL.Path, "/api") && req.URL.Path != "/service/token": return nil
  token = bearerToken(req)                    // reads "Authorization: Bearer <val>"
  claims = oidc.VerifyToken(ctx, token)       // full OIDC verification with ClientID check
    -> verifyTokenWithConfig(ctx, token, nil)
       p = provider.get(ctx)                  // gets/creates OIDC provider (refreshed every 3s)
       conf = &gooidc.Config{ClientID: settings.ClientID}
       verifier = p.Verifier(conf)
       return verifier.Verify(ctx, token)     // verifies: signature, issuer, audience=ClientID, expiry, nonce
  u = user.Ctl.GetBySubIss(ctx, claims.Subject, claims.Issuer)
  info = oidc.UserInfoFromIDToken(ctx, &oidc.Token{RawIDToken: token}, *setting)
    -> parseIDToken(ctx, token)               // SKIP expiry, SKIP clientID check
       conf = &gooidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true}
       return verifyTokenWithConfig(ctx, token, conf)
  oidc.InjectGroupsToUser(info, u)
  return local.NewSecurityContext(u)
```

**Key risk**: `VerifyToken` correctly verifies the full token. Then `UserInfoFromIDToken` re-parses the SAME token with `SkipClientIDCheck: true, SkipExpiryCheck: true`. The second parse is redundant for group extraction but means if an attacker can substitute a different ID token after the first check (race condition), the groups are extracted from the second (less-verified) parse. In practice this is not a race, but the dual parse is architecturally fragile.

---

### Path 5: authProxy.Generate (auth_proxy.go:35)

```
authProxy.Generate(req)
  if authMode != HTTPAuth: return nil
  if !strings.HasPrefix(req.URL.Path, "/v2"): return nil
  proxyUserName, proxyPwd = req.BasicAuth()  // attacker-controlled
  rawUserName, match = matchAuthProxyUserName(proxyUserName)
    // requires strings.HasPrefix(name, common.AuthProxyUserNamePrefix)
    // strips prefix
  if !match: return nil
  httpAuthProxyConf = config.HTTPAuthProxySetting(ctx)
  tokenReviewStatus = authproxy.TokenReview(proxyPwd, httpAuthProxyConf)
    // POST to configured TokenReviewEndpoint with proxyPwd as bearer
    // returns status: user.username, user.groups, authenticated bool
  if rawUserName != tokenReviewStatus.User.Username: return nil  // username binding
  user = pkguser.Mgr.GetByName(ctx, rawUserName)
  if NotFound:
    uid = auth.SearchAndOnBoardUser(ctx, rawUserName)  // creates user in DB
    user = pkguser.Mgr.Get(ctx, uid)
  u2 = authproxy.UserFromReviewStatus(tokenReviewStatus, adminGroups, adminUsernames)
  user.GroupIDs = u2.GroupIDs
  user.AdminRoleInAuth = u2.AdminRoleInAuth
  return local.NewSecurityContext(user)
```

**Key risk**: `proxyPwd` (the review token) is user-supplied and sent directly to the configured token review endpoint. The endpoint's response determines group membership and admin status. If the token review endpoint is attacker-controlled or responds with crafted data, admin role can be injected.

**Key risk**: The `AuthProxyUserNamePrefix` check (stripping the prefix) means a username like `robot$admin` would pass through if `robot$` is not the exact prefix. The prefix is `common.AuthProxyUserNamePrefix`.

---

### Path 6: robot.Generate (robot.go:33)

```
robot.Generate(req)
  name, secret = req.BasicAuth()             // attacker-controlled
  if !strings.HasPrefix(name, config.RobotPrefix(ctx)): return nil
  robots = robot_ctl.Ctl.List(ctx, q.New(q.KeyWords{
    "name": strings.TrimPrefix(name, config.RobotPrefix(ctx)),
  }), &robot_ctl.Option{WithPermission: true})
  if len(robots) == 0: return nil
  robot = robots[0]
  if utils.Encrypt(secret, robot.Salt, utils.SHA256) != robot.Secret: return nil
  if robot.Disabled: return nil
  now = time.Now().Unix()
  if robot.ExpiresAt != -1 && robot.ExpiresAt <= now: return nil
  return robotCtx.NewSecurityContext(robot)
```

**Key risk**: `utils.Encrypt(secret, robot.Salt, utils.SHA256)` — SHA256(password+salt) — a single-round hash. No bcrypt/argon2. If the `robot` table is leaked (SQL injection), secrets can be brute-forced offline with moderate GPU resources.

**Key risk**: `robots[0]` — if multiple robots exist with the same trimmed name (different prefixes?), only the first is used. This could be a timing/race if robot creation is concurrent.

---

### Path 7: basicAuth.Generate (basic_auth.go:60)

```
basicAuth.Generate(req)
  username, password = req.BasicAuth()       // attacker-controlled
  user = auth.Login(ctx, AuthModel{Principal: username, Password: password})
    authMode = config.AuthMode(ctx)
    if authMode == "" || IsSuperUser(ctx, username):
      authMode = DBAuth                      // BYPASS: admin always uses DB auth
    authenticator = registry[authMode]
    if lock.IsLocked(username): return nil   // lockout check
    user = authenticator.Authenticate(ctx, m)
    if ErrAuth: lock.Lock(username); sleep(1.5s)
    authenticator.PostAuthenticate(ctx, user)
  return local.NewSecurityContext(user)
```

**Key risk**: `IsSuperUser` does a DB lookup by username to check if `userID == 1`. This lookup happens on EVERY authentication attempt. If the admin username is known, this function is called before the actual authentication, leaking information about whether user ID 1 exists with that username.

**Key risk**: The lockout (`lock.IsLocked`) applies per-username. The lock is an in-memory lock (`frozenTime = 1500ms`). In a multi-instance Harbor deployment (multiple core pods), the lockout does not propagate across instances. Brute force can proceed across multiple pods.

---

### Path 8: session.Generate (session.go:31)

```
session.Generate(req)
  store = web.GlobalSessions.SessionStart(httptest.NewRecorder(), req)
    // reads session cookie from request
    // loads session data from Redis
  userInterface = store.Get(ctx, "user")
  user = userInterface.(models.User)          // type assertion
  return local.NewSecurityContext(&user)
```

**Key risk**: Session data (`models.User`) is stored in Redis without application-level integrity check. In unauthenticated Redis deployments (common), an attacker with Redis access can inject arbitrary `models.User` objects. The type assertion is the only gate.

**Key risk**: Uses `httptest.NewRecorder()` as response writer — this is a test utility being used in production code. The session cookie cannot be set in the response through this path; this is a code smell indicating the session is read-only here.

---

### Path 9: proxyCacheSecret.Generate (proxy_cache_secret.go:29)

```
proxyCacheSecret.Generate(req)
  artifact = lib.GetArtifactInfo(ctx)        // from context (set by ArtifactInfo middleware)
  if artifact == empty: return nil
  secret = ps.GetSecret(req)                 // reads from request (header or param?)
  if !ps.GetManager().Verify(secret, artifact.Repository): return nil
  return proxycachesecret.NewSecurityContext(artifact.Repository)
```

Limited attack surface; secret is internal.

---

## 2. Token Parsing and Verification Parameters

### V2 Bearer Token (JWT RS256)
```
token.Parse(opt, rawToken, claims):
  jwt.NewParser(
    jwt.WithLeeway(common.JwtLeeway),  // grace period on exp
    jwt.WithValidMethods(["RS256"])    // algorithm restriction
  )
  parser.ParseWithClaims(rawToken, claims, keyFunc)
  // keyFunc: returns privateKey.PublicKey
  // Validates: signature (RS256), exp (with leeway), iat
  // Does NOT validate: aud at parse time

// Then separately:
jwt.NewValidator(
  jwt.WithLeeway(JwtLeeway),
  jwt.WithAudience(svc_token.Registry)  // "harbor-registry"
).Validate(claims)
// Validates: exp again, aud="harbor-registry"
```

**Note**: Algorithm restriction to RS256 via `WithValidMethods` prevents algorithm confusion. Key is loaded from filesystem at startup.

### OIDC ID Token (Full Verification)
```
gooidc.IDToken.Verify via p.Verifier(conf):
  conf = &gooidc.Config{ClientID: settings.ClientID}
  // Validates: signature (from provider JWKS), issuer, audience=ClientID, exp, nonce
```

### OIDC ID Token (Stored/DB context, relaxed)
```
parseIDToken via p.Verifier(conf):
  conf = &gooidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true}
  // Validates: signature only (from provider JWKS), issuer
  // SKIPS: audience check, expiry check
```

### Robot Secret
```
utils.Encrypt(secret, robot.Salt, utils.SHA256)
  = SHA256(secret + salt)  // single-round, fast hash
  compared to robot.Secret (stored hash)
```

### OIDC CLI Secret
```
utils.ReversibleDecrypt(oidcUser.Secret, key)  // AES decrypt
  plainSecret compared to supplied secret (string equality)
```

---

## 3. Conditional Branches That Skip or Short-Circuit Validation

| Location | Condition | Effect |
|---------|-----------|--------|
| `v2_token.go:85-87` | `info.ProjectName == ""` | Skips project creation timestamp check entirely |
| `oidc_cli.go:74` | `u.UserID != 1` | Suppresses error log for admin user; does not skip verification, but silences audit trail |
| `authenticator.go:142` | `authMode == "" || IsSuperUser(ctx, username)` | Forces DBAuth regardless of configured auth mode |
| `authenticator.go:151` | `lock.IsLocked(username)` | Returns nil user with no error — caller cannot distinguish lockout from bad credentials |
| `helper.go:204` | `len(pkceCode) > 0` | If pkceCode is empty string, PKCE verifier is not appended to token exchange |
| `helper.go:298-311` | `remote == nil && local != nil` | Falls back to ID token data silently on network failure to userinfo endpoint |
| `helper.go:301-303` | subject mismatch | Returns error but only when BOTH remote and local are non-nil — single source fallback bypasses this check |
| `authproxy/auth.go:167-174` | `SkipSearch == true` | Returns stub user without directory lookup |
| `oidc_cli.go:62-64` | `strings.HasPrefix(username, config.RobotPrefix(ctx))` | Prevents robot accounts from being processed as OIDC CLI |
| `fix.go:57-72` | `FixEmptySubIss` extracts subject/issuer by decoding JWT payload WITHOUT signature verification | Token manipulation attack if DB is writable |

---

## 4. External Calls

| Location | Target | Triggered By | Trust Level |
|---------|--------|-------------|-------------|
| `authproxy/auth.go:77-84` | Configured auth proxy `Endpoint` | Every Basic Auth login in HTTPAuth mode | High (admin-configured) |
| `authproxy/auth.go:119` | Configured `TokenReviewEndpoint` | Session creation and CLI Docker login | High (admin-configured) |
| `helper.go:207` | OIDC provider token endpoint | OIDC callback code exchange | High (OIDC provider) |
| `helper.go:354` | OIDC provider userinfo endpoint | OIDC CLI secret verification (via VerifySecret -> UserInfoFromToken) | High (OIDC provider) |
| `helper.go:69` | OIDC provider discovery endpoint | Provider initialization and every 3 seconds thereafter | High (OIDC provider) |
| `secret.go:116-117` | OIDC provider token endpoint | CLI auth when token expired (token refresh) | High (OIDC provider) |
| `helper.go:515-533` | OIDC provider revocation endpoint | Logout with offline session | High (OIDC provider) |

---

## 5. Session Read/Write Operations

### Writes (OIDCController.Callback and RedirectLogin):
- `SetSession(redirectURLKey, redirectURL)` — stores attacker-supplied (but validated) redirect URL
- `SetSession(pkceCodeKey, string(pkceCode))` — stores PKCE code verifier
- `SetSession(stateKey, state)` — stores CSRF state
- `SetSession(tokenKey, tokenBytes)` — stores full OIDC token (access + refresh + ID) as JSON bytes
- `SetSession(userInfoKey, string(ouDataStr))` — stores full OIDC user info JSON

### Reads (OIDCController.Callback):
- `GetSession(stateKey)` — compared against URL `state` parameter
- `GetSession(pkceCodeKey).(string)` — cast; produces `""` on type mismatch (silent PKCE bypass)
- `GetSession(redirectURLKey)` — used for post-auth redirect

### Reads (OIDCController.Onboard):
- `GetSession(userInfoKey).(string)` — user info for onboarding (fully trusted from session)
- `GetSession(tokenKey).([]byte)` — token for onboarding

### Reads (session.Generate):
- `store.Get(ctx, "user").(models.User)` — full user model loaded from Redis

---

## 6. Cryptographic Operations

| Operation | Algorithm | Key Source | What Is Validated |
|-----------|-----------|-----------|------------------|
| V2 bearer token sign | RS256 | Private key from `config.TokenPrivateKeyPath()` (filesystem) | JWT signature |
| V2 bearer token verify | RS256 | Public key derived from same private key | JWT signature, exp+leeway, aud="harbor-registry" |
| OIDC ID token verify (full) | Provider-defined (RS256/ES256) | OIDC provider JWKS (fetched at startup) | Signature, iss, aud=ClientID, exp, nonce |
| OIDC ID token verify (relaxed) | Provider-defined | OIDC provider JWKS | Signature, iss ONLY |
| OIDC token stored in DB | AES (ReversibleEncrypt) | `config.SecretKey()` | Encryption/decryption only; not integrity |
| OIDC CLI secret stored in DB | AES (ReversibleEncrypt) | `config.SecretKey()` | Encryption/decryption only |
| Robot secret | SHA256(pwd+salt) | salt stored in `robot` table | Password hash comparison |
| Session data | None (Redis) | N/A | No integrity protection at application layer |

---

## 7. Attacker-Controlled Data Flow

| Input | Entry Point | Used In | Privilege Decision |
|-------|------------|---------|-------------------|
| HTTP `Authorization: Harbor-Secret <val>` header | Any request | `secret.Generate` -> `config.SecretStore.IsValid(val)` | Full internal trust if match |
| Basic Auth username + password (OIDC CLI mode) | `/v2/*`, `/service/token`, select APIs | `oidcCli.Generate` -> `VerifySecret` -> DB lookup -> AES decrypt | OIDC user identity |
| Bearer token JWT (v2) | `/v2/*` requests | `v2Token.Generate` -> RS256 parse -> `tokenIssuedAfterProjectCreation` | Repository access claims from JWT `access` field |
| Bearer token JWT (OIDC ID token) | `/api/*`, `/service/token` | `idToken.Generate` -> OIDC verify -> user lookup by sub+iss | OIDC user identity |
| Basic Auth username (auth proxy mode) | `/v2/*` (HTTPAuth mode) | `authProxy.Generate` -> `matchAuthProxyUserName` -> token review -> username binding check | User identity if token review passes |
| Basic Auth password as token (auth proxy) | `/v2/*` (HTTPAuth mode) | `authProxy.Generate` -> `authproxy.TokenReview(proxyPwd, ...)` | Token review result drives group/admin assignment |
| OIDC callback `state` | `GET /c/oidc/callback?state=` | `OIDCController.Callback` -> compared to session | Controls whether callback is accepted |
| OIDC callback `code` | `GET /c/oidc/callback?code=` | `oidc.ExchangeToken` -> OIDC provider | Exchanged for ID+access+refresh tokens |
| OIDC callback `redirect_url` (stored in session from login) | `GET /c/oidc/login?redirect_url=` | `OIDCController.RedirectLogin` -> `utils.IsLocalPath` check -> session | Post-auth redirect destination |
| Onboard `username` (JSON body) | `POST /c/oidc/onboard` | `OIDCController.Onboard` -> length/char validation -> `ctluser.Ctl.OnboardOIDCUser` | Username for new Harbor account |
| Basic Auth username for all modes | Any path | `basicAuth.Generate` -> `auth.Login` -> `IsSuperUser` DB lookup -> mode-specific authenticator | User identity and auth mode selection |
| Basic Auth prefix name (robot) | Any path | `robot.Generate` -> DB list by name | Robot account identity |
| OIDC groups claim (from ID token or userinfo) | OIDC provider response | `groupsFromClaims` -> `filterGroup` (regex) -> `populateGroupsDB` -> `user.GroupIDs` | Group membership -> RBAC role assignments |
| OIDC admin group claim | OIDC provider response | `userInfoFromClaims` -> `slices.Contains(groups, AdminGroup)` | `AdminRoleInAuth` = true (system admin) |
