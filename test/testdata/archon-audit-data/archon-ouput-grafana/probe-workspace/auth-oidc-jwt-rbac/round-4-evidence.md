# Round 4 Evidence

## PH-19: Renderer JWT uses default secret "-" allowing token forgery -- VALIDATED

**Evidence:**
1. `pkg/setting/setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` -- default is literally `"-"`
2. `pkg/services/rendering/auth.go:56-68`: `getRenderUserFromJWT` validates with `[]byte(rs.Cfg.RendererAuthToken)` as the HMAC key
3. `pkg/services/rendering/auth.go:58-60`:
   ```go
   tkn, err := jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) {
       return []byte(rs.Cfg.RendererAuthToken), nil
   }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
   ```
4. With default key `"-"`, any attacker can create a valid JWT: sign with HS512 using key byte `0x2D`
5. The JWT payload controls `OrgID`, `UserID`, `OrgRole` -- attacker can set `OrgRole: "Admin"` and `UserID: 1` (admin)
6. HOWEVER: This requires `FlagRenderAuthJWT` feature flag to be enabled (defaults to `false`, still in preview)
7. When feature flag disabled (default), the fallback is cache-based render keys which are random 32-char strings

**Code path:**
- Request with `renderKey` cookie -> `render.go:37` `getRenderKey` -> `auth.go:34` `GetRenderUser` -> checks if JWT (`looksLikeJWT`, line 41) AND feature flag enabled -> `getRenderUserFromJWT` verifies with default key

**Security consequence:** When `renderAuthJWT` feature flag is enabled AND default `renderer_token = "-"` is unchanged, any user can forge a render JWT to authenticate as any user with any role (including Admin).
**Severity:** CRITICAL (when feature flag enabled + default token) / LOW (when feature flag disabled, which is default)

## PH-20: Renderer uses different JWT library than main auth -- VALIDATED (informational)

**Evidence:**
1. `pkg/services/rendering/auth.go:12`: imports `github.com/golang-jwt/jwt/v4`
2. `pkg/services/auth/jwt/auth.go:9-10`: imports `github.com/go-jose/go-jose/v4` and `github.com/go-jose/go-jose/v4/jwt`
3. These are fundamentally different JWT libraries with different validation behavior:
   - `golang-jwt/jwt/v4`: Uses `ParseWithClaims` with keyfunc; validates `exp` by default via `RegisteredClaims`
   - `go-jose/go-jose/v4`: Uses `ParseSigned` then `Claims()` + separate `Validate()`; exp only checked if Expiry is non-nil
4. The renderer JWT at `auth.go:156-158` properly sets `ExpiresAt` in the JWT, and `golang-jwt` validates it by default
5. The main JWT auth path does NOT require `exp` (PH-01/PH-03 findings)

**Security consequence:** Informational -- the dual-library usage creates inconsistency in temporal claim handling. Renderer JWTs properly enforce expiry; main auth JWTs do not.
**Severity:** N/A (informational)

## PH-21: ValidateRedirectTo does not check query string for injection -- NEEDS-DEEPER

**Evidence:**
1. `pkg/api/login.go:54-82` validation flow:
   - Parses URL with `url.Parse`
   - Checks `to.IsAbs()` -- blocks absolute URLs
   - Checks `to.Host != ""` -- blocks host-based URLs
   - Checks `redirectDenyRe` on `to.Path` and `to.Fragment` -- blocks `//` and `..` in path and fragment
   - Checks `redirectAllowRe` on `to.Path` -- only allows `[a-zA-Z0-9-_./]`
2. Query string (`to.RawQuery`) is NOT validated at all
3. However, the redirect is used as an HTTP 302 Location header value, so query string injection doesn't enable XSS
4. Fragment is checked for `//` and `..` but not for JavaScript schemes
5. `to.String()` returns the full URL including query and fragment -- these are preserved in the redirect

**Security consequence:** Query string content is not restricted, but since the value is used as a Location header for HTTP redirect (not as href in HTML), the attack surface is limited. The browser would navigate to the path and query as a same-origin relative URL.
**Severity:** LOW (query injection doesn't enable meaningful attacks in redirect context)

## PH-22: Redirect cookie encoding/decoding mismatch -- NEEDS-DEEPER

**Evidence:**
1. Write: `pkg/middleware/auth.go:103`: `cookies.WriteCookie(c.Resp, "redirect_to", url.QueryEscape(redirectTo), 0, nil)` -- value is QueryEscaped
2. Read: `pkg/api/utils.go:19`: `c.GetCookie("redirect_to")` -- reads raw cookie value
3. The cookie value is QueryEscaped on write, but on read it's passed directly to `ValidateRedirectTo` without QueryUnescaping first
4. `ValidateRedirectTo` calls `url.Parse(redirectTo)` on the QueryEscaped value
5. QueryEscaped paths like `%2F` would be parsed literally by `url.Parse`, resulting in path like `/%2Fsome-path`
6. The validation would likely reject such paths since `%` is not in `redirectAllowRe` pattern `[a-zA-Z0-9-_./]`
7. This means the redirect validation is overly strict (may reject valid redirects) rather than too permissive

**Security consequence:** The encoding mismatch causes the validator to reject some valid redirect targets, but does not create a security bypass. The validator operates on the encoded form, which is MORE restrictive (blocks `%`-encoded chars).
**Severity:** N/A (defense-in-depth actually works here)
