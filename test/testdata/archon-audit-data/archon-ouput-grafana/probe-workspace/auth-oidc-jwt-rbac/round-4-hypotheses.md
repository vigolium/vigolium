# Round 4 Hypotheses: Renderer JWT, redirect validation, and JWT library differences

## PH-19: Renderer JWT uses default secret "-" allowing token forgery
- **Input path**: `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT`
- **Attack input**: JWT signed with HS512 using key "-" (single byte)
- **Expected behavior**: Token accepted, attacker controls OrgID, UserID, OrgRole in token payload

## PH-20: Renderer JWT uses golang-jwt/jwt/v4 (different library from main JWT auth)
- **Input path**: `pkg/services/rendering/auth.go:12` -- uses `github.com/golang-jwt/jwt/v4`
- **Observation**: Main JWT auth uses `go-jose/go-jose/v4`, renderer uses `golang-jwt/jwt/v4` -- different validation behavior

## PH-21: ValidateRedirectTo does not check query string for injection payloads
- **Input path**: `pkg/api/login.go:54-82` -- `ValidateRedirectTo`
- **Attack input**: `/valid-path?javascript:alert(1)` or `/valid-path#javascript:alert(1)`
- **Expected behavior**: Path is validated but query/fragment content may allow open redirect via JavaScript schemes

## PH-22: Redirect cookie value read without URL-decoding consistency
- **Input path**: `pkg/api/utils.go:19` -- `c.GetCookie("redirect_to")` vs write at `pkg/middleware/auth.go:103` -- `url.QueryEscape(redirectTo)`
- **Attack input**: Double-encoded redirect URL that bypasses ValidateRedirectTo
- **Expected behavior**: Cookie written with QueryEscape, read without explicit unescape -- potential mismatch
