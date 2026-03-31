# Round 3 Hypotheses: Auth Proxy, RBAC evaluator, ExtJWT, Session

## PH-14: Auth proxy IP whitelist bypassed if whitelist is empty (default)
- **Input path**: `pkg/services/authn/clients/proxy.go:200-218` -- `isAllowedIP`
- **Attack input**: Auth proxy header from any IP when whitelist empty
- **Expected behavior**: When `len(c.acceptedIPs) == 0`, `isAllowedIP` returns `true` -- any IP accepted

## PH-15: RBAC evaluator with zero scopes grants action on ALL resources
- **Input path**: `pkg/services/accesscontrol/evaluator.go:46-48`
- **Attack input**: A route definition using `EvalPermission(action)` without any scope
- **Expected behavior**: `if len(p.Scopes) == 0 { return true }` -- having the action on ANY scope matches

## PH-16: ExtJWT RenderService type gets Admin role automatically
- **Input path**: `pkg/services/authn/clients/ext_jwt.go:184-190`
- **Attack input**: ExtJWT with ID token subject type `render`
- **Expected behavior**: RenderService always assigned Admin role without checking actual permissions

## PH-17: Auth proxy header injection if headers_encoded is false and proxy passes user-controlled headers
- **Input path**: `pkg/services/authn/clients/proxy.go:83` -- `getProxyHeader(r, c.cfg.AuthProxy.HeaderName, c.cfg.AuthProxy.HeadersEncoded)`
- **Attack input**: Client sends request with auth proxy header name directly (e.g., `X-WEBAUTH-USER: admin`)
- **Expected behavior**: If no reverse proxy strips the header and whitelist is empty, direct client requests are accepted as authenticated

## PH-18: Session cookie token not cryptographically bound to user IP or user-agent
- **Input path**: `pkg/services/authn/clients/session.go:46-74`
- **Attack input**: Stolen session cookie replayed from different IP/user-agent
- **Expected behavior**: Session accepted regardless of IP/UA change -- no binding
