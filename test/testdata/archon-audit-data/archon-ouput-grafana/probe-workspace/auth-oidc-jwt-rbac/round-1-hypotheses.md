# Round 1 Hypotheses: JWT exp/nbf bypass, Anonymous auth scope, OAuth claim gaps

## PH-01: JWT tokens without `exp` claim are accepted as never-expiring
- **Assumption broken**: The code assumes JWT tokens will always include an `exp` claim, but never requires it
- **Input path**: `pkg/services/auth/jwt/validation.go:86-89` -- `validateClaims` -- when `exp` key missing from claims map
- **Attack input**: JWT with valid signature but no `exp` claim
- **Expected behavior**: Token accepted indefinitely (never expires)
- **Deepening**: What if `exp` is present but set to `null`? (line 87: `if value == nil { continue }`)

## PH-02: JWT tokens without `nbf` claim bypass not-before validation
- **Assumption broken**: `nbf` validation is skipped if claim missing or nil
- **Input path**: `pkg/services/auth/jwt/validation.go:96-99` -- `validateClaims` -- when `nbf` missing or nil
- **Attack input**: JWT with future `iat` but no `nbf` claim
- **Expected behavior**: Token accepted even if logically not yet valid

## PH-03: JWT `exp: null` explicitly bypasses expiry via nil check
- **Assumption broken**: Explicit `null` value for `exp` is treated same as missing
- **Input path**: `pkg/services/auth/jwt/validation.go:87-88` -- `if value == nil { continue }`
- **Attack input**: JWT with `{"exp": null}` in payload
- **Expected behavior**: `registeredClaims.Expiry` stays nil, go-jose `Validate` skips expiry check (line 116: `if c.Expiry != nil`)

## PH-04: Multiple endpoints use `reqSignedIn` instead of `reqSignedInNoAnonymous` allowing anonymous access
- **Assumption broken**: Routes assume `reqSignedIn` blocks unauthenticated users, but with anonymous enabled it doesn't
- **Input path**: `pkg/api/api.go` -- numerous routes at lines 560, 578, 596, 599, 602, 605, 608
- **Attack input**: HTTP request with no auth credentials when `[auth.anonymous] enabled = true`
- **Expected behavior**: Anonymous user gets Viewer-equivalent access to admin APIs (but RBAC may still block)

## PH-05: `/api/gnet/*` proxy accessible to anonymous users
- **Assumption broken**: Gnet proxy should require authenticated user
- **Input path**: `pkg/api/api.go:602` -- `r.Any("/api/gnet/*", ..., reqSignedIn, hs.ProxyGnetRequest)`
- **Attack input**: Anonymous request to `/api/gnet/api/plugins` when anon enabled
- **Expected behavior**: Anonymous user can proxy requests through Grafana to grafana.net

## PH-06: `/render/*` endpoint accessible to anonymous users
- **Assumption broken**: Render handler should require authenticated user
- **Input path**: `pkg/api/api.go:599` -- `r.Get("/render/*", ..., reqSignedIn, hs.RenderHandler)`
- **Attack input**: Anonymous request to render endpoint
- **Expected behavior**: Anonymous user can trigger server-side rendering

## PH-07: OAuth `sub` claim not required by default (behind feature flag)
- **Assumption broken**: OAuth authentication should always require a `sub` claim to identify the user
- **Input path**: `pkg/services/authn/clients/oauth.go:189-195` -- sub claim check gated by `FlagOauthRequireSubClaim`
- **Attack input**: OAuth provider that returns an ID token without `sub` claim
- **Expected behavior**: User authenticated without stable identity; feature flag `oauthRequireSubClaim` defaults to `false`

## PH-08: RBAC scope injection via Go `text/template` in URL parameters
- **Assumption broken**: URL parameters injected into scope templates are treated as data, but `text/template` allows function calls
- **Input path**: `pkg/services/accesscontrol/middleware.go:409-421` -- `scopeInjector` uses `template.New("scope").Parse(scope)` then `tmpl.Execute(&buf, params)`
- **Attack input**: URL parameter containing Go template syntax (e.g., `{{.OrgID}}`)
- **Expected behavior**: Template is the scope definition (from code), not user input -- but URL params are injected as template data, not into the template string itself. LIKELY SAFE but needs verification.
