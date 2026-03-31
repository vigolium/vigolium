# Round 5 Hypotheses: Client priority ordering, RBAC cache timing

## PH-23: Render client high priority (10) allows preempting all other auth methods
- **Input path**: `pkg/services/authn/clients/render.go:73-78` -- `Test()` returns true if `renderKey` cookie present
- **Attack input**: Set `renderKey` cookie on request; render client tested at priority 10 before JWT (20), API key (30), session (60)
- **Expected behavior**: If render key is invalid, auth error returned, stops auth chain (but continues to next client because of `continue` in service.go:129)

## PH-24: JWT auth client `Test()` uses `UnsafeClaimsWithoutVerification` to check for sub claim
- **Input path**: `pkg/services/auth/jwt/auth.go:110-123` -- `HasSubClaim` uses `parsed.UnsafeClaimsWithoutVerification`
- **Attack input**: JWT without sub claim used to bypass JWT client Test() and fall through to other auth mechanisms
- **Expected behavior**: JWT without sub claim falls through to API key or other clients -- potentially auth with different identity

## PH-25: RBAC permission sync timing gap during role changes
- **Input path**: `pkg/services/authn/authnimpl/sync/rbac_sync.go` -- permissions synced after authentication
- **Attack input**: User has role changed (demoted) but uses existing session before permission cache expires
- **Expected behavior**: Stale permissions used until sync happens -- timing window for privilege escalation
