# Cold Verification: p8-031-preheat-token-theft

## Verdict

```
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Attack requires system admin who already has unrestricted image pull access; capturing a scoped pull token provides zero privilege escalation; preheat token forwarding is by-design behavior.
Severity-Final: LOW
PoC-Status: theoretical
```

## Key Findings

### Code Path Verified (Dragonfly only)

The token forwarding code path exists and is correctly described for the Dragonfly provider:

1. `enforcer.go:159-175` -- `credMaker` generates Bearer JWT via `token.MakeToken` with pull scope
2. `enforcer.go:444-445` -- Token placed in `PreheatImage.Headers["Authorization"]`
3. `dragonfly.go:250` -- `headerToMapString(preheatingImage.Headers)` copies token into JSON body
4. `dragonfly.go:268-269` -- JSON body POST-ed to configured Dragonfly endpoint

### Factual Error in Finding

The finding claims `kraken.go:100` exhibits the "Same pattern for Kraken driver." This is **incorrect**. The Kraken driver at `kraken.go:80-111` constructs a `notification.Notification` payload containing only image metadata (digest, repository, URL, tag). It does NOT include `preheatingImage.Headers`. The Kraken path does not leak the authorization token.

### Decisive Defense: Admin-Only Access

All preheat instance operations require `RequireSystemAccess` (`preheat.go:73`). A Harbor system administrator already has:

- Full access to all projects and repositories
- Ability to pull any image directly
- Control over all Harbor configuration

Capturing a pull-scoped, 30-minute-TTL token for a single repository provides zero additional capability to a system admin.

### By-Design Behavior

The preheat feature is explicitly designed to provide credentials to external P2P distribution systems (Dragonfly, Kraken) so they can pull images from Harbor for pre-caching. Sending the authorization header to the configured endpoint IS the intended mechanism. The admin who registers the preheat instance is the one who decides to trust that endpoint.

## Conclusion

DISPROVED as a security vulnerability. The token forwarding is by-design behavior in a feature that requires the highest privilege level to configure. No trust boundary is meaningfully crossed because the system admin already controls both sides of the interaction. Downgraded from HIGH to LOW (informational design concern at best).

## Review File

Full review: `security/adversarial-reviews/preheat-token-theft-review.md`
