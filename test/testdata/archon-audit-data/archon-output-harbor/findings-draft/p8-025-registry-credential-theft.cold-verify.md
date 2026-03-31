# Cold Verification: p8-025-registry-credential-theft

## Adversarial Verdict

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path mechanically verified end-to-end from admin-controlled URL through auth discovery to Basic auth credential transmission with no IP filtering; reproduction blocked due to deployment complexity but code analysis is conclusive.
Severity-Final: MEDIUM
PoC-Status: theoretical
```

## Summary of Verification

The finding claims that a system administrator can register an external registry with an attacker-controlled URL, and Harbor will send stored credentials to that URL via Basic auth during health checks.

**Code path confirmed:**

1. `CreateRegistry` (registry.go:46) stores admin-supplied URL and credentials after `ValidateHTTPURL` check (scheme-only, no IP filtering).
2. `GetRegistryInfo` (registry.go:179) triggers adapter creation via `NewAdapter` (native/adapter.go:66), which passes decrypted credentials to `registry.NewClientWithCACert`.
3. `HealthCheck` calls `Ping()` (native/adapter.go:124), which calls `c.do(req)` (client.go:175), invoking `c.authorizer.Modify(req)` (client.go:669).
4. The authorizer's `initialize` (auth/authorizer.go:87) sends an unauthenticated probe to the attacker URL. If the attacker responds with `WWW-Authenticate: Basic`, credentials are sent via `req.SetBasicAuth(username, password)` (basic/authorizer.go:38).

**Key nuance not in finding draft:** Credentials are only sent if the attacker's server responds with a `WWW-Authenticate: Basic` (or `Bearer`) challenge. A trivial requirement for an attacker, but a precondition nonetheless.

## Severity Downgrade Rationale (HIGH to MEDIUM)

- **Requires system admin privileges** -- the highest privilege level in Harbor. Both `CreateRegistry` and `GetRegistryInfo` enforce `RequireSystemAccess`.
- **Admin-supplies-credentials paradox** -- the admin who creates the registry already knows the credentials they provide. The meaningful attack scenario requires a multi-admin environment where admin A exfiltrates credentials stored by admin B (by updating the URL of an existing registry).
- **Not remotely exploitable by unauthenticated users** -- this cannot be triggered without authenticated system admin access.
- **Real SSRF/credential-forwarding design weakness** -- despite the precondition, this represents a genuine gap in URL validation that could enable credential theft in multi-admin environments.

## Files Referenced

- `/Users/tuan.v.tran/AuditSource/harbor/src/server/v2.0/handler/registry.go` (lines 46-77, 179-184)
- `/Users/tuan.v.tran/AuditSource/harbor/src/pkg/reg/adapter/native/adapter.go` (lines 66-78, 118-131)
- `/Users/tuan.v.tran/AuditSource/harbor/src/pkg/registry/client.go` (lines 139-141, 170-181, 662-674)
- `/Users/tuan.v.tran/AuditSource/harbor/src/pkg/registry/auth/authorizer.go` (lines 67-138)
- `/Users/tuan.v.tran/AuditSource/harbor/src/pkg/registry/auth/basic/authorizer.go` (lines 36-41)
- `/Users/tuan.v.tran/AuditSource/harbor/src/lib/endpoint.go` (lines 27-44)
- `/Users/tuan.v.tran/AuditSource/harbor/src/controller/registry/controller.go` (line 95)

## Full Review

See: `/Users/tuan.v.tran/AuditSource/harbor/security/adversarial-reviews/registry-credential-theft-review.md`
