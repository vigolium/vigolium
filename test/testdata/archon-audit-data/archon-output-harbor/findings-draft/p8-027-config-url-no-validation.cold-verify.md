# Cold Verification: p8-027-config-url-no-validation

## Verdict

```
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Admin-only config fields for auth endpoints are intended functionality; URL validation cannot prevent a malicious admin from setting syntactically-valid but attacker-controlled endpoints; LDAP has scheme validation contradicting "zero validation" claim.
Severity-Final: LOW
PoC-Status: blocked
```

## Reasoning Summary

This finding describes intended administrator functionality -- configuring authentication provider endpoints -- as a vulnerability. The attack requires system administrator credentials, which is the highest privilege level in Harbor. Three decisive factors lead to DISPROVED:

1. **Admin-does-admin-things**: Only a system admin (verified via `RequireSystemAccess` at `src/server/v2.0/handler/config.go:76`) can modify these settings. A malicious admin already controls the entire Harbor instance and has far more direct attack paths (modifying users, disabling security, etc.). URL validation cannot prevent an admin from setting a syntactically-valid but malicious endpoint like `https://evil-but-legit-looking.example.com`.

2. **LDAP scheme validation exists**: The finding claims "zero URL validation" but `formatURL()` at `src/pkg/ldap/ldap.go:77-115` validates that LDAP URLs use only `ldap://` or `ldaps://` schemes (line 87: `if !((protocol == "ldap") || (protocol == "ldaps"))`). The claim that `http://169.254.169.254/`, `ftp://`, or `file:///` would work for LDAP is factually incorrect.

3. **Project explicitly accepts admin-config risk**: Harbor's `SECURITY.md` (line 79) states: "we do not currently consider the default settings for Harbor to be secure-by-default. It is necessary for operators to explicitly configure settings." This confirms admin configuration is outside their security threat model.

## Code Evidence

- `src/lib/config/metadata/type.go:41-43` -- `StringType.validate()` returns nil (confirmed, no URL validation at type level)
- `src/controller/config/controller.go:115-147` -- `validateCfg()` has no URL validation (confirmed)
- `src/pkg/ldap/ldap.go:77-115` -- `formatURL()` DOES validate LDAP URL scheme (contradicts finding)
- `src/pkg/oidc/helper.go:93` -- OIDC endpoint used directly in `gooidc.NewProvider()` (confirmed, no validation)
- `src/server/v2.0/handler/config.go:76` -- Requires system admin access (confirmed)
- `src/lib/endpoint.go:27` -- `ValidateHTTPURL()` exists but is not applied here (confirmed, defense-in-depth gap)

## Full Review

See: `/Users/tuan.v.tran/AuditSource/harbor/security/adversarial-reviews/config-url-no-validation-review.md`
