Phase: 8
Sequence: 005
Slug: ldap-null-bind-auth-bypass
Verdict: FALSE POSITIVE (adversarial)
Rationale: Missing empty password check is a clear RFC 4511 violation with unused sentinel error as proof of developer awareness, and no alternative Harbor-side protection found.
Severity-Original: HIGH
PoC-Status: blocked
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The go-ldap library v3.4.11 Conn.Bind() method hardcodes AllowEmptyPassword:false and SimpleBind() rejects empty passwords client-side at bind.go:65-67 before any LDAP network request, making the claimed attack impossible.
Severity-Final: INFORMATIONAL
PoC-Status: blocked

## Summary

Harbor's LDAP authentication path does not check for empty passwords before performing an LDAP bind operation. When a user submits a login request with a valid username and an empty password, Harbor passes the empty password directly to the LDAP server via `ldapSession.Bind(dn, "")`. Per RFC 4511 Section 4.2, an empty-password bind is an "unauthenticated" (anonymous) bind, not authentication of the named DN. Many LDAP servers (OpenLDAP default config, some Active Directory configurations) accept null binds, causing Harbor to treat the bind as a successful authentication.

## Location

- `src/core/auth/ldap/ldap.go:87` -- `ldapSession.Bind(dn, m.Password)` with no empty check
- `src/core/auth/ldap/ldap.go:57` -- username empty check exists (password check absent)
- `src/pkg/ldap/ldap.go:190-192` -- `Session.Bind` passes empty password to go-ldap
- `src/pkg/ldap/ldap.go:39` -- `ErrEmptyPassword` declared but unused in auth path

## Attacker Control

The attacker controls the password field in the login request. Setting it to an empty string triggers the null bind. The username must be a valid LDAP user (enumerable via login error timing or other means).

## Trust Boundary Crossed

External network -> Authenticated Harbor session as any LDAP user. The empty password bypasses the intended credential verification.

## Impact

- Authentication bypass for any LDAP user account
- Includes system admin accounts if LDAP admin group is configured
- Affects all Harbor instances configured with LDAP auth mode where the LDAP server accepts null binds
- The `ErrEmptyPassword` sentinel error exists but is unused, suggesting the developer was aware of the need

## Evidence

```go
// src/core/auth/ldap/ldap.go:55-90
func (l *Auth) Authenticate(ctx context.Context, m models.AuthModel) (*models.User, error) {
    p := m.Principal
    if len(strings.TrimSpace(p)) == 0 {   // username check EXISTS
        return nil, auth.NewErrAuth("Empty user id")
    }
    // ... search user by username ...
    dn := ldapUsers[0].DN
    if err = ldapSession.Bind(dn, m.Password); err != nil {  // NO empty password check
        return nil, auth.NewErrAuth(err.Error())
    }
    // ... user authenticated ...
}

// src/pkg/ldap/ldap.go:39 -- sentinel exists but unused
var ErrEmptyPassword = errors.New("empty password")
```

## Reproduction Steps

1. Configure Harbor with LDAP auth mode pointing to an OpenLDAP server with default config (null binds permitted)
2. Identify a valid LDAP username (e.g., via user search or login error message differences)
3. Send login request: `curl -X POST https://harbor.example.com/c/login -d '{"principal":"validuser","password":""}'`
4. Observe successful authentication -- Harbor session cookie returned
5. Verify access to Harbor resources as the LDAP user
6. Recommended fix: Add `if len(strings.TrimSpace(m.Password)) == 0 { return nil, auth.NewErrAuth("empty password") }` before the Bind call
