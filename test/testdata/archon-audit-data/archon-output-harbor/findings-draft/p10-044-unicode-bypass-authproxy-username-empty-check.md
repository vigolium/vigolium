Phase: 10
Sequence: 044
Slug: unicode-bypass-authproxy-username-empty-check
Verdict: VALID
Rationale: Auth.fillInModel in core/auth/authproxy/auth.go uses strings.TrimSpace to check for empty username, which does not strip Unicode zero-width characters; an auth-proxy that returns a username consisting only of invisible Unicode chars bypasses the empty-username guard and creates a Harbor user with a visually-empty username.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-043-cve-allowlist-unicode-bypass.md
Origin-Pattern: AP-043

## Summary

`Auth.fillInModel` at `src/core/auth/authproxy/auth.go:207-218` gates new user creation on a non-empty username check via `strings.TrimSpace`:

```go
func (a *Auth) fillInModel(u *models.User) error {
    if strings.TrimSpace(u.Username) == "" {
        return fmt.Errorf("username cannot be empty")
    }
    // ...
}
```

Go's `strings.TrimSpace` does not strip Unicode zero-width characters (U+200B, U+200C, U+200D, U+00AD). An HTTP auth-proxy that returns a username containing only zero-width characters (e.g., a misconfigured or malicious proxy) would pass this guard. The resulting Harbor user record has a username that appears blank in the UI and API but is not the empty string, creating undefined behavior in downstream username-based queries.

## Location

- `src/core/auth/authproxy/auth.go:207-218` -- `fillInModel` function
- `src/core/auth/authproxy/auth.go:144-155` -- `PostAuthenticate` calls `fillInModel` during user onboarding

## Attacker Control

- **Input**: Username field from HTTP auth-proxy token review response (`UserFromReviewStatus`)
- **Threat**: A misconfigured or attacker-controlled auth-proxy endpoint (SSRF pivot via p8-027 Config URL No Validation) can return arbitrary username strings
- **Auth requirement**: Depends on auth-proxy access; combined with p8-027 an admin can pivot auth-proxy URL to attacker-controlled server

## Trust Boundary Crossed

- TB-2: External auth-proxy to Harbor Core (trust boundary for external identity provider)
- Auth-proxy username claim treated as trusted after token review; zero-width username bypasses empty guard

## Impact

- Creation of Harbor user account with semantically-empty username
- Username consisting of zero-width chars would appear empty in audit logs and UI
- Potential for duplicate user creation (two separate zero-width-username users with different Unicode compositions)
- `GetByName` lookups for the zero-width username may return unexpected results depending on PostgreSQL collation settings
- Amplified by p8-027: admin can redirect auth-proxy endpoint to attacker server to inject arbitrary usernames

## Evidence

```go
// src/core/auth/authproxy/auth.go:208
if strings.TrimSpace(u.Username) == "" {     // U+200B passes this check
    return fmt.Errorf("username cannot be empty")
}

// strings.TrimSpace("\u200b") returns "\u200b" (non-empty) -- guard bypassed
// Compare with p8-043 (allowlist validator) -- same TrimSpace bypass pattern
```

## Reproduction Steps

1. Configure Harbor with HTTP auth-proxy mode
2. Control or simulate the auth-proxy to return a username of `\u200b` (zero-width space) in the token review response
3. Authenticate via Harbor using the zero-width username credentials
4. `PostAuthenticate` calls `fillInModel`: `strings.TrimSpace("\u200b") == ""` evaluates to false
5. `OnBoardUser` creates a Harbor user with username `\u200b`
6. User appears in harbor_user table but with invisible username in all UI/audit contexts
7. Recommended fix: apply Unicode-aware empty check: `strings.TrimFunc(u.Username, ...)` stripping invisible/format characters
