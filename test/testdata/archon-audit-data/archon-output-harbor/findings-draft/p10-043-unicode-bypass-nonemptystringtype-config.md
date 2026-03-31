Phase: 10
Sequence: 043
Slug: unicode-bypass-nonemptystringtype-config
Verdict: VALID
Rationale: NonEmptyStringType.validate in lib/config/metadata/type.go uses strings.TrimSpace as its sole emptiness check, which does not strip Unicode zero-width characters, allowing a configuration field value consisting only of invisible Unicode chars (U+200B etc.) to pass validation while being semantically empty; shares the same root cause as p8-043.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-043-cve-allowlist-unicode-bypass.md
Origin-Pattern: AP-043

## Summary

`NonEmptyStringType.validate` at `src/lib/config/metadata/type.go:54-58` uses `strings.TrimSpace` as its sole emptiness guard:

```go
func (t *NonEmptyStringType) validate(str string) error {
    if len(strings.TrimSpace(str)) == 0 {
        return ErrStringValueIsEmpty
    }
    return nil
}
```

Go's `strings.TrimSpace` only strips characters matched by `unicode.IsSpace()`. Unicode zero-width characters (U+200B zero-width space, U+200C zero-width non-joiner, U+200D zero-width joiner, U+00AD soft hyphen) are NOT stripped. A configuration value consisting entirely of such characters passes `NonEmptyStringType` validation but is semantically empty, causing downstream consumers to receive garbage values for required configuration fields.

`NonEmptyStringType` is used for LDAP Base DN (`LDAP_BASE_DN`), LDAP UID attribute (`LDAP_UID`), and LDAP URL (`LDAP_URL`) in `metadatalist.go`.

## Location

- `src/lib/config/metadata/type.go:54-58` -- `NonEmptyStringType.validate`
- `src/lib/config/metadata/metadatalist.go:84` -- LDAP Base DN uses `NonEmptyStringType`
- `src/lib/config/metadata/metadatalist.go:95` -- LDAP UID uses `NonEmptyStringType`
- `src/lib/config/metadata/metadatalist.go:96` -- LDAP URL uses `NonEmptyStringType`

## Attacker Control

- **Input**: LDAP/OIDC configuration values via `PUT /api/v2.0/configurations` (system admin)
- **Control level**: Full control over string content including Unicode characters
- **Auth requirement**: System admin

## Trust Boundary Crossed

- Admin configuration validation boundary -- validation is expected to prevent empty required fields; invisible characters bypass the guard silently

## Impact

- A system admin (or attacker with stolen admin session) can set LDAP Base DN to `\u200B` (zero-width space) which passes `NonEmptyStringType` validation
- The LDAP authenticator receives a zero-width-only Base DN and issues LDAP search requests with no base, potentially matching the root DSE and returning unintended results
- LDAP URL set to `\u200B` would fail LDAP connection but appear non-empty in audit/config display, making misconfiguration diagnosis difficult
- Shares root cause with p8-043: `strings.TrimSpace` is insufficient for detecting semantically empty strings

## Evidence

```go
// src/lib/config/metadata/type.go:54-58
func (t *NonEmptyStringType) validate(str string) error {
    if len(strings.TrimSpace(str)) == 0 {   // TrimSpace does NOT strip U+200B
        return ErrStringValueIsEmpty
    }
    return nil
}

// src/lib/config/metadata/metadatalist.go:84
{Name: common.LDAPBaseDN, ..., ItemType: &NonEmptyStringType{}, ...}
// LDAP_BASE_DN validated only by NonEmptyStringType -- accepts "\u200B"
```

## Reproduction Steps

1. Authenticate as system admin
2. PUT /api/v2.0/configurations with body: `{"ldap_base_dn": "\u200b"}`
3. Verify: 200 OK, validation passes
4. Read back config: LDAP Base DN appears as a non-empty string in UI/API
5. Attempt LDAP authentication: Base DN is a zero-width space, LDAP search has no effective base
6. Recommended fix: use `strings.TrimFunc(str, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) })` instead of `strings.TrimSpace`
