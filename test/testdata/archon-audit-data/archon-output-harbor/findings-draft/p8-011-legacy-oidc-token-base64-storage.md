Phase: 8
Sequence: 011
Slug: legacy-oidc-token-base64-storage
Verdict: VALID
Rationale: Residual encryption migration risk in upgraded instances. Base64 fallback confirmed in code. DB access is an elevated precondition.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

Harbor's `ReversibleDecrypt` function at `encrypt.go:82-89` falls back to base64 decoding when the stored value lacks the `<enc-v1>` AES encryption prefix. In Harbor instances upgraded from older versions (pre-AES-encryption), OIDC user records in the `oidc_user.token` and `oidc_user.secret` columns may still contain legacy base64-encoded values. These records can be decoded without the AES key, exposing OIDC tokens (including refresh tokens) and CLI secrets to anyone with database read access.

## Location

- `src/common/utils/encrypt.go:82-89` -- `ReversibleDecrypt` base64 fallback
- `src/pkg/oidc/dao/` -- `oidc_user` table DAO
- Database: `oidc_user.token` and `oidc_user.secret` columns

## Attacker Control

The attacker needs read access to the PostgreSQL database's `oidc_user` table. This is an elevated position but is reachable via SQL injection (if any exist), database backup exposure, or compromised database credentials.

## Trust Boundary Crossed

Database read access -> Plaintext OIDC tokens. The encryption at rest intended to protect these values is absent for legacy records.

## Impact

- OIDC refresh tokens for legacy accounts recoverable without AES key
- CLI secrets for legacy accounts exposed in plaintext (base64 encoding only)
- Affects only Harbor instances upgraded from pre-encryption versions with unmigrated records
- New records created after the encryption migration use AES and are protected

## Evidence

```go
// src/common/utils/encrypt.go:82-89
func ReversibleDecrypt(str, key string) (string, error) {
    if strings.HasPrefix(str, encryptHeaderV1) {
        // AES decryption path (new records)
        return decryptAES(strings.TrimPrefix(str, encryptHeaderV1), key)
    }
    // Base64 fallback path (legacy records) -- NO AES key needed
    return decodeB64(str)
}
```

## Reproduction Steps

1. Identify a Harbor instance that was upgraded from a pre-AES-encryption version
2. Query the `oidc_user` table: `SELECT token, secret FROM oidc_user WHERE token NOT LIKE '<enc-v1>%'`
3. For any returned records, base64-decode the `token` column: `echo "<value>" | base64 -d`
4. Observe the plaintext OIDC token JSON (containing refresh_token, access_token, etc.)
5. Recommended fix: Add a one-time migration that re-encrypts all legacy base64 records with AES, or reject base64 fallback in production mode
