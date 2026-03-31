Phase: 10
Sequence: 022
Slug: registry-credential-base64-fallback
Verdict: VALID
Rationale: Replication registry access secrets use the same ReversibleDecrypt base64 fallback path confirmed in p8-011, meaning legacy registry credentials in the registry table are recoverable without the AES key.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-011-legacy-oidc-token-base64-storage.md
Origin-Pattern: AP-007

## Summary

Harbor's replication registry manager (`pkg/reg/manager.go:191`) decrypts registry `access_secret` credentials using `utils.ReversibleDecrypt`, the same function confirmed in p8-011 to fall back to base64 decoding when the stored value lacks the `<enc-v1>` AES prefix. In Harbor instances upgraded from pre-AES-encryption versions, the `registry` table's `access_secret` column may contain legacy base64-encoded registry passwords. These can be decoded without the AES key by anyone with database read access, exposing replication credentials (passwords, API tokens) for all configured external registries (Docker Hub, ECR, GCR, Harbor, etc.). The `lib/encrypt/encrypt.go` wrapper also inherits this fallback, affecting any config `PasswordType` field loaded from the DB via `pkg/config/db/db.go:52`.

## Location

- `src/pkg/reg/manager.go:191` -- `utils.ReversibleDecrypt(secret, secretKey)` with base64 fallback
- `src/pkg/reg/dao/model.go:34` -- `access_secret` column in `registry` table
- `src/common/utils/encrypt.go:82-89` -- shared `ReversibleDecrypt` base64 fallback (root cause)
- `src/lib/encrypt/encrypt.go:81` -- `Instance().Decrypt()` calls same function, affects PasswordType config fields
- `src/pkg/config/db/db.go:52` -- PasswordType config items decrypted via same path

## Attacker Control

The attacker needs read access to the PostgreSQL database's `registry` table (or `config` table for PasswordType fields). This is the same elevated precondition as p8-011. Reachable via SQL injection, backup exposure, or compromised DB credentials.

## Trust Boundary Crossed

Database read access -> Plaintext replication credentials. Registry `access_secret` values encrypted before the AES migration are recoverable as base64 without the AES key, exposing credentials for all external registries configured for replication.

## Impact

- Registry credentials (passwords, API tokens) for all legacy replication targets exposed in plaintext (base64 only)
- Compromised credentials enable: unauthorized image push/pull at target registries, lateral movement to connected registries (ECR, GCR, Docker Hub accounts), and supply-chain attacks via image tampering at replicated registries
- Also affects PasswordType config fields (LDAP bind password via `lib/encrypt` wrapper) stored before AES migration
- Registry credentials are long-lived service account credentials -- no automatic rotation
- Compared to p8-011 (OIDC tokens): registry credentials are static passwords rather than time-limited tokens, potentially worse long-term exposure

## Evidence

```go
// src/pkg/reg/manager.go:182-196
func decrypt(secret string) (string, error) {
    if len(secret) == 0 {
        return "", nil
    }
    secretKey, err := config.SecretKey()
    // ...
    decrypted, err := utils.ReversibleDecrypt(secret, secretKey)  // base64 fallback applies
    // ...
}

// src/common/utils/encrypt.go:82-89 (root cause, same as p8-011)
func ReversibleDecrypt(str, key string) (string, error) {
    if strings.HasPrefix(str, EncryptHeaderV1) {
        return decryptAES(strings.TrimPrefix(str, EncryptHeaderV1), key)
    }
    return decodeB64(str)  // no AES key needed for legacy records
}
```

## Reproduction Steps

1. Identify a Harbor instance upgraded from a pre-AES-encryption version
2. Query the `registry` table: `SELECT name, access_key, access_secret FROM registry WHERE access_secret NOT LIKE '<enc-v1>%' AND access_secret != ''`
3. For any returned records, base64-decode: `echo "<access_secret_value>" | base64 -d`
4. Observe plaintext registry password or API token
5. Use recovered credentials to authenticate to the external registry
6. Also query `config` table for PasswordType fields: compare `src/lib/config/metadata/metadatalist.go` for `PasswordType` items (e.g., `OIDCClientSecret`, LDAP bind DN password)
7. Recommended fix: Add a one-time migration script that re-encrypts all legacy base64-encoded records in the `registry` and `config` tables with AES-CFB encryption before next startup
