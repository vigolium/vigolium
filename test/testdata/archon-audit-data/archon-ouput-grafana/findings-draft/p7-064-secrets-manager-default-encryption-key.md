Phase: 9
Sequence: 064
Slug: secrets-manager-default-encryption-key
Verdict: VALID
Rationale: The secrets manager's envelope encryption key defaults to the publicly known value "SW2YcwTIb9zpOOhoPsMm" (same string as [security] secret_key), meaning all datasource credentials and secrets encrypted at rest with this default can be decrypted by anyone who reads the database and knows the publicly documented default, completely nullifying at-rest encryption.
Severity-Original: HIGH
PoC-Status: executed (live)
Origin-Finding: security/findings-draft/p7-041-renderer-jwt-forgery-default-token.md
Origin-Pattern: AP-041

## Summary

The Grafana secrets manager uses AES-256-GCM envelope encryption (via PBKDF2 key derivation) to protect datasource credentials, alertmanager configurations, and other secrets stored in the database. The encryption key for the default `secret_key.v1` provider is configured in `[secrets_manager.encryption.secret_key.v1]` with the key `secret_key`. This defaults to `"SW2YcwTIb9zpOOhoPsMm"` in `conf/defaults.ini:2301`.

This is the same publicly known value as `[security] secret_key`. Any operator who has not changed this value (a common configuration omission since the advisor check only warns—it does not block startup) is using a publicly documented encryption key. An attacker who obtains a copy of the Grafana database (via SQL injection, backup theft, or insider access) can decrypt all protected secrets by applying the known key through the same AES-GCM + PBKDF2 derivation, completely defeating at-rest encryption.

The `advisor` app does check for the default value (see `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:56`) but only for the `[security] secret_key`. There is no equivalent startup guard or validation that prevents Grafana from starting with the default encryption key.

## Location

- **Default value in defaults.ini:** `conf/defaults.ini:2301` -- `secret_key = SW2YcwTIb9zpOOhoPsMm` under `[secrets_manager.encryption.secret_key.v1]`
- **Also default in [security] section:** `conf/defaults.ini:387` -- `secret_key = SW2YcwTIb9zpOOhoPsMm`
- **KMS provider setup:** `pkg/registry/apis/secret/encryption/kmsproviders/kmsproviders.go:30` -- reads `secretKey := properties[SecretKeyKey]` from config
- **Provider registration:** `pkg/registry/apis/secret/encryption/kmsproviders/kmsproviders.go:32` -- `newSecretKeyProvider(secretKey, cipher)` — this key is the sole encryption secret
- **Encryption implementation:** `pkg/registry/apis/secret/encryption/cipher/provider/cipher_aesgcm.go:41` -- `key, err := aes256CipherKey(secret, salt)` where `secret` is the config value
- **Key derivation:** `pkg/registry/apis/secret/encryption/cipher/provider/aes256.go:13` -- `pbkdf2.Key(sha256.New, password, salt, 10000, 32)`
- **Advisor check (incomplete):** `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:56` -- only checks `[security] secret_key`, not the secrets_manager section

## Attacker Control

An attacker with read access to the Grafana database (by any means: SQL injection, DB backup theft, cloud storage misconfiguration, insider threat). Database contents include AES-GCM encrypted blobs for datasource credentials (passwords, API keys, private keys). With the known default key, the attacker can:
1. Extract ciphertext from the database
2. Apply the same PBKDF2 derivation: `pbkdf2(SHA256, "SW2YcwTIb9zpOOhoPsMm", salt, 10000, 32)`
3. Decrypt AES-GCM ciphertext using the derived key

No brute force is needed — the key is deterministic and publicly known from the open-source defaults.ini.

## Trust Boundary Crossed

TB10 (Database Boundary). The encryption is designed as a defense-in-depth layer protecting secrets from attackers who gain database read access. With a publicly known encryption key, this boundary provides no protection: database access directly equals plaintext credential access.

## Impact

All datasource credentials stored by Grafana instances using the default encryption key are recoverable in plaintext from a database dump:
- Database passwords, TLS private keys, API tokens for Prometheus, Loki, InfluxDB, PostgreSQL, CloudWatch, etc.
- External alertmanager credentials
- Any value stored via the secrets manager API

This compounds the impact of any database exfiltration attack by also exposing all connected system credentials. The advisor warning (HIGH severity) exists but does not prevent startup, and many operators may miss or ignore it.

## Evidence

1. `conf/defaults.ini:2301`: `secret_key = SW2YcwTIb9zpOOhoPsMm` under `[secrets_manager.encryption.secret_key.v1]` — publicly known default encryption key
2. `conf/defaults.ini:387`: Same value `SW2YcwTIb9zpOOhoPsMm` for `[security] secret_key` — single value serves both functions
3. `pkg/registry/apis/secret/encryption/kmsproviders/kmsproviders.go:30-32`: Key read directly from config and passed to `newSecretKeyProvider()` with no validation of key strength or detection of default value
4. `pkg/registry/apis/secret/encryption/cipher/provider/aes256.go:13`: `pbkdf2.Key(sha256.New, password, salt, 10000, 32)` — deterministic derivation from known password
5. `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:16,56`: `defaultSecretKey = "SW2YcwTIb9zpOOhoPsMm"` — Grafana's own code acknowledges this is the known default value to warn about, but only for `[security] secret_key`, not the encryption key
6. No startup guard in `pkg/registry/apis/secret/encryption/kmsproviders/kmsproviders.go` rejects or warns on the default key value

## Reproduction Steps

1. Install Grafana without changing the default `secret_key` values
2. Configure a datasource with credentials (e.g., a PostgreSQL password)
3. Obtain the raw `secure_json_data` blob from the `data_source` table in the Grafana DB
4. Apply PBKDF2 derivation: `pbkdf2(SHA256, "SW2YcwTIb9zpOOhoPsMm", <first 8 bytes of blob as salt>, 10000, 32)` to obtain the AES-256 key
5. Apply AES-GCM decryption using the derived key and nonce from the blob
6. Observe plaintext datasource credential
