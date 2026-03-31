Phase: 9
Sequence: 065
Slug: session-token-known-default-secret-key
Verdict: VALID
Rationale: The [security] secret_key default "SW2YcwTIb9zpOOhoPsMm" is used as a HMAC pepper for session token hashing and as the HMAC-SHA256 key for password reset time-limit codes; with the publicly known default, offline pre-computation against stolen token hashes is significantly accelerated, and password reset codes become forgeable for any attacker with read access to user records.
Severity-Original: MEDIUM
PoC-Status: executed (live)
Origin-Finding: security/findings-draft/p7-041-renderer-jwt-forgery-default-token.md
Origin-Pattern: AP-041

## Summary

The `[security] secret_key` configuration value (default `"SW2YcwTIb9zpOOhoPsMm"`) is used in two security-critical cryptographic operations:

**1. Session token hashing** (`auth_token.go:689-691`): User session tokens are stored in the DB as `SHA256(token + secretKey)`. The raw token is sent to the browser as a cookie. If `secretKey` is the publicly known default, an attacker who steals the `auth_token` table can pre-compute rainbow tables for the default pepper, dramatically reducing the cost of recovering raw token values from stolen hashes.

**2. Password reset / email verification codes** (`notifications/codes.go:44-50`): Time-limit codes are generated as `HMAC-SHA256(key=secretKey, msg=userID+email+login+passwordHash+rands+startStr+endStr)`. If `secretKey` is known and an attacker has read access to the `user` table (obtaining `UserID`, `Email`, `Login`, `Password`, `Rands`), they can forge a valid password reset code for any account without triggering the email flow. This allows account takeover without email access.

The advisor check in `apps/advisor/pkg/app/checks/configchecks/security_config_step.go` warns about the default `secret_key` at HIGH severity, but this check runs asynchronously and does not block startup.

## Location

- **Default value:** `conf/defaults.ini:387` -- `secret_key = SW2YcwTIb9zpOOhoPsMm` in `[security]`
- **Config read:** `pkg/setting/setting.go:1802` -- `cfg.SecretKey = valueAsString(security, "secret_key", "")`
- **Session hash:** `pkg/services/auth/authimpl/auth_token.go:689-691` -- `sha256.Sum256([]byte(token + secretKey))`
- **Session creation:** `pkg/services/auth/authimpl/auth_token.go:86` -- `generateAndHashToken(s.cfg.SecretKey)`
- **Session lookup:** `pkg/services/auth/authimpl/auth_token.go:145` -- `hashToken(s.cfg.SecretKey, unhashedToken)`
- **Email code HMAC:** `pkg/services/notifications/codes.go:45-50` -- `hmac.New(sha256.New, key)` where `key = []byte(secretKey)`
- **Email code generation:** `pkg/services/notifications/codes.go:107` -- `createTimeLimitCode(cfg.SecretKey, payload, ...)`
- **Email code validation:** `pkg/services/notifications/codes.go:74` -- `createTimeLimitCode(cfg.SecretKey, payload, ...)` compared against user-supplied code
- **Advisor warning:** `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:56` -- checks `secretKey == defaultSecretKey` but does not block operation

## Attacker Control

**For session token attack:** An attacker with read access to the `user_auth_token` table (via SQL injection, DB backup, or insider). The `auth_token` column contains `SHA256(token + "SW2YcwTIb9zpOOhoPsMm")`. With the known pepper, pre-computation is feasible using hardware accelerators.

**For password reset code forgery:** An attacker with read access to the `user` table (obtaining `ID`, `Email`, `Login`, `Password`, `Rands`). The attacker computes:
```
payload = userID + email + login + passwordHash + rands
code = HMAC-SHA256(key="SW2YcwTIb9zpOOhoPsMm", msg=payload+startStr+endStr)
```
and submits this code to the `/api/user/password/reset` endpoint, bypassing the email verification step.

## Trust Boundary Crossed

TB2 (Authentication Gate) for session token pre-computation. TB2 (Authentication Gate) for password reset code forgery — allows account takeover without email access or interaction.

## Impact

**Session tokens:** The known pepper reduces hash security. SHA256 without a secret pepper is equivalent to a fast hash for cracking purposes; with a known pepper, an attacker can pre-build tables keyed to this specific pepper. Token recovery from stolen DB hashes is accelerated vs. a truly secret/per-deployment pepper.

**Password reset codes:** An attacker with DB read access to the `user` table can forge valid time-limit codes for any user account, bypassing the email delivery step. This converts read-only DB access into full account takeover for all accounts, since:
1. The HMAC key (`secret_key`) is publicly known (default)
2. All HMAC inputs come from the `user` table (attacker already has read access)
3. The forged code is accepted by `/api/user/password/reset` without additional checks

The net result is that any attacker who achieves read access to both `user` and `user_auth_token` tables can take over any Grafana account. Under the default configuration, this requires no key material beyond the publicly known default.

## Evidence

1. `conf/defaults.ini:387`: `secret_key = SW2YcwTIb9zpOOhoPsMm` — publicly known default pepper/key
2. `pkg/services/auth/authimpl/auth_token.go:689-691`: `hashBytes := sha256.Sum256([]byte(token + secretKey)); return hex.EncodeToString(hashBytes[:])` — SHA256 with known pepper
3. `pkg/services/notifications/codes.go:45`: `key := []byte(secretKey); h := hmac.New(sha256.New, key)` — HMAC key is the known default
4. `pkg/services/notifications/codes.go:73`: `payload := strconv.FormatInt(user.ID, 10) + user.Email + user.Login + string(user.Password) + user.Rands` — all from `user` table
5. `pkg/services/notifications/codes.go:78`: `if hmac.Equal([]byte(code), []byte(expectedCode)) && minutes > 0` — pure code comparison, no additional auth
6. `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:16`: `defaultSecretKey = "SW2YcwTIb9zpOOhoPsMm"` — Grafana itself acknowledges this string as the known-bad default
7. No startup guard in `readSecuritySettings()` at `pkg/setting/setting.go:1800-1808` rejects or warns on empty/default secret_key

## Reproduction Steps

**Password reset code forgery (requires user table read access):**
1. Read `user` table row for target user: `ID`, `Email`, `Login`, `Password` (hashed), `Rands`
2. Choose `startStr` = current time in format `200601021504`, `minutes` = cfg.EmailCodeValidMinutes (default value from config, typically 120)
3. Compute `endStr = startStr + minutes`
4. Compute `payload = fmt.Sprintf("%d%s%s%s%s", userID, email, login, passwordHash, rands)`
5. Compute `code = HMAC-SHA256(key="SW2YcwTIb9zpOOhoPsMm", msg=payload+startStr+endStr)` encoded as hex
6. Submit `POST /api/user/password/reset` with the constructed code and new password
7. Observe successful password reset without email interaction
