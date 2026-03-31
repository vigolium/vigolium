# Variant Analysis for p7-041 (renderer-jwt-forgery-default-token / AP-041)

**Origin finding:** security/findings-draft/p7-041-renderer-jwt-forgery-default-token.md
**Pattern:** AP-041 — Default Cryptographic Key in Auth Token
**Search date:** 2026-03-20
**Variant analyst:** Phase 9 agent
**NNN range assigned:** p7-063 to p7-065

---

## Search Strategy Applied

### 1. Registry-Driven Grep (AP-041 detection signature)
Searched for:
- `RendererAuthToken.*valueAsString.*"-"` — found only `setting.go:2070` (origin finding)
- `SW2YcwTIb9zpOOhoPsMm` — found in `conf/defaults.ini:387`, `conf/defaults.ini:2301`, and `apps/advisor/pkg/app/checks/configchecks/security_config_step.go:16`

### 2. Flow Shape Search: Same Default Key, Different Cryptographic Operations
Searched for all uses of `cfg.RendererAuthToken`, `cfg.SecretKey`, and `cfg.IPRangeACSecretKey` across the codebase to identify structurally similar default-key usages.

### 3. JWT and HMAC Operations Survey
Searched for all `jwt.SignedString`, `jwt.ParseWithClaims`, `hmac.New`, and `sha256.Sum256` usages to find other signing operations using potentially weak/default keys.

### 4. Phase 7 Addendum Targets
Chamber 3 addendum mentioned `RenderAuthJWT` with default token `"-"` (the origin finding). No additional default-key surfaces were specifically called out.

### 5. Chamber Variant Candidates
No pre-identified candidates in `security/chamber-workspace/*/variant-candidates/`.

### 6. CodeQL Artifacts
`sinks.json` SINK-004 references `authn/clients/render.go` as a SQL taint source. `entry-points.json` contains renderer-related routes. No additional default-key flow shapes identified from these artifacts.

---

## Candidate Evaluation

### Candidate A: HTTP Mode Default `renderer_token` Sent as `X-Auth-Token`

**File:** `pkg/services/rendering/http_mode.go:148`
**Pattern match:** Same root cause (default `renderer_token = "-"` from `setting.go:2070`), different attack surface (outbound auth to renderer vs. inbound JWT auth from attacker)

**Root cause confirmed:** `req.Header.Set(authTokenHeader, rs.Cfg.RendererAuthToken)` — the same `RendererAuthToken` value (default `"-"`) that is the JWT signing key in JWT mode is also the bearer token sent to the external renderer service in HTTP mode. The renderer validates this header as the sole access control on its HTTP interface.

**Attacker control confirmed:** Any attacker who can reach the renderer's HTTP port directly can present `X-Auth-Token: -` to authenticate to the renderer without involving Grafana.

**No blocking protection:** The renderer validates the header value against its own configuration of `renderer_token`. In the default configuration both sides use `"-"`, meaning the renderer accepts the known default from any caller.

**Distinct from origin finding:** The origin (p7-041) is an *inbound* attack on Grafana — an attacker forges a JWT to bypass Grafana's auth. This variant is an attack on the *renderer service* — an attacker bypasses the renderer's own access control. Different trust boundary crossed (TB6 renderer boundary vs. TB2 authentication gate).

**Verdict:** VALID — MEDIUM severity (requires reaching renderer HTTP port; no direct Grafana auth bypass but defeats renderer access control completely)

**Output:** `security/findings-draft/p7-063-renderer-http-mode-default-auth-token.md`

---

### Candidate B: Secrets Manager Envelope Encryption Default Key

**File:** `conf/defaults.ini:2301` and `pkg/registry/apis/secret/encryption/kmsproviders/kmsproviders.go:30`
**Pattern match:** Same AP-041 pattern (publicly known default value used as cryptographic key), different crypto operation (AES-256-GCM envelope encryption of datasource credentials instead of HMAC-HS512 JWT signing)

**Root cause confirmed:** `conf/defaults.ini:2301` sets `[secrets_manager.encryption.secret_key.v1] secret_key = SW2YcwTIb9zpOOhoPsMm`. This value is read by `ProvideOSSKMSProviders()` and passed to `newSecretKeyProvider()`, which uses it as the password for `pbkdf2.Key(SHA256, password, salt, 10000, 32)` to derive AES-256-GCM encryption keys for all stored secrets.

**Attacker control confirmed:** An attacker with database read access (e.g., from SQL injection, backup theft) can extract encrypted blobs from the datasource table and decrypt them offline using the publicly known key. The advisor check (`security_config_step.go:16`) confirms Grafana itself treats this as a known-bad default, but only warns — no startup guard prevents operation with the default key.

**No blocking protection:** No validation in `kmsproviders.go` checks whether the key matches the known default. The advisor check is advisory only, asynchronous, and only covers `[security] secret_key` — not the secrets_manager section key.

**Verdict:** VALID — HIGH severity (requires DB read access as precondition, but completely nullifies at-rest encryption for all datasource credentials and secrets)

**Output:** `security/findings-draft/p7-064-secrets-manager-default-encryption-key.md`

---

### Candidate C: `[security] secret_key` Default Used for Session Tokens and Password Reset Codes

**File:** `pkg/services/auth/authimpl/auth_token.go:689-691` and `pkg/services/notifications/codes.go:44-50`
**Pattern match:** Same AP-041 pattern (publicly known default `"SW2YcwTIb9zpOOhoPsMm"` used as HMAC key), different operations (SHA256 session token hashing and HMAC-SHA256 password reset codes)

**Root cause confirmed (session tokens):** `hashToken()` computes `sha256.Sum256([]byte(token + secretKey))`. With known `secretKey`, rainbow tables can be pre-computed against this pepper, accelerating recovery of raw tokens from stolen `auth_token` table rows.

**Root cause confirmed (password reset codes):** `createTimeLimitCode()` uses `hmac.New(sha256.New, []byte(secretKey))` with `secretKey = "SW2YcwTIb9zpOOhoPsMm"`. The HMAC input is constructed entirely from fields in the `user` table (`UserID`, `Email`, `Login`, `Password`, `Rands`). An attacker with read access to the `user` table can compute a valid reset code for any account without triggering the email flow.

**Attacker control confirmed:** An attacker with read access to the `user` table (same precondition as Candidate B — DB read access). All HMAC inputs are available from that table.

**No blocking protection:** No startup validation. Advisor check only covers the config value name, not how it is used cryptographically. The `readSecuritySettings()` function sets `SecretKey` from config with no strength check.

**Verdict:** VALID — MEDIUM severity (requires DB read access; password reset code forgery enables account takeover for all user accounts without email delivery)

**Output:** `security/findings-draft/p7-065-session-token-known-default-secret-key.md`

---

### Candidate D: OAuth State HMAC with Default `secret_key`

**File:** `pkg/services/authn/clients/oauth.go:372-374`
**Pattern match:** `hashOAuthState` uses `sha256.Sum256([]byte(state + secret + seed))` where `secret = cfg.SecretKey`

**Evaluation:** The OAuth state is randomly generated per login (`genOAuthState` uses `crypto/rand`). The state value is sent to the client in the redirect URL AND the hash is stored in a same-site cookie. An attacker needs the random state AND the cookie to forge the CSRF check. Even with the known `secretKey`, an attacker cannot forge the state without the random state value, which is transient. This is not exploitable with just the known default key alone.

**Verdict:** DROPPED — not a standalone vulnerability given the random state per-flow prevents forgery without the transient state value.

---

### Candidate E: `IPRangeACSecretKey` Default Empty String

**File:** `pkg/setting/setting.go:2223-2225` and `pkg/services/pluginsintegration/clientmiddleware/grafana_request_id_header_middleware.go:93`
**Pattern match:** HMAC-SHA256 signing key `IPRangeACSecretKey` defaults to `""` (empty string)

**Evaluation:** The `IPRangeAC` feature is `enabled = false` by default. The setting at line 2224-2225 explicitly logs an error if the feature is enabled with an empty key. The signed header is sent TO plugins, not validated by Grafana. The attacker would need to impersonate Grafana to a plugin, which requires network-level access to the plugin gRPC/HTTP channel. This is a much higher bar than the other variants, and the feature is explicitly off by default with an error log if misconfigured.

**Verdict:** DROPPED — disabled by default, explicit error log when empty, and the attack requires plugin-channel-level network access. Does not meet minimum MEDIUM bar as a standalone finding.

---

## Summary Table

| ID | Slug | Severity | Root Cause | Precondition |
|----|------|----------|-----------|--------------|
| p7-063 | renderer-http-mode-default-auth-token | MEDIUM | `renderer_token = "-"` sent as X-Auth-Token to renderer | Network access to renderer HTTP port |
| p7-064 | secrets-manager-default-encryption-key | HIGH | `secret_key = SW2YcwTIb9zpOOhoPsMm` as AES-256-GCM encryption key for all secrets | Database read access |
| p7-065 | session-token-known-default-secret-key | MEDIUM | `secret_key = SW2YcwTIb9zpOOhoPsMm` as HMAC key for password reset codes | Database read access to `user` table |

**Total confirmed variants: 3**

---

## Registry Updates

AP-041 `confirmed_instances` updated in `security/attack-pattern-registry.json` to include:
- p7-063 at `pkg/services/rendering/http_mode.go:148`
- p7-064 at `conf/defaults.ini:2301`
- p7-065 at `pkg/services/auth/authimpl/auth_token.go:689-691`

The pattern description was broadened from single-char `"-"` to encompass the publicly known 20-char `"SW2YcwTIb9zpOOhoPsMm"` as well, since both share the same root cause category (default known cryptographic key material).
