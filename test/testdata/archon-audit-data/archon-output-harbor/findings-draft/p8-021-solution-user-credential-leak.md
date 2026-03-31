Phase: 8
Sequence: 021
Slug: solution-user-credential-leak
Verdict: FALSE POSITIVE (adversarial)
Rationale: Solution-user auth bypasses ConvertForGet password stripping, leaking all system secrets (LDAP, OIDC, PostgreSQL, admin passwords) in a single API call; defense exists via solution-user secret isolation but container/Kubernetes compromise provides access.
Severity-Original: HIGH
PoC-Status: blocked
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: ConfigurationsResponse swagger model (api/v2.0/swagger.yaml:8981-9161) contains no password fields; json.Unmarshal into the generated typed struct silently drops all PasswordType config values before they reach the API response.
Severity-Final: N/A

## Summary

The `GET /api/v2.0/configurations` endpoint has a solution-user code path that returns all configuration values including PasswordType fields (LDAP bind password, OIDC client secret, PostgreSQL password, admin initial password) without redaction. The solution-user path calls `AllConfigs()` directly instead of `UserConfigs()` which applies `ConvertForGet()` to strip sensitive fields.

## Location

- `src/server/v2.0/handler/config.go:41-59` -- Solution-user branch calls `c.controller.AllConfigs(ctx)` bypassing password redaction
- `src/controller/config/controller.go:224-253` -- `ConvertForGet` strips PasswordType fields but is NOT called for solution-user path
- `src/lib/config/metadata/metadatalist.go:70,93,106,141` -- PasswordType fields that should be redacted

## Attacker Control

- Attacker needs the solution-user shared secret (Harbor-Secret header)
- Secret is stored in container environment variables and Kubernetes secrets
- Container escape, Kubernetes RBAC misconfiguration, or env var leakage provides access

## Trust Boundary Crossed

- Internal service authentication (solution-user) to full credential exfiltration
- TB-5: Core API internal interface exposed to broader attack surface

## Impact

- Single API call leaks: `ldap_search_password`, `oidc_client_secret`, `postgresql_password`, `admin_initial_password`, `email_password`, `trace_jaeger_password`
- Enables lateral movement to LDAP server, OIDC provider, PostgreSQL database
- Full system compromise from a single credential theft

## Evidence

- Deep Probe PH-05/PH-C07: Validated end-to-end
- config.go:43-44: `sec.IsSolutionUser()` true -> `AllConfigs()` (no stripping)
- config.go:64: Normal admin path -> `UserConfigs()` -> `ConvertForGet()` (strips passwords)
- Bypass analysis bypass-85e756486 confirms this pattern

## Reproduction Steps

1. Obtain the solution-user shared secret (from container env, Kubernetes secret, or config file)
2. Send: `GET /api/v2.0/configurations` with header `Authorization: Harbor-Secret <secret>`
3. Verify response contains plaintext values for all PasswordType fields
4. Contrast with system-admin GET which correctly redacts these fields
