Phase: 10
Sequence: 054
Slug: renderer-token-no-startup-validation-when-jwt-enabled
Verdict: VALID
Rationale: When renderAuthJWT feature flag is enabled, Grafana initializes jwtRenderKeyProvider with cfg.RendererAuthToken (default "-") as the HMAC-SHA512 signing key without any startup validation that the key meets minimum strength requirements; unlike the [security] secret_key which has an advisor check, cfg.RendererAuthToken has no advisory or enforcement check anywhere in the codebase, meaning operators who enable the renderAuthJWT flag are given no warning that the default 1-byte signing key is in use.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-041-renderer-jwt-forgery-admin-takeover.md
Origin-Pattern: AP-041

## Summary

Grafana has two publicly known default secrets with distinct risk profiles:

1. `[security] secret_key = SW2YcwTIb9zpOOhoPsMm` — has an advisor check in `apps/advisor/pkg/app/checks/configchecks/security_config_step.go` that warns at HIGH severity when the default value is detected
2. `[rendering] renderer_token = -` — has NO advisory check, NO startup validation, NO minimum-length enforcement anywhere in the codebase

When an operator enables the `renderAuthJWT` feature flag (required for JWT-based renderer auth), Grafana silently initializes the JWT signing key as `[]byte("-")` — a 1-byte key — with zero indication that this is insecure. The `jwtRenderKeyProvider` is constructed at `rendering.go:114-118` with `authToken: []byte(cfg.RendererAuthToken)` and no length or entropy check.

This creates a dangerous asymmetry: the `secret_key` default is actively monitored by the advisor, but the equally dangerous (and simpler to exploit) `renderer_token` default has no detection mechanism. An operator who carefully follows Grafana's security hardening guide (changing `secret_key`) and then enables `renderAuthJWT` would have no indication that they introduced a critical authentication vulnerability via the default renderer token.

Furthermore, the advisor's security check (`security_config_step.go`) only examines 2 configuration keys (lines 46-62) and explicitly does not check `renderer_token` or any rendering-related settings. There is no corresponding `rendering_config_step.go` or equivalent.

This is a structural variant of the original finding: it shares the root cause (default 1-byte key) but represents a distinct gap in the detection and advisory layer, separate from the cryptographic weakness itself.

## Location

- **Primary**: `pkg/services/rendering/rendering.go:113-118` — `jwtRenderKeyProvider` initialized with `authToken: []byte(cfg.RendererAuthToken)` without length/entropy validation
- **Primary**: `apps/advisor/pkg/app/checks/configchecks/security_config_step.go` — advisor checks only `[security] secret_key`, no check for `[rendering] renderer_token`
- **Secondary**: `pkg/setting/setting.go:2070` — `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` — no startup warning when value is `-`
- **Secondary**: `pkg/services/featuremgmt/registry.go:181-186` — `renderAuthJWT` flag is `PublicPreview`, `Expression: "false"` — operator must explicitly enable it, but no documentation links to a security prerequisite about changing `renderer_token`

## Attacker Control

This finding does not represent a new attack vector beyond the original finding — the exploit is identical (forge JWT with `[]byte("-")` key). The distinct vulnerability is the **absence of detection**:

- Attacker can reliably assume that any Grafana instance with `renderAuthJWT=true` also has the default `renderer_token = "-"`, because there is no mechanism to prompt or enforce a change
- Unlike `secret_key` (where the advisor creates operational pressure to change the default), `renderer_token` has no such pressure
- Operators who audit their Grafana instance via the advisor will see a clean report regarding rendering configuration, even when the default JWT key is in use

## Trust Boundary Crossed

Configuration trust boundary: the operator's security model assumes that advisory checks cover all critical defaults. The absence of a `renderer_token` check means the advisor presents a false sense of security when `renderAuthJWT` is enabled with the default key.

## Impact

- Silent deployment of a critically weak JWT signing key when `renderAuthJWT` is enabled
- Operators have no automated mechanism to detect the `renderer_token = "-"` default when using JWT mode
- High probability that any `renderAuthJWT`-enabled deployment uses the default key (no operational pressure to change it)
- Scope: affects all deployments that enable `renderAuthJWT` without an explicit security-focused configuration review

## Evidence

1. `security_config_step.go:46-62`: Advisor checks for `admin_password` and `secret_key` only — no `renderer_token` check in the security step's switch statement
2. `rendering.go:113-118`: `jwtRenderKeyProvider{authToken: []byte(cfg.RendererAuthToken)}` — no `len(cfg.RendererAuthToken) < minLength` guard
3. `setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` — Go default is `-`, and conf/defaults.ini:1952 also sets `renderer_token = -` as the INI default
4. Compare with `setting.go:1802`: `cfg.SecretKey = valueAsString(security, "secret_key", "")` (Go default empty) — but `defaults.ini:387` sets `SW2YcwTIb9zpOOhoPsMm` AND the advisor flags this
5. No `rendering_config_step.go` or equivalent exists in `apps/advisor/pkg/app/checks/`

## Reproduction Steps

1. Enable `renderAuthJWT` feature flag in Grafana configuration
2. Do NOT change `renderer_token` from its default value `-`
3. Run Grafana advisor: `/api/advisor/checks` or check the Grafana UI's administration panel
4. Observe: advisor reports no security issues related to rendering configuration
5. Despite the advisor's clean report, the JWT signing key is `"-"` (1 byte)
6. Forge JWT and authenticate as Admin per the original finding's reproduction steps

**Remediation gap**: The fix requires:
- Adding a check in `security_config_step.go` (or a new `rendering_config_step.go`) that detects when `renderAuthJWT` is enabled AND `renderer_token == "-"`
- Adding minimum length validation (e.g., 32 bytes minimum) in `rendering.go` when the `jwtRenderKeyProvider` is initialized
- Updating the `renderAuthJWT` feature flag documentation to explicitly list "change renderer_token" as a required security prerequisite before enabling the flag
