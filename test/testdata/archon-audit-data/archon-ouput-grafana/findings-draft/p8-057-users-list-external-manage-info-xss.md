Phase: 10
Sequence: 057
Slug: users-list-external-manage-info-xss
Verdict: FALSE_POSITIVE
Rationale: The externalUserMngInfo value originates from Grafana's own server-side configuration file (grafana.ini [users] external_manage_info), not from an external attacker-controlled source; only an operator with filesystem access to grafana.ini can set this value, making this a non-exploitable self-XSS from an already-privileged configuration context.
Severity-Original: N/A
PoC-Status: N/A
Origin-Finding: security/findings-draft/p8-044-plugin-readme-xss-no-sanitization.md
Origin-Pattern: AP-044

## Summary

`UsersListPage.tsx:114` renders `externalUserMngInfoHtml` (derived from `config.externalUserMngInfo`) via `dangerouslySetInnerHTML`. The `externalUserMngInfo` value flows from `conf/defaults.ini:584` (`external_manage_info =`) through `pkg/setting/setting.go:2005` to the frontend settings API. This is a Grafana administrator configuration value that can only be modified by editing `grafana.ini` on the server, which requires OS-level access to the Grafana host. There is no attacker-controlled path to this value from the network; it is not fetched from external services, user input, or plugins.

## Location

- `public/app/features/users/UsersListPage.tsx:67`: `renderMarkdown(config.externalUserMngInfo)`
- `public/app/features/users/UsersListPage.tsx:114`: `dangerouslySetInnerHTML={{ __html: externalUserMngInfoHtml }}`
- `pkg/api/frontendsettings.go:244`: Value sourced from `hs.Cfg.ExternalUserMngInfo`
- `conf/defaults.ini:584`: `external_manage_info =` (empty by default)

## Attacker Control

None. The `external_manage_info` configuration key is a server-side operator setting in `grafana.ini`. An attacker who can modify `grafana.ini` has already achieved OS-level access and full compromise.

## Trust Boundary Crossed

None from network perspective. Configuration file to rendered HTML is not a trust boundary crossing — both are under operator control.

## Impact

N/A — no exploitable attack path.

## Evidence

1. `setting.go:2005`: `cfg.ExternalUserMngInfo = valueAsString(users, "external_manage_info", "")` -- read from .ini file
2. `conf/defaults.ini:584`: `external_manage_info =` -- empty by default, requires operator configuration
3. No API endpoint allows setting this value without direct config file access

## Reproduction Steps

N/A — not exploitable via network.
