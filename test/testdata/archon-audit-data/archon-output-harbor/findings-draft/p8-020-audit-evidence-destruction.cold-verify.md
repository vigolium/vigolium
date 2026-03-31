# Cold Verification: p8-020 audit-evidence-destruction

## Verdict: CONFIRMED (severity downgraded from CRITICAL to MEDIUM)

## Reasoning

### Technical Claims -- All Verified

1. **Config API allows setting both values in one call**: Verified at `src/server/v2.0/handler/config.go:75-91`. The `PUT /api/v2.0/configurations` endpoint accepts a JSON body with both `audit_log_forward_endpoint` and `skip_audit_log_database` fields. Both are UserScope, editable config items (`metadatalist.go:192-193`).

2. **Minimal endpoint validation**: Verified at `src/controller/config/controller.go:149-169`. `verifySkipAuditLogCfg` only checks that the endpoint is non-empty when skip is true. The `updateLogEndpoint` function at lines 100-113 calls `CheckEndpointActive` which does a TCP syslog dial -- this confirms the endpoint is reachable but does not validate trustworthiness.

3. **Database audit trail silenced**: Verified at `src/pkg/auditext/manager.go:85-86`. When `config.SkipAuditLogDatabase(ctx)` returns true, the function returns `(0, nil)` without calling `m.dao.Create`.

4. **Self-concealing via async processing**: This is the most significant finding. The audit event processing chain is:
   - `log.Middleware` (`src/server/middleware/log/log.go:69`) calls `next.ServeHTTP` (handler updates config synchronously)
   - After handler returns, event is queued via `notification.AddEvent` (line 81)
   - `notification.Middleware` fires `event.BuildAndPublish` (line 34 of notification.go)
   - `BuildAndPublish` at `src/pkg/notifier/event/event.go:101-113` runs in a **goroutine** (`go func()`)
   - The goroutine eventually calls `auditext.Mgr.Create` which reads the **already-updated** config
   - Result: the config change's own audit event is dropped

### Severity Downgrade Rationale

The finding is technically accurate but CRITICAL severity is not warranted because:

- **Requires system admin privileges**: The `RequireSystemAccess` check at `config.go:76` restricts this to the highest privilege level. This is an insider threat scenario, not an external attack.
- **Designed feature being used as intended**: Audit log forwarding with database skip is a deliberate Harbor feature for SIEM integration. The "vulnerability" is a design gap (no immutable audit of config changes), not a code defect.
- **Significant precondition**: Compromised or malicious system admin is a substantial precondition that prevents HIGH/CRITICAL classification per the severity challenge framework.
- **External mitigations possible**: Network segmentation and egress filtering can prevent connection to arbitrary syslog endpoints.

### What Makes This a Real Issue (MEDIUM, not FALSE POSITIVE)

The self-concealing aspect is a genuine design weakness. Even for a trusted admin, security best practice requires that audit configuration changes themselves be recorded in an immutable, separate audit trail. The fact that the skip flag can suppress the audit record for its own activation is a real gap that should be addressed with:
- A separate, immutable log for audit configuration changes
- Or recording the config change BEFORE applying the new config values

## Files

- Finding draft: `/Users/tuan.v.tran/AuditSource/harbor/security/findings-draft/p8-020-audit-evidence-destruction.md`
- Full review: `/Users/tuan.v.tran/AuditSource/harbor/security/adversarial-reviews/audit-evidence-destruction-review.md`
