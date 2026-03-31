# Bypass Analysis: 2e8c4d4de — Audit Log Payload Removal (Config Event)

**Advisory ID**: undisclosed (silent fix)  
**Cluster ID**: audit-payload-disclosure  
**Commit**: `2e8c4d4de` (cherry-pick of `85e756486`)  
**Author**: stonezdj  
**Date**: 2026-03-04  
**Tag**: [undisclosed]

---

## Patch Summary

### What Was Fixed

The commit removes two forms of sensitive data from the `update_configuration` audit log entry:

1. **`e.Payload` field** — was set to a redacted copy of the full HTTP request body sent to `PUT /api/v2.0/configurations`, with only `ldap_password` and `oidc_client_secret` masked via `Redact()`.
2. **`e.OperationDescription` field** — was set to `"update configuration: <first 950 bytes of request body>"`, exposing most of the configuration payload verbatim.

After the patch both fields are neutralized:
- `e.Payload` assignment is removed entirely.
- `e.OperationDescription` is now the static string `"update configuration"`.

The helper `Redact()` function in `src/pkg/auditext/event/utils.go` and its test file are deleted, as they are no longer referenced.

### Cherry-Pick Confirmation

Commit `2e8c4d4de` is a confirmed cherry-pick of `85e756486`. The code diffs for `config.go` and `config_test.go` are byte-for-byte identical. The cherry-pick commit additionally includes three unrelated changes (Makefile Trivy version bump, portal pagination test fix, security hub test sort fix) that were bundled into the cherry-pick branch.

---

## Pre-Patch Vulnerability (Reconstructed)

**Bug class**: Sensitive data exposure via audit logging.

Before the patch, every successful `PUT /api/v2.0/configurations` request wrote the following to the `audit_log_ext` database table:

- **`payload` column (TEXT)**: The entire request body as JSON with only two keys masked — `ldap_password` and `oidc_client_secret`. All other secrets in the configuration payload were stored in cleartext.
- **`op_desc` column (VARCHAR 1024)**: The first 950 bytes of the raw request body appended to the static prefix `"update configuration: "`, with no redaction at all.

This means credentials such as `ldap_search_password` (constant key `"ldap_search_password"`) were stored in the audit log in **plain text** via `op_desc`, since the `SensitiveAttributes` list in the original resolver only contained `"ldap_password"` (an incorrect key that does not match the actual config field name). The `Redact()` function would therefore silently skip the LDAP search password while appearing to redact it.

The `payload` column is mapped with ORM tag `orm:"-"` in the Go model (meaning beego ORM ignores it for standard SELECT/INSERT), but the database schema defines the column as `payload TEXT NULL`, leaving open the question of whether it was written via raw SQL elsewhere or was simply dead code that accumulated data at the application layer only.

Exposed credentials when using LDAP authentication:
- `ldap_search_password` — written verbatim in both `payload` (via Redact miss) and `op_desc`.
- `admin_initial_password`, `trace_jaeger_password` — written verbatim in `op_desc` (950-byte window).

---

## Bypass Verdict: BYPASSABLE (Partial)

The fix is **sound for the specific `/api/v2.0/configurations` endpoint** after the patch. However, multiple residual paths remain that expose sensitive data via audit logs.

---

## Evidence

### 1. `SensitiveAttributes` Field Is a Dead Code Stub in `basic.go` and `user/user.go`

**File**: `src/pkg/auditext/event/basic.go` (line 45–46)  
**File**: `src/pkg/auditext/event/user/user.go` (line 39)

The `Resolver` struct in `basic.go` retains the `SensitiveAttributes []string` field, and `user.go` still initializes it with `[]string{"password"}`. The `Redact()` function that consumed this field was deleted in this commit. The field is now **declared but never used** — no call site in the current codebase invokes redaction on user event payloads.

Consequence: When a user's password is changed via `PUT /api/v2.0/users/{id}/password`, the `userEventResolver.Resolve()` calls `basic.Resolver.Resolve()`, which sets `OperationDescription` to `"update user with name: <username>, change user password"`. This does not include the raw password, so there is no active regression here. However, the dead `SensitiveAttributes` field creates misleading security documentation implying redaction is occurring when it is not.

### 2. Audit Log Forwarding Path Emits `OperationDescription` to External Endpoint

**File**: `src/pkg/auditext/manager.go` (lines 80–83)

```go
if len(config.AuditLogForwardEndpoint(ctx)) > 0 {
    auditV1.LogMgr.DefaultLogger(ctx).WithField("operator", audit.Username).
        WithField("time", audit.OpTime).WithField("resourceType", audit.ResourceType).
        Infof("action:%s, resource:%s, operation_description:%s", audit.Operation, audit.Resource, audit.OperationDescription)
}
```

When `AUDIT_LOG_FORWARD_ENDPOINT` is configured, every audit log entry is forwarded to an external syslog endpoint including the full `OperationDescription`. Post-patch this is safe for configuration events (the description is now static), but the forwarding path itself performs **no filtering or sanitization** before transmission. Any future regression in `OperationDescription` construction will silently forward sensitive data to the external collector.

### 3. `payload` Column Still Exists in Database Schema

**File**: `make/migrations/postgresql/0160_2.13.0_schema.up.sql`

The `audit_log_ext` table retains the `payload TEXT NULL` column. The Go ORM model marks this field with `orm:"-"`, which prevents beego ORM from reading or writing it. However:

- Data written to `payload` by any pre-patch version remains in the database and is never purged by the existing `Purge()` logic (which operates on `op_time` only).
- The `convertToModelAuditLogExt()` function that converts DB records to API responses does not include the `payload` field in its output, so historical payload data is not exposed via the current API. However, direct database access (e.g., backup restores, DBA queries, or raw SQL tools) will expose this historical data.

### 4. Original Redaction Was Incomplete — `ldap_password` Key Mismatch

This is a retroactive finding about the pre-patch state, confirming the severity of the original vulnerability.

The pre-patch `SensitiveAttributes` list was `["ldap_password", "oidc_client_secret"]`. The actual constant for the LDAP search password in Harbor's codebase is:

```go
// src/common/const.go line 72
LDAPSearchPwd = "ldap_search_password"
```

The key `"ldap_password"` does not match any config field. The `Redact()` function would therefore silently skip the LDAP search password even when the redaction path was active (for `e.Payload`). Combined with the fact that `op_desc` was populated from the **unredacted** `ce.RequestPayload`, the LDAP search password was stored in plaintext in both columns.

### 5. No Resolver Exists for Robot Account Secret Generation

**File**: `src/controller/event/topic.go` (lines 410–421, 437–448)

`create_robot` and `delete_robot` audit events are handled via `CreateRobotEvent` and `DeleteRobotEvent`, not via the `commonevent.Metadata` + resolver pipeline. These events set `OperationDescription` to `"create robot: <name>"` or `"delete robot: <name>"` only — the robot secret is not logged. This entry point is clean with respect to the fix.

### 6. Login Event Reads `RequestPayload` But Only Extracts Username

**File**: `src/pkg/auditext/event/login/login.go` (lines 64–75)

The login resolver reads `ce.RequestPayload` to extract the username via regex `principal=(.*?)&password`. The password portion is captured in the regex match group but discarded (only `match[1]` is used). The raw `RequestPayload` (which contains `principal=user&password=secret`) is never written to any audit log field. This entry point is clean.

---

## Residual Risk Summary

| Risk | Severity | Status |
|---|---|---|
| Historical `payload` column data in DB from pre-patch | Medium | Not mitigated (no schema cleanup) |
| `SensitiveAttributes` dead code in `basic.go`/`user.go` creates false redaction assurance | Low | Not mitigated |
| Audit log forward endpoint emits `operation_description` without sanitization | Low | Not mitigated (future regression risk) |
| Pre-patch `ldap_search_password` stored plaintext due to wrong key name | High | Mitigated by removing payload entirely |

---

## Recommendation

1. Issue a database migration to `TRUNCATE` or `NULL OUT` the `payload` column in `audit_log_ext` for all existing rows to eliminate historical exposure.
2. Remove the `SensitiveAttributes` field from `basic.Resolver` and from `user/user.go` to eliminate dead code that implies security guarantees.
3. Consider adding a sanitization wrapper around the audit log forwarding path in `manager.go` so that any future `OperationDescription` regressions are contained.
