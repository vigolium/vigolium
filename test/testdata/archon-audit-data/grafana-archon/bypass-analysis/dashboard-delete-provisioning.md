# Bypass Analysis: Dashboard Delete Provisioning Protection

**Patch**: `7b366ebd0071f2a55b032468130fc23869e56c75`
**Component**: `pkg/registry/apis/dashboard/register.go` (validateDelete)
**Tag**: [undisclosed]
**Cluster ID**: dashboard-provisioning-protection

---

## Patch Summary

The commit fixes a fail-open bug in `validateDelete`. Before the patch, when `readResp.Error` was non-nil (including 403, 500, etc.), the code treated it identically to "not found" and returned nil (allowing deletion). The fix now only allows deletion on HTTP 404; all other in-band errors fail closed, blocking the delete.

The fix is **correct for the specific bug it addresses** (in-band error misclassification), but the surrounding function contains additional bypasses that undermine provisioning protection.

## Bypass Verdict: **bypassable**

---

## Evidence

### Bypass 1: GracePeriodSeconds=0 (CRITICAL)

**File**: `pkg/registry/apis/dashboard/register.go:334-337`

```go
// Skip validation for forced deletions (grace period = 0)
if deleteOptions.GracePeriodSeconds != nil && *deleteOptions.GracePeriodSeconds == 0 {
    return nil
}
```

`GracePeriodSeconds` is a standard Kubernetes `DeleteOptions` field. Any authenticated client with `dashboards:delete` permission can send a DELETE request to `/apis/dashboard.grafana.app/v1/namespaces/{ns}/dashboards/{uid}` with `{"gracePeriodSeconds": 0}` in the request body. This entirely skips the provisioning check.

The intent is for this to be an internal signal: the legacy `DashboardServiceImpl.deleteDashboardThroughK8s()` sets `GracePeriodSeconds=0` when `validateProvisionedDashboard=false` (used only by `DeleteProvisionedDashboard()`, which is the provisioning system's own delete path). However, there is no guard ensuring only internal callers can set this field. The K8s API server passes `DeleteOptions` directly from the HTTP request body into the admission webhook.

The storage-level check (`checkManagerPropertiesOnDelete` -> `enforceManagerProperties`) does NOT protect against this because it explicitly allows deletions of `ManagerKindClassicFP` resources without any identity check:

```go
case utils.ManagerKindPlugin, utils.ManagerKindClassicFP:
    // ?? what identity do we use for legacy internal requests?
    return nil // no error
```

This means provisioning protection for classic file-provisioned dashboards relies **solely** on the admission webhook in `validateDelete`, which is fully bypassed by setting `GracePeriodSeconds=0`.

**Exploitation**: `DELETE /apis/dashboard.grafana.app/v1/namespaces/default/dashboards/<uid>` with body `{"gracePeriodSeconds": 0}` sent by any user with dashboard delete permission.

### Bypass 2: isStandalone mode skip

**File**: `pkg/registry/apis/dashboard/register.go:343-346`

```go
// HACK: deletion validation currently doesn't work for the standalone case. So we currently skip it.
if b.isStandalone {
    return nil
}
```

When Grafana runs in standalone dashboard app mode (`isStandalone=true`), all provisioning delete validation is skipped entirely. This is explicitly marked as a HACK and represents a deployment-configuration-gated gap: any standalone deployment has zero provisioning protection on deletes.

Risk is limited because standalone mode is a specific deployment target, but it is a complete removal of the security control for that configuration.

### Bypass 3: DeleteCollection skip (Low Risk)

**File**: `pkg/registry/apis/dashboard/register.go:338-341`

```go
if a.GetName() == "" {
    return nil
}
```

When `GetName()` is empty (DeleteCollection requests), validation is skipped. However, `DeleteCollectionWorkers` is set to 0 in `pkg/storage/unified/apistore/restoptions.go:173`, which disables the DeleteCollection operation at the storage level. This bypass is **not currently exploitable** but would become exploitable if DeleteCollection were enabled in the future.

### Non-Issue: validateUpdate lacks provisioning check

The `validateUpdate` function does not check whether a dashboard is provisioned before allowing updates. However, this is mitigated by the storage-layer `enforceManagerProperties` which handles repo-managed resources (though it allows `ManagerKindClassicFP` through, meaning classic file-provisioned dashboards CAN be modified via the K8s API by any editor).

---

## Sibling Resource Analysis

### Folders (pkg/registry/apis/folders/)
Folder deletion validation in `validateOnDelete` does not have the same GracePeriodSeconds bypass pattern. Folder provisioning protection follows a different path.

### Alert Rules (pkg/services/ngalert/api/)
Alert rule provisioning protection is handled at the service layer (`api_ruler.go:150`) with a direct provenance check. It does not use the K8s admission webhook pattern and is not affected by this bypass class.

### Datasources (pkg/services/provisioning/datasources/)
Datasource provisioning protection is handled at the service layer. Not affected by this K8s-specific bypass.

---

## Recommendations

1. **Remove the GracePeriodSeconds=0 signal mechanism**. Instead, use a context value or a separate internal-only field to signal that provisioning validation should be skipped. The K8s API passes `DeleteOptions` from untrusted input, making it unsuitable as a trust boundary.

2. **Fix the storage-level enforceManagerProperties** for `ManagerKindClassicFP` to require a service identity or specific permission rather than unconditionally allowing all callers.

3. **Address the isStandalone gap** by implementing provisioning checks that work in standalone mode, or documenting the security tradeoff.
