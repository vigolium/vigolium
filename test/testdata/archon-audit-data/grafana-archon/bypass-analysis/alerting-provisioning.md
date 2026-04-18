# Bypass Analysis: Alerting Provisioning Protected Fields

- **Commit**: 329327952e9bc785fddfbd3b1f1e70d64aa42778
- **Component**: Alerting provisioning — ContactPointService
- **Type**: [undisclosed]
- **Cluster ID**: alerting-protected-fields-provisioning

## Patch Summary

The patch adds protected field authorization checks to the **provisioning API** path for updating contact points. Prior to this fix, the `ContactPointService.UpdateContactPoint` method did not verify whether the caller had the `ActionAlertingReceiversUpdateProtected` permission before allowing modifications to protected fields (e.g., webhook URLs, API endpoints).

**What was fixed:**
1. `UpdateContactPoint` now accepts a `user identity.Requester` parameter (previously it did not require one).
2. A new `checkProtectedFields` method compares existing vs incoming `EmbeddedContactPoint` to detect protected field changes using `models.HasIntegrationsDifferentProtectedFields`.
3. If protected fields differ and the user lacks `ActionAlertingReceiversUpdateProtected`, an authorization error is returned.
4. A new `ProtectedFieldsAuthz` interface is introduced and wired into `ContactPointService`.
5. The file-based provisioning path (`contact_point_provisioner.go`) now passes `provisionerUser` which is granted `ActionAlertingReceiversUpdateProtected`.

**Pre-patch vulnerability:**
A user with `ActionAlertingNotificationsWrite` (basic write permission) could modify protected fields (e.g., webhook destination URLs) on contact points via the provisioning API (`PUT /api/v1/provisioning/contact-points/{UID}`) without needing the `ActionAlertingReceiversUpdateProtected` permission. This could allow redirecting alert notifications to attacker-controlled endpoints.

## Bypass Verdict: **sound**

The fix is sound for its intended scope. No bypasses were identified in the patched code path.

## Evidence

### Entry Point Coverage

| Update Path | Protected Fields Check | Status |
|---|---|---|
| `ReceiverService.UpdateReceiver` (non-provisioning API) | Yes (line 477-486 in receiver_svc.go) — existed before this patch | Covered |
| `ContactPointService.UpdateContactPoint` (provisioning API) | Yes — **added by this patch** | Covered |
| `ReceiverTestingService.TestExisting` (test notification path) | Yes (line 114-125 in receiver_testing_svc.go) — existed before this patch | Covered |
| File provisioning (`contact_point_provisioner.go`) | Covered via `provisionerUser` which has `ActionAlertingReceiversUpdateProtected` | Covered |
| `ContactPointService.CreateContactPoint` | N/A — new resources have no existing protected fields to protect | N/A |

### Specific Observations

1. **Error swallowing in `HasUpdateProtected` is fail-closed**: Both the patched code and the existing `ReceiverService` use `canUpdateProtected, _ := ecp.authz.HasUpdateProtected(...)`. If the auth check errors, `canUpdateProtected` defaults to `false`, which triggers the detailed diff check. This is safe (fail-closed).

2. **SecureSettings handling is correct**: In the provisioning path, secret values are patched back into `Settings` (lines 281-287 of `contactpoints.go`) before the protected fields check runs. The `EmbeddedContactPointToIntegration` conversion correctly captures these values in `Settings` (not `SecureSettings`), so the diff will catch protected secret fields that are changed.

3. **Nil user is handled**: The `checkProtectedFields` method returns `ErrUserRequired` if `user == nil`, preventing bypass through missing caller identity.

4. **Receiver UID derivation uses existing name**: Authorization check uses `legacy_storage.NameToUid(existing.Name)`, preventing a bypass where a user renames a receiver to one they have more permissions on and then modifies protected fields.

5. **No bulk AM config update path exists for Grafana-managed receivers**: There is no `RoutePutAlertingConfig` equivalent that could bulk-replace contact point configurations and bypass the provisioning check. The alertmanager config store paths all go through `ReceiverService` which has its own checks.

### No Sibling Gaps Found

- All three code paths that can modify receiver/contact point state (ReceiverService, ContactPointService, ReceiverTestingService) now enforce protected field authorization.
- The K8s-style API for alerting notifications does not directly modify receivers; it routes through `ReceiverService`.

## Recommendation

No action needed. The patch correctly closes the provisioning API bypass for protected field modification. The fix is consistent with the pre-existing check in `ReceiverService.UpdateReceiver`.
