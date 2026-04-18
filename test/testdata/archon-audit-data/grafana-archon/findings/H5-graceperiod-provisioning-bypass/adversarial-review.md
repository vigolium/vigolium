# Adversarial Review: graceperiod-provisioning-bypass

## Step 1: Restatement and Decomposition

**Restated claim**: The Grafana Dashboard K8s API has an admission webhook (`validateDelete`) that protects provisioned dashboards from being deleted via the API. However, any authenticated user with dashboard delete permission can bypass this protection by setting the `GracePeriodSeconds` field to 0 in the DELETE request body. This causes an early return from the validation function before the provisioning check is reached.

**Sub-claims**:

- **Sub-claim A**: An attacker (Editor-role user) controls the `GracePeriodSeconds` field in the HTTP DELETE request body. **SUPPORTED** -- `GracePeriodSeconds` is a standard `metav1.DeleteOptions` field that any API client can set.

- **Sub-claim B**: Setting `GracePeriodSeconds=0` causes the `validateDelete` function to return nil before reaching the provisioning check at line 370. **SUPPORTED** -- Code at lines 334-337 confirms unconditional early return.

- **Sub-claim C**: This bypasses a meaningful security control (provisioned dashboard immutability). **PARTIALLY SUPPORTED** -- The bypass is real but was intentionally designed. See analysis below.

## Step 2: Independent Code Path Trace

Entry point: `DashboardsAPIBuilder.Validate()` at `register.go:300`

1. `Validate()` dispatches to `validateDelete()` for `admission.Delete` operations on dashboard resources (line 307-308)
2. `validateDelete()` at line 327 receives the admission attributes
3. Line 328-332: Extracts `DeleteOptions` from operation options
4. **Line 334-337**: If `GracePeriodSeconds != nil && *GracePeriodSeconds == 0`, returns nil immediately (NO ERROR)
5. Lines 339-341: Skips if DeleteCollection (no name)
6. Lines 343-346: Skips if standalone mode
7. Lines 348-374: Actual provisioning check -- looks up dashboard, checks manager annotations, returns error if `ManagerKindClassicFP`

**Validation/sanitization on path**: NONE between the GracePeriodSeconds check and the return. No RBAC check on the GracePeriodSeconds value. No middleware filtering this field.

**Framework-level protections**: Standard K8s RBAC applies to the DELETE verb on dashboards resource, but there is no separate permission for "force delete" or "delete with grace period 0".

## Step 3: Protection Surface Search

| Layer | Protection | Blocks Attack? |
|-------|-----------|---------------|
| Language | Go type system -- `*int64` for GracePeriodSeconds | No -- attacker can set any int64 value |
| Framework | K8s RBAC on DELETE verb | No -- Editor role has dashboards:delete |
| Middleware | None specific to GracePeriodSeconds | No |
| Application | The GracePeriodSeconds=0 check IS the only relevant control | No -- it is the bypass itself |
| Documentation | No SECURITY.md or changelog discussing this as accepted risk | N/A |

**Key finding**: The test file (`register_test.go:136-145`) contains a test explicitly named "should not run the check for delete if grace period is set to 0" with `checkRan: false, expectedError: false`. This means:
- The bypass was **intentionally coded** in the original commit (5ed2a4c6244) that introduced provisioned dashboard deletion protection
- It is **tested behavior**, not an accidental oversight
- However, no internal system appears to use `GracePeriodSeconds=0` for legitimate purposes -- no callers were found in the provisioning system

## Step 4: Real-Environment Reproduction

**PoC-Status: theoretical**

Reproduction was not attempted because:
1. Setting up a full Grafana instance with K8s API mode and provisioned dashboards requires significant infrastructure
2. The code path is unambiguous and confirmed by existing unit tests in the repository

The unit test at `register_test.go:136-145` effectively serves as a reproduction -- it confirms the bypass works as claimed.

## Step 5: Prosecution and Defense Briefs

### Prosecution Brief

The vulnerability is genuine. The code at `register.go:334-337` provides an unconditional bypass of provisioned dashboard protection. Any user with `dashboards:delete` permission (Editor role) can delete provisioned dashboards by adding `gracePeriodSeconds: 0` to the DELETE request body. This crosses a trust boundary: provisioned dashboards are infrastructure-as-code artifacts meant to be immutable through the UI/API, manageable only through the provisioning pipeline. No internal system uses this bypass mechanism, meaning it serves no legitimate purpose. The bypass was introduced in commit 5ed2a4c6244 without apparent security review of the implications. No additional authorization check prevents an Editor from using this field.

### Defense Brief

The bypass was **intentionally designed** by the Grafana development team. Evidence:
1. The bypass was part of the original commit that introduced provisioned dashboard deletion protection (PR #98504)
2. A dedicated test validates the bypass behavior with a clear name: "should not run the check for delete if grace period is set to 0"
3. The code comment reads "Skip validation for forced deletions (grace period = 0)" -- showing deliberate intent

The design likely follows the Kubernetes pattern where `GracePeriodSeconds=0` with `--force` is an admin-level override for stuck resources. While the intent may be questionable from a security perspective, this is a **design decision** rather than an accidental vulnerability. The provisioned dashboard protection is an availability concern, not a confidentiality/integrity boundary. Provisioned dashboards are automatically re-created by the provisioning cycle, limiting the impact window.

Additionally, any user who can delete provisioned dashboards can also delete non-provisioned dashboards -- the provisioning protection is a guardrail against accidental deletion, not a security boundary.

## Step 6: Severity Challenge

Starting at MEDIUM:

**Downgrade signals**:
- This is an **intentional design decision** with dedicated tests, not an accidental bug
- Provisioned dashboard protection is primarily an **availability guardrail**, not a security boundary
- The provisioning system will automatically re-create deleted dashboards on the next cycle
- Requires authentication and `dashboards:delete` permission (not unauthenticated)
- The same user could delete any non-provisioned dashboard anyway
- No confidentiality or integrity impact -- only temporary availability disruption

**Upgrade signals**:
- Remotely triggerable via HTTP API
- Crosses an implicit trust boundary (Editor vs admin-provisioned configuration)

**Challenged severity**: LOW -- This is a design weakness/guardrail bypass, not a traditional vulnerability. The protection being bypassed is an availability guardrail, not a security control.

## Step 7: Verdict

```
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The GracePeriodSeconds=0 bypass is intentional, tested behavior introduced in the same commit as the provisioned dashboard protection (5ed2a4c6244), with a dedicated test confirming the design. This is a deliberate design decision, not a vulnerability. The provisioning protection is an availability guardrail against accidental deletion, not a security boundary.
Severity-Final: LOW
PoC-Status: theoretical
```

The finding conflates an intentional design decision with a security vulnerability. While the bypass could be considered a design weakness (no internal system actually uses GracePeriodSeconds=0), the Grafana team explicitly coded and tested this behavior, making it an accepted design choice rather than an exploitable vulnerability.
