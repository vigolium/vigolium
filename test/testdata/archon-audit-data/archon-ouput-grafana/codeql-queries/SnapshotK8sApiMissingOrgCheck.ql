/**
 * @name Snapshot K8s API delete-by-key missing organization isolation check
 * @description The K8s API snapshot handler calls DeleteWithKey without verifying
 *              the snapshot belongs to the caller's organization. The legacy REST API
 *              correctly compares OrgID before deletion (CVE-2024-1313 fix), but the
 *              K8s API path at pkg/registry/apis/dashboard/snapshot/routes.go bypasses
 *              this check. Any authenticated user with ActionSnapshotsDelete permission
 *              can delete snapshots belonging to other organizations.
 * @kind problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @id grafana/snapshot-k8s-missing-org-check
 * @tags security
 *       authorization
 *       multi-tenant
 *       cve-2024-1313
 */

import go

/**
 * Finds DeleteWithKey calls in the snapshot routes package.
 */
from CallExpr deleteCall, Function deleteWithKey
where
  deleteWithKey.getName() = "DeleteWithKey" and
  deleteCall.getTarget() = deleteWithKey and
  deleteCall.getFile().getPackageName() = "snapshot"
select deleteCall, "DeleteWithKey called without verifying snapshot.OrgID matches requester's org; cross-org snapshot deletion possible (K8s API path missing CVE-2024-1313 fix)."
