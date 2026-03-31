/**
 * @name Cloud migration CancelSnapshot missing orgID parameter
 * @description CancelSnapshot(ctx, sessionUid, snapshotUid) has no orgID parameter.
 *              The resulting UpdateSnapshot SQL UPDATE uses WHERE session_uid=? AND uid=?
 *              without an org_id constraint. An admin in any organization can cancel
 *              snapshots belonging to other organizations by supplying their session_uid
 *              and snapshot_uid. This mirrors the cross-org bypass in CVE-2024-9476.
 * @kind problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @id grafana/cloud-migration-cancel-snapshot-missing-orgid
 * @tags security
 *       authorization
 *       multi-tenant
 *       cve-2024-9476
 */

import go

/**
 * Finds the CancelSnapshot function declaration without orgID parameter.
 */
from Function cancelFn
where
  cancelFn.getName() = "CancelSnapshot" and
  cancelFn.getNumParameter() <= 3 and
  not exists(Parameter orgParam |
    orgParam = cancelFn.getAParameter() and
    orgParam.getName().toLowerCase().matches("%org%")
  )
select cancelFn,
  "CancelSnapshot lacks orgID parameter; UpdateSnapshot SQL has no org_id in WHERE clause, enabling cross-org snapshot cancellation (CVE-2024-9476)."
