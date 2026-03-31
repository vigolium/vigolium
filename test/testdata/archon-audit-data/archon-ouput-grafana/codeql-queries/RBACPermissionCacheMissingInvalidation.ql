/**
 * @name RBAC Permission Cache Missing Invalidation After Delete
 * @description Detects datasource deletion operations that are not followed
 *              by a cache invalidation call, leaving stale permission/datasource
 *              cache entries for the TTL duration (5 seconds).
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id go/grafana/rbac-cache-missing-invalidation
 * @tags security
 *       external/cwe/cwe-362
 *       grafana/dfd-5
 *       grafana/cfd-2
 */

import go

/**
 * Calls to DeleteDataSource that represent deletion operations.
 */
class DeleteDataSourceCall extends CallExpr {
  DeleteDataSourceCall() {
    this.getCalleeName() = "DeleteDataSource"
  }
}

/**
 * Cache invalidation calls that should follow delete operations.
 */
class CacheInvalidationCall extends CallExpr {
  CacheInvalidationCall() {
    this.getCalleeName().matches("%Delete%") or
    this.getCalleeName().matches("%Invalidate%") or
    this.getCalleeName().matches("%Remove%")
  }
}

/**
 * Find DeleteDataSource calls that are not within a function
 * that also calls a cache invalidation method.
 */
from DeleteDataSourceCall deleteCall, Function f
where
  deleteCall.getEnclosingFunction() = f and
  not exists(CacheInvalidationCall invalidate |
    invalidate.getEnclosingFunction() = f
  )
select deleteCall,
  "DeleteDataSource() at " + deleteCall.getFile().getRelativePath() + ":" +
  deleteCall.getLocation().getStartLine() +
  " is not followed by a cache invalidation call in the same function. " +
  "The datasource cache (5s TTL) will serve stale data until expiry."
