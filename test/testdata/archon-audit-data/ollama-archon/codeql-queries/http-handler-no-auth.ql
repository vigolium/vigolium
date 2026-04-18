/**
 * @name Ollama - HTTP handler registered without authentication check
 * @description Finds gin route registrations where the handler function literal
 *              lacks any call to auth-checking functions.
 *              CVE-2025-63389: multiple API endpoints lack authentication.
 *              DFD: cross-cutting (all HTTP handler slices).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @id go/ollama/http-handler-no-auth
 * @tags security authentication
 *       external/cwe/cwe-306
 *       external/cwe/cwe-284
 */

import go

/**
 * A gin route registration method call.
 */
class GinRouteRegistration extends DataFlow::CallNode {
  GinRouteRegistration() {
    this.getCalleeName() = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
  }
}

/**
 * Predicate: a function literal contains an auth-related call.
 */
predicate funcLitHasAuthCall(FuncLit fl) {
  exists(DataFlow::CallNode call |
    call.getRoot() = fl and
    call.getCalleeName() =
      ["getAuthorizationToken", "ensureAuth", "GetHeader", "Unauthorized", "Abort", "AbortWithStatus"]
  )
}

from GinRouteRegistration reg, FuncLit handler
where
  reg.getArgument(reg.getNumArgument() - 1).asExpr() = handler and
  not funcLitHasAuthCall(handler)
select reg,
  "Route registered via " + reg.getCalleeName() +
  " with handler at " + handler.getFile().getRelativePath() +
  " lacks detected auth check — review per CVE-2025-63389."
