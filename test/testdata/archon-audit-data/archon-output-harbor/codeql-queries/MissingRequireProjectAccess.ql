/**
 * @name Missing RequireProjectAccess in v2.0 API handler
 * @description Handler methods that do not call RequireProjectAccess,
 *              RequireSystemAccess, or RequireAuthenticated before performing
 *              operations on resources. This is the root-cause pattern behind
 *              CVE-2022-31666 through CVE-2022-31671 (authorization bypass).
 * @kind problem
 * @id harbor/missing-require-project-access
 * @problem.severity error
 * @security-severity 9.1
 * @tags security
 *       authorization
 *       harbor
 */

import go

/**
 * A handler method: a method whose source file lives under server/v2.0/handler/
 * and has a name that starts with an uppercase letter (exported).
 */
class HandlerMethod extends Method {
  HandlerMethod() {
    this.getFuncDecl().getFile().getRelativePath().matches("%server/v2.0/handler%") and
    // Exported methods have names starting with an uppercase letter
    this.getName().regexpMatch("[A-Z].*") and
    not this.getName() = "Prepare"
  }
}

/**
 * Calls to authorization enforcement helpers.
 */
predicate hasAuthCall(Method m) {
  exists(CallExpr c |
    c.getEnclosingFunction().(FuncDecl).getFunction() = m and
    (
      c.getTarget().getName().matches("Require%Access") or
      c.getTarget().getName() = "RequireAuthenticated" or
      c.getTarget().getName() = "RequireSolutionUserAccess" or
      c.getTarget().getName().matches("require%ccess") or
      c.getTarget().getName().matches("require%olicy%")
    )
  )
}

from HandlerMethod m
where not hasAuthCall(m)
select m.getFuncDecl(),
  "Handler method '" + m.getName() + "' in " + m.getFuncDecl().getFile().getBaseName() +
  " does not call RequireProjectAccess/RequireSystemAccess/RequireAuthenticated. " +
  "This may be an authorization bypass (pattern of CVE-2022-31666 cluster)."
