/**
 * @name Avatar endpoint uses reqSignedIn allowing anonymous bypass
 * @description The /avatar/:hash route is registered with reqSignedIn middleware.
 *              When anonymous auth is enabled, reqSignedIn allows anonymous
 *              requests because AllowAnonymous=true causes requireLogin to be false.
 *              The correct middleware is reqSignedInNoAnonymous (ReqNoAnonymous=true).
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id grafana/avatar-reqsignedin-anonymous-bypass
 * @tags security
 *       authentication
 *       cve-2026-21720
 */

import go

/**
 * Finds calls to r.Get that register the /avatar/:hash route with reqSignedIn.
 */
from CallExpr routeReg, StringLit path
where
  routeReg.getTarget().getName() = "Get" and
  path = routeReg.getArgument(0) and
  path.getValue() = "/avatar/:hash"
select routeReg, "Avatar route registered with reqSignedIn; anonymous users bypass auth when [auth.anonymous] enabled=true. Use reqSignedInNoAnonymous instead."
