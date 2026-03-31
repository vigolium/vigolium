/**
 * @name http.ServeFile called without directory confinement check
 * @description http.ServeFile is called with result.FilePath from the rendering
 *              pipeline without verifying the path is within an expected temp
 *              directory. If the renderer JWT can be forged (default token '-')
 *              and the renderer returns a manipulated FilePath, ServeFile can
 *              expose arbitrary filesystem files to authenticated users.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id grafana/servefile-no-directory-confinement
 * @tags security
 *       path-traversal
 *       file-disclosure
 */

import go

/**
 * Finds http.ServeFile calls in render handler where the path argument
 * accesses a FilePath field, without a strings.HasPrefix guard.
 */
from CallExpr serveFileCall, SelectorExpr filePathAccess
where
  serveFileCall.getTarget().getName() = "ServeFile" and
  serveFileCall.getArgument(2) = filePathAccess.getBase() and
  filePathAccess.getSelector().getName() = "FilePath" and
  serveFileCall.getFile().getAbsolutePath().matches("%/pkg/api/render%")
select serveFileCall,
  "http.ServeFile called with rendering result FilePath without directory confinement check; path traversal possible if renderer JWT is forged with default token '-'."
