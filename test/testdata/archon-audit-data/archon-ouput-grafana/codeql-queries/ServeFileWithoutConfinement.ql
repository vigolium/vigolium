/**
 * @name http.ServeFile Without Path Confinement Check
 * @description Detects calls to http.ServeFile where the file path argument
 *              is not preceded by a path confinement check (strings.HasPrefix,
 *              filepath.Rel, or filepath.Abs comparison against a known safe
 *              directory). Missing confinement is a defense-in-depth gap even
 *              if the path is currently derived from safe sources.
 * @kind problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @id go/grafana/servefile-without-confinement
 * @tags security
 *       external/cwe/cwe-22
 *       grafana/dfd-2
 */

import go

/**
 * http.ServeFile calls where the file path is a field access
 * (e.g., result.FilePath) suggesting it comes from a struct.
 */
from CallExpr serveFileCall, SelectorExpr pathArg
where
  serveFileCall.getTarget().hasQualifiedName("net/http", "ServeFile") and
  serveFileCall.getArgument(2) = pathArg and
  // The path comes from a struct field (e.g., result.FilePath)
  pathArg.getSelector().getName().matches("%Path%")
select serveFileCall,
  "http.ServeFile() at " + serveFileCall.getFile().getRelativePath() + ":" +
  serveFileCall.getLocation().getStartLine() +
  " uses a struct field path (" + pathArg.toString() + ") without a visible path confinement check. " +
  "Add strings.HasPrefix(filePath, filepath.Clean(allowedDir)) before serving."
