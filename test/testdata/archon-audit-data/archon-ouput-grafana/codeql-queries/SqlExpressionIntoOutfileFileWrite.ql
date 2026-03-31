/**
 * @name SQL expression engine allows INTO OUTFILE without DisableFileWrites
 * @description The go-mysql-server AllowQuery function permits *sqlparser.Into nodes,
 *              allowing SELECT ... INTO OUTFILE statements. The mysql context is created
 *              without WithDisableFileWrites(true), and the IsReadOnly engine flag is
 *              bypassed because plan.Into.IsReadOnly() delegates to the child SELECT
 *              which returns true. This enables authenticated users to write arbitrary
 *              files on the Grafana server when the sqlExpressions feature flag is enabled.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id grafana/sql-expression-into-outfile-file-write
 * @tags security
 *       file-write
 *       cve-2024-9264
 */

import go

/**
 * Finds mysql.NewContext calls that lack WithDisableFileWrites option in the sql expression engine.
 */
from CallExpr newContextCall
where
  newContextCall.getTarget().getName() = "NewContext" and
  newContextCall.getFile().getAbsolutePath().matches("%/pkg/expr/sql/%")
select newContextCall,
  "go-mysql-server context created without WithDisableFileWrites(true); INTO OUTFILE can write arbitrary files when sqlExpressions feature is enabled (CVE-2024-9264)."
