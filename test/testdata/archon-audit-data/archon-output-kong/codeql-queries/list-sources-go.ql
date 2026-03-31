/**
 * @name List recognized dataflow sources (Go)
 * @description Enumerates all locations CodeQL recognizes as dataflow sources
 * @kind problem
 * @id custom/list-sources-go
 */
import go
import semmle.go.security.FlowSources

from RemoteFlowSource src
select src,
  src.getLocation().getFile().getRelativePath()
    + ":" + src.getLocation().getStartLine().toString()
