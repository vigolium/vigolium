/**
 * @name List recognized dataflow sources (Python)
 * @description Enumerates all locations CodeQL recognizes as remote flow sources
 * @kind problem
 * @problem.severity note
 * @id custom/list-sources-python
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources

from RemoteFlowSource src
select src,
  src.getSourceType()
    + " | " + src.getLocation().getFile().getRelativePath()
    + ":" + src.getLocation().getStartLine().toString()
