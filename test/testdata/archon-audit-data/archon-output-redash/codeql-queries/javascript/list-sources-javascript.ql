/**
 * @name List recognized dataflow sources (JavaScript)
 * @description Enumerates all locations CodeQL recognizes as remote flow sources
 * @kind problem
 * @problem.severity note
 * @id custom/list-sources-javascript
 */
import javascript

from RemoteFlowSource src
select src,
  src.getLocation().getFile().getRelativePath()
    + ":" + src.getLocation().getStartLine().toString()
