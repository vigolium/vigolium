/**
 * @name List recognized dataflow sources (JavaScript)
 * @description Enumerates all locations CodeQL recognizes as dataflow sources
 * @kind problem
 * @id custom/list-sources-javascript
 */
import javascript

from RemoteFlowSource src
select src,
  src.getLocation().getFile().getRelativePath()
    + ":" + src.getLocation().getStartLine().toString()
