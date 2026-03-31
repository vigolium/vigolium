/**
 * @name List recognized dataflow sinks (JavaScript)
 * @description Enumerates security-relevant sinks CodeQL recognizes
 * @kind problem
 * @problem.severity note
 * @id custom/list-sinks-javascript
 */
import javascript

from DataFlow::Node sink, string kind
where
  exists(DatabaseAccess e |
    sink = e.getAQueryArgument() and kind = "database-access"
  )
  or
  exists(SystemCommandExecution e |
    sink = e.getACommandArgument() and kind = "command-execution"
  )
  or
  exists(FileSystemAccess e |
    sink = e.getAPathArgument() and kind = "file-access"
  )
select sink,
  kind
    + " | " + sink.getLocation().getFile().getRelativePath()
    + ":" + sink.getLocation().getStartLine().toString()
