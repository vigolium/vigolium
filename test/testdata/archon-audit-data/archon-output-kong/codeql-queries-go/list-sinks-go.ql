/**
 * @name List recognized dataflow sinks (Go)
 * @description Enumerates security-relevant sinks CodeQL recognizes
 * @kind problem
 * @id custom/list-sinks-go
 */
import go
import semmle.go.frameworks.SQL

from DataFlow::Node sink, string kind
where
  sink instanceof SQL::QueryString and kind = "sql-query"
  or
  exists(SystemCommandExecution e |
    sink = e.getCommandName() and kind = "command-execution"
  )
  or
  exists(FileSystemAccess e |
    sink = e.getAPathArgument() and kind = "file-access"
  )
select sink,
  kind
    + " | " + sink.getLocation().getFile().getRelativePath()
    + ":" + sink.getLocation().getStartLine().toString()
