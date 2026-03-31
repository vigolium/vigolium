/**
 * @name List recognized dataflow sinks (Python)
 * @description Enumerates security-relevant sinks CodeQL recognizes
 * @kind problem
 * @problem.severity note
 * @id custom/list-sinks-python
 */
import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow

from DataFlow::Node sink, string kind
where
  exists(SqlExecution e | sink = e.getSql() and kind = "sql-execution")
  or
  exists(SystemCommandExecution e |
    sink = e.getCommand() and kind = "command-execution"
  )
  or
  exists(FileSystemAccess e |
    sink = e.getAPathArgument() and kind = "file-access"
  )
  or
  exists(Http::Client::Request r |
    sink = r.getAUrlPart() and kind = "http-request"
  )
  or
  exists(Decoding d | sink = d.getAnInput() and kind = "decoding")
  or
  exists(CodeExecution e | sink = e.getCode() and kind = "code-execution")
select sink,
  kind
    + " | " + sink.getLocation().getFile().getRelativePath()
    + ":" + sink.getLocation().getStartLine().toString()
