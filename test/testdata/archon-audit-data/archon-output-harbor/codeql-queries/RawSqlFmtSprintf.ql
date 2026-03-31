/**
 * @name Raw SQL construction via fmt.Sprintf
 * @description fmt.Sprintf is used to build SQL strings that flow into Raw()
 *              or Exec(). If any interpolated value is user-influenced, this
 *              creates a SQL injection vulnerability.
 * @kind path-problem
 * @id harbor/raw-sql-fmt-sprintf
 * @problem.severity error
 * @security-severity 9.3
 * @tags security
 *       sql-injection
 *       harbor
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

/**
 * A call to fmt.Sprintf as a taint source.
 */
class FmtSprintfSource extends DataFlow::Node {
  FmtSprintfSource() {
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("fmt", "Sprintf") and
      this = c.getResult()
    )
  }
}

/**
 * The first argument of a Raw() / Exec() call as a taint sink.
 */
class RawSQLSink extends DataFlow::Node {
  RawSQLSink() {
    exists(DataFlow::CallNode c |
      (
        c.getTarget().getName() = "Raw" or
        c.getTarget().getName() = "Exec" or
        c.getTarget().getName() = "QueryRow" or
        c.getTarget().getName() = "QueryRows"
      ) and
      this = c.getArgument(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof FmtSprintfSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RawSQLSink
  }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;
import SqlFlow::PathGraph

from SqlFlow::PathNode source, SqlFlow::PathNode sink
where SqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL string constructed with fmt.Sprintf flows to raw SQL execution. " +
  "Verify no user-controlled value is interpolated into the SQL template."
