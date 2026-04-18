/**
 * @name Ollama - Unbounded io.ReadAll on HTTP Response Body
 * @description Detects calls to io.ReadAll on an HTTP response body without
 *              a preceding http.MaxBytesReader or io.LimitReader wrapper.
 *              CVE class: CVE-2024-12886 (gzip bomb via io.ReadAll).
 *              DFD: DFD-13 (gzip-encoded registry response → io.ReadAll memory exhaustion).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id go/ollama/unbounded-readall-on-remote-response
 * @tags security correctness
 *       external/cwe/cwe-400
 *       external/cwe/cwe-770
 */

import go
import semmle.go.dataflow.DataFlow

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Field f |
      f.getName() = "Body" and
      f.getDeclaringType().hasQualifiedName("net/http", "Response") and
      source.(DataFlow::FieldReadNode).getField() = f
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("io", "ReadAll") or
        call.getTarget().hasQualifiedName("io/ioutil", "ReadAll")
      ) and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode wrapper |
      (
        wrapper.getTarget().hasQualifiedName("net/http", "MaxBytesReader") or
        wrapper.getTarget().hasQualifiedName("io", "LimitReader")
      ) and
      node = wrapper.getResult(0)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "io.ReadAll on HTTP response body $@ without size limit — gzip bomb / memory exhaustion risk (CVE-2024-12886 class, DFD-13).",
  source.getNode(), source.getNode().toString()
