/**
 * @name Ollama - File read via glob/walk without EvalSymlinks canonicalization
 * @description Detects file paths from filepath.Glob flowing to os.Open/ReadFile
 *              without a filepath.EvalSymlinks + IsLocal check.
 *              Known positives: x/create/create.go, x/create/imagegen.go (commit d931ee8f).
 *              DFD: DFD-3 (create → symlink escape).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id go/ollama/symlink-read-without-evalsymlinks
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-61
 */

import go
import semmle.go.dataflow.DataFlow

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("path/filepath", "Glob") and
      source = call.getResult(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os", "Open") or
        call.getTarget().hasQualifiedName("os", "ReadFile") or
        call.getTarget().hasQualifiedName("os", "OpenFile") or
        call.getTarget().hasQualifiedName("os", "Stat")
      ) and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("path/filepath", "EvalSymlinks") or
        call.getTarget().hasQualifiedName("path/filepath", "IsLocal")
      ) and
      node = call.getResult(0)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Filepath from glob $@ reaches file open without EvalSymlinks+IsLocal check — symlink escape risk (commit d931ee8f).",
  source.getNode(), source.getNode().toString()
