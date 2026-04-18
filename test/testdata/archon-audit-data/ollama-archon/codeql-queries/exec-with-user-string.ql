/**
 * @name Ollama - exec.Command/CommandContext with user-controlled argument
 * @description Tracks user-supplied strings flowing into exec.Command or exec.CommandContext.
 *              Known positives: x/tools/bash.go, cmd/cmd.go ($EDITOR path).
 *              DFD: DFD-5 (LLM output → Agent Tool Call → bash), DFD-14 ($EDITOR).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @id go/ollama/exec-with-user-string
 * @tags security correctness
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.security.FlowSources

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os", "Getenv") or
        call.getTarget().hasQualifiedName("os", "LookupEnv")
      ) and
      source = call.getResult(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os/exec", "Command") or
        call.getTarget().hasQualifiedName("os/exec", "CommandContext")
      ) and
      sink = call.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled value $@ flows to exec.Command/CommandContext — OS command injection risk (DFD-5 / DFD-14).",
  source.getNode(), source.getNode().toString()
