/**
 * @name Ollama - text/template.Parse or Execute with user-controlled source
 * @description Detects user-controlled content flowing into text/template.Parse or Execute.
 *              Since Ollama uses text/template (not html/template), auto-escaping is off.
 *              DFD: DFD-4 (Modelfile TEMPLATE → text/template → LLM Prompt / DoS).
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @id go/ollama/template-execute-user-src
 * @tags security
 *       external/cwe/cwe-94
 *       external/cwe/cwe-400
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
        call.getTarget().hasQualifiedName("os", "ReadFile") or
        call.getTarget().hasQualifiedName("io", "ReadAll")
      ) and
      source = call.getResult(0)
    )
    or
    exists(DataFlow::FieldReadNode fr |
      fr.getFieldName() = ["Template", "System", "ChatTemplate"] and
      source = fr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["Parse", "Execute", "ExecuteTemplate"] and
      sink = call.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled content $@ flows to text/template.Parse/Execute — SSTI/DoS risk (DFD-4, html auto-escape disabled since commit 62d29b21).",
  source.getNode(), source.getNode().toString()
