/**
 * @name Supply-chain RCE via ENTRYPOINT in pulled model config
 * @description The Entrypoint field from a registry-supplied ConfigV2 JSON blob
 *              flows into exec.Command without sandboxing or user consent.
 *              CWE-78 / CWE-494.
 * @kind path-problem
 * @problem.severity error
 * @id ollama/entrypoint-rce
 * @tags security
 */

import go
import DataFlow::PathGraph

/**
 * Source: Entrypoint field deserialized from ConfigV2 JSON
 * (types/model/config.go: ConfigV2.Entrypoint)
 */
class EntrypointSource extends DataFlow::Node {
  EntrypointSource() {
    exists(FieldRead fr |
      fr.getField().getName() = "Entrypoint" and
      fr.getField().getDeclaringType().getName() = "ConfigV2" and
      this.asExpr() = fr
    )
  }
}

/**
 * Sink: exec.Command / exec.CommandContext first argument
 */
class ExecCommandSink extends DataFlow::Node {
  ExecCommandSink() {
    exists(CallExpr call |
      (call.getTarget().getName() = "Command" or
       call.getTarget().getName() = "CommandContext") and
      call.getTarget().getPackage().getName() = "exec" and
      this.asExpr() = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::hasFlowPath(source, sink)
  and source.getNode() instanceof EntrypointSource
  and sink.getNode() instanceof ExecCommandSink
select sink.getNode(), source, sink,
  "Model config Entrypoint flows into exec.Command with no sandbox or consent check."
