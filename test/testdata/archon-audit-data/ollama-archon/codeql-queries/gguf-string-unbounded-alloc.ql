/**
 * @name GGUF string length unbounded allocation
 * @description readGGUFString reads a uint64 length from untrusted GGUF data
 *              and uses it directly in make([]byte, length) without an upper
 *              bound check. Enables OOM via crafted GGUF. CWE-770.
 * @kind path-problem
 * @problem.severity error
 * @id ollama/gguf-string-unbounded-alloc
 * @tags security
 */

import go
import DataFlow::PathGraph

/**
 * Source: GGUF file read into uint64 length field
 */
class GGUFStringLengthSource extends DataFlow::Node {
  GGUFStringLengthSource() {
    exists(CallExpr call |
      call.getTarget().getName() = "Uint64" and
      call.getEnclosingFunction().getName() = "readGGUFString" and
      this.asExpr() = call
    )
  }
}

/**
 * Sink: make([]byte, length) in readGGUFString
 */
class UnboundedAllocSink extends DataFlow::Node {
  UnboundedAllocSink() {
    exists(CallExpr make |
      make.getTarget().getName() = "make" and
      make.getEnclosingFunction().getName() = "readGGUFString" and
      this.asExpr() = make.getArgument(1)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::hasFlowPath(source, sink)
  and source.getNode() instanceof GGUFStringLengthSource
  and sink.getNode() instanceof UnboundedAllocSink
select sink.getNode(), source, sink,
  "GGUF string length from untrusted file flows into make() without upper bound check."
