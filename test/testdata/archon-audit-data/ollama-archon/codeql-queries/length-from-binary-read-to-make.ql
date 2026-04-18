/**
 * @name Ollama - Unsafe length from binary.Read flows to make/io.CopyN
 * @description Tracks integer lengths read via encoding/binary.Read that flow
 *              into memory allocation (make builtin) or io.CopyN without a bounds check.
 *              CVE class: CVE-2025-0315, CVE-2025-66959, TALOS-2024-1913.
 *              DFD: DFD-2 (blob upload → GGUF parser), DFD-10 (safetensors header).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id go/ollama/length-from-binary-read-to-make
 * @tags security correctness
 *       external/cwe/cwe-190
 *       external/cwe/cwe-400
 *       external/cwe/cwe-770
 */

import go
import semmle.go.dataflow.DataFlow

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // The pointer argument (&n) of binary.Read — after call n holds attacker-controlled length
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("encoding/binary", "Read") and
      source = call.getArgument(2)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // make([]T, n) — the length argument to the built-in make function
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "make" and
      (
        sink = call.getArgument(1) or
        sink = call.getArgument(2)
      )
    )
    or
    // io.CopyN(dst, src, n) — n is arg 2
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("io", "CopyN") and
      sink = call.getArgument(2)
    )
    or
    // io.ReadFull(r, buf) where buf was sized from the length
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("io", "ReadFull") and
      sink = call.getArgument(1)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Length read via binary.Read at $@ flows to allocation/copy without bounds check — OOM/DoS risk (GGUF/safetensors parser, CVE-2025-0315 class).",
  source.getNode(), source.getNode().toString()
