/**
 * @name Ollama - Digest used in file path without canonicalization
 * @description Detects cases where a Digest string field flows into os.Create/OpenFile
 *              without passing through a canonicalization function (BlobsPath, filepath.IsLocal).
 *              CVE-2024-37032 ("Probllama"): path traversal via malformed sha256 digest.
 *              DFD: DFD-1 (HTTP /api/pull → Registry → Disk Write).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id go/ollama/digest-path-no-canonicalization
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-73
 */

import go
import semmle.go.dataflow.DataFlow

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FieldReadNode fr |
      fr.getFieldName() = ["Digest", "digest"] and
      source = fr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os", "Create") or
        call.getTarget().hasQualifiedName("os", "OpenFile") or
        call.getTarget().hasQualifiedName("os", "WriteFile")
      ) and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = ["BlobsPath", "blobsPath"] or
        call.getTarget().hasQualifiedName("path/filepath", "IsLocal") or
        call.getTarget().hasQualifiedName("path/filepath", "EvalSymlinks")
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
  "Remote manifest Digest $@ reaches file path construction without BlobsPath() canonicalization — path traversal risk (CVE-2024-37032).",
  source.getNode(), source.getNode().toString()
