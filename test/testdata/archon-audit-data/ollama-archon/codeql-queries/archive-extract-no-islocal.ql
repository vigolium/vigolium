/**
 * @name Ollama - Archive extraction without filepath.IsLocal guard (ZipSlip)
 * @description Detects archive member names flowing into os.Create/OpenFile without IsLocal guard.
 *              CVE-2024-45436 (extractFromZipFile ZipSlip).
 *              DFD: DFD-3 (HTTP /api/create → Local File Ingestion → Symlink Escape).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id go/ollama/archive-extract-no-islocal
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-23
 */

import go
import semmle.go.dataflow.DataFlow

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FieldReadNode fr |
      fr.getFieldName() = "Name" and
      (
        fr.getBase().getType().hasQualifiedName("archive/zip", "File") or
        fr.getBase().getType().hasQualifiedName("archive/tar", "Header") or
        fr.getBase().getType().(PointerType).getBaseType().hasQualifiedName("archive/zip", "File") or
        fr.getBase().getType().(PointerType).getBaseType().hasQualifiedName("archive/tar", "Header")
      ) and
      source = fr
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("os", "Create") or
        call.getTarget().hasQualifiedName("os", "OpenFile") or
        call.getTarget().hasQualifiedName("os", "MkdirAll")
      ) and
      sink = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      (
        call.getTarget().hasQualifiedName("path/filepath", "IsLocal") or
        call.getTarget().hasQualifiedName("path/filepath", "Rel") or
        call.getTarget().hasQualifiedName("strings", "HasPrefix") or
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
  "Archive member name $@ flows to file creation without filepath.IsLocal() containment — ZipSlip path traversal (CVE-2024-45436).",
  source.getNode(), source.getNode().toString()
