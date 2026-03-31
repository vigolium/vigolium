/**
 * @name Slice: remote input to file access (Python)
 * @description Structural slice for config/file injection concerns
 * @kind path-problem
 * @problem.severity note
 * @id custom/slice-remote-to-file-python
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.PathGraph

module SliceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(FileSystemAccess f | sink = f.getAPathArgument())
  }
}

module SliceFlow = TaintTracking::Global<SliceConfig>;
import SliceFlow::PathGraph

from SliceFlow::PathNode source, SliceFlow::PathNode sink
where SliceFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Remote input can reach file path.",
  source.getNode(), "remote input"
