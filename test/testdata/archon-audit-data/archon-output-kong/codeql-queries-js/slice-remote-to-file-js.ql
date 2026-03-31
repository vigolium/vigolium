/**
 * @name Slice: remote input to file access (JavaScript)
 * @description Structural slice for file access from remote sources
 * @kind path-problem
 * @problem.severity note
 * @id custom/slice-remote-to-file-js
 */
import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.dataflow.PathGraph

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
