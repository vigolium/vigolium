/**
 * @name Slice: HTTP request source to HTTP client sink (Python)
 * @description Structural slice for DFD: proxy/admin inputs to outbound HTTP
 * @kind path-problem
 * @problem.severity note
 * @id custom/slice-http-request-to-http-request-python
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
    exists(Http::Client::Request req | sink = req.getAUrlPart())
  }
}

module SliceFlow = TaintTracking::Global<SliceConfig>;
import SliceFlow::PathGraph

from SliceFlow::PathNode source, SliceFlow::PathNode sink
where SliceFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Remote input can reach HTTP client URL.",
  source.getNode(), "remote input"
