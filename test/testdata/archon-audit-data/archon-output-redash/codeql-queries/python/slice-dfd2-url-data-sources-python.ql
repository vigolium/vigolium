/**
 * @name DFD-2 URL Data Sources (Python)
 * @description RemoteFlowSource to HTTP request URL parts
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id custom/dfd2-url-data-sources-python
 * @tags security
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

module Dfd2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(Http::Client::Request r | sink = r.getAUrlPart())
  }
}

module Dfd2Flow = TaintTracking::Global<Dfd2Config>;
import Dfd2Flow::PathGraph

from Dfd2Flow::PathNode source, Dfd2Flow::PathNode sink, DataFlow::Node srcNode, DataFlow::Node sinkNode
where
  Dfd2Flow::flowPath(source, sink) and
  srcNode = source.getNode() and
  sinkNode = sink.getNode()
select sinkNode, source, sink,
  "DFD-2: remote input at " + srcNode.getLocation().getFile().getRelativePath()
  + ":" + srcNode.getLocation().getStartLine().toString()
  + " flows to HTTP URL sink at " + sinkNode.getLocation().getFile().getRelativePath()
  + ":" + sinkNode.getLocation().getStartLine().toString()
