/**
 * @name DFD-4 Webhooks/Destinations (Python)
 * @description Local/admin config input to HTTP request URL parts
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id custom/dfd4-webhooks-destinations-python
 * @tags security
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

module Dfd4Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["get", "get_str"] and
      c.getFunc().(Attribute).getObject().toString().regexpMatch("self\\.configuration") and
      source.asExpr() = c
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Http::Client::Request r | sink = r.getAUrlPart())
  }
}

module Dfd4Flow = TaintTracking::Global<Dfd4Config>;
import Dfd4Flow::PathGraph

from Dfd4Flow::PathNode source, Dfd4Flow::PathNode sink, DataFlow::Node srcNode, DataFlow::Node sinkNode
where
  Dfd4Flow::flowPath(source, sink) and
  srcNode = source.getNode() and
  sinkNode = sink.getNode()
select sinkNode, source, sink,
  "DFD-4: input at " + srcNode.getLocation().getFile().getRelativePath()
  + ":" + srcNode.getLocation().getStartLine().toString()
  + " flows to webhook URL sink at " + sinkNode.getLocation().getFile().getRelativePath()
  + ":" + sinkNode.getLocation().getStartLine().toString()
