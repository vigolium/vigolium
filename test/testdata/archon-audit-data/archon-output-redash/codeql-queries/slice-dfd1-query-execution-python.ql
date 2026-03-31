/**
 * @name DFD-1 Query Execution (Python)
 * @description RemoteFlowSource to SQL execution or HTTP request
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id custom/dfd1-query-execution-python
 * @tags security
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

module Dfd1Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution e | sink = e.getSql())
    or exists(Http::Client::Request r | sink = r.getAUrlPart())
  }
}

module Dfd1Flow = TaintTracking::Global<Dfd1Config>;
import Dfd1Flow::PathGraph

from Dfd1Flow::PathNode source, Dfd1Flow::PathNode sink, DataFlow::Node srcNode, DataFlow::Node sinkNode
where
  Dfd1Flow::flowPath(source, sink) and
  srcNode = source.getNode() and
  sinkNode = sink.getNode()
select sinkNode, source, sink,
  "DFD-1: remote input at " + srcNode.getLocation().getFile().getRelativePath()
  + ":" + srcNode.getLocation().getStartLine().toString()
  + " flows to sink at " + sinkNode.getLocation().getFile().getRelativePath()
  + ":" + sinkNode.getLocation().getStartLine().toString()
