/**
 * @name DFD-3 Auth Flows (Python)
 * @description RemoteFlowSource to auth decision (login/session creation)
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id custom/dfd3-auth-flows-python
 * @tags security
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow

module Dfd3Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc().(Name).getId() = "login_user" and
      sink.asExpr() = c.getArg(0)
    )
    or
    exists(Call c |
      c.getFunc().(Name).getId() = "create_and_login_user" and
      sink.asExpr() = c.getArg(1)
    )
    or
    exists(Call c |
      c.getFunc().(Name).getId() = "create_and_login_user" and
      sink.asExpr() = c.getArg(2)
    )
  }
}

module Dfd3Flow = TaintTracking::Global<Dfd3Config>;
import Dfd3Flow::PathGraph

from Dfd3Flow::PathNode source, Dfd3Flow::PathNode sink, DataFlow::Node srcNode, DataFlow::Node sinkNode
where
  Dfd3Flow::flowPath(source, sink) and
  srcNode = source.getNode() and
  sinkNode = sink.getNode()
select sinkNode, source, sink,
  "DFD-3: remote input at " + srcNode.getLocation().getFile().getRelativePath()
  + ":" + srcNode.getLocation().getStartLine().toString()
  + " flows to auth sink at " + sinkNode.getLocation().getFile().getRelativePath()
  + ":" + sinkNode.getLocation().getStartLine().toString()
