/**
 * @name SSRF via user-controlled URL in job service HTTP client
 * @description A URL value from job parameters flows to http.NewRequest without
 *              any private-IP filtering, allowlist check, or scheme restriction.
 *              This enables SSRF attacks via webhook, replication, and preheat jobs.
 * @kind path-problem
 * @id harbor/ssrf-job-http-client
 * @problem.severity error
 * @security-severity 8.6
 * @tags security
 *       ssrf
 *       harbor
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

/**
 * Source: job Parameters map access — params["address"] or params["url"]
 */
class JobParamsSource extends DataFlow::Node {
  JobParamsSource() {
    exists(IndexExpr ie |
      ie.getBase().getType().(MapType).getValueType() instanceof Interface and
      (
        ie.getIndex().(StringLit).getValue() = "address" or
        ie.getIndex().(StringLit).getValue() = "url" or
        ie.getIndex().(StringLit).getValue() = "endpoint"
      ) and
      this.asExpr() = ie
    )
  }
}

/**
 * Sink: first argument (URL string) of http.NewRequest.
 */
class HttpNewRequestURLSink extends DataFlow::Node {
  HttpNewRequestURLSink() {
    exists(CallExpr c |
      c.getTarget().hasQualifiedName("net/http", "NewRequest") and
      this.asExpr() = c.getArgument(1)
    )
  }
}

module SSRFConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof JobParamsSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof HttpNewRequestURLSink
  }
}

module SSRFFlow = TaintTracking::Global<SSRFConfig>;
import SSRFFlow::PathGraph

from SSRFFlow::PathNode source, SSRFFlow::PathNode sink
where SSRFFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled URL from job parameters flows to http.NewRequest without " +
  "validation. This is an SSRF vector if the job was created by an end user."
