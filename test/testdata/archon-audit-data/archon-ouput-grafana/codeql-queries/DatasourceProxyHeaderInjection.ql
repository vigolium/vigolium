/**
 * @name Datasource Proxy Header Injection via X-DS-Authorization
 * @description Detects when the X-DS-Authorization header from an incoming
 *              client request is forwarded as the Authorization header to backend
 *              datasources, allowing authenticated users to inject arbitrary
 *              credentials for backend services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id go/grafana/datasource-proxy-header-injection
 * @tags security
 *       external/cwe/cwe-116
 *       grafana/dfd-1
 */

import go
import DataFlow::PathGraph

/**
 * Source: req.Header.Get("X-DS-Authorization") - user-controlled HTTP header
 */
class XDsAuthorizationSource extends DataFlow::Node {
  XDsAuthorizationSource() {
    exists(CallExpr call |
      call.getCalleeName() = "Get" and
      call.getArgument(0).(StringLit).getValue() = "X-DS-Authorization" and
      call.getFile().getRelativePath().matches("%pluginproxy%")
    |
      this.asExpr() = call
    )
  }
}

/**
 * Sink: req.Header.Set("Authorization", value) - forwarded to backend
 */
class AuthorizationHeaderSetSink extends DataFlow::Node {
  AuthorizationHeaderSetSink() {
    exists(CallExpr call |
      call.getCalleeName() = "Set" and
      call.getArgument(0).(StringLit).getValue() = "Authorization" and
      call.getFile().getRelativePath().matches("%pluginproxy%")
    |
      this.asExpr() = call.getArgument(1)
    )
  }
}

class HeaderInjectionConfig extends TaintTracking::Configuration {
  HeaderInjectionConfig() { this = "HeaderInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof XDsAuthorizationSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof AuthorizationHeaderSetSink
  }
}

from HeaderInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "X-DS-Authorization header ($@) from client request is forwarded as Authorization to backend datasource, allowing credential injection.",
  source.getNode(), "user-controlled X-DS-Authorization header"
