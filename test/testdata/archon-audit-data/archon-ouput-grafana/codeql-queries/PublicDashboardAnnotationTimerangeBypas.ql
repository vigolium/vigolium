/**
 * @name Public Dashboard Annotation Timerange Bypass
 * @description Detects when From/To query parameters from an unauthenticated
 *              public dashboard request can reach the annotation SQL WHERE clause
 *              without validation, allowing from=0&to=0 to bypass time filtering.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id go/grafana/public-dashboard-annotation-timerange-bypass
 * @tags security
 *       external/cwe/cwe-284
 *       grafana/dfd-3
 */

import go
import DataFlow::PathGraph

/**
 * Models c.QueryInt64("from") and c.QueryInt64("to") as taint sources
 * in the public dashboard annotation handler.
 */
class PublicDashboardAnnotationSource extends DataFlow::Node {
  PublicDashboardAnnotationSource() {
    // Match c.QueryInt64("from") or c.QueryInt64("to") calls
    exists(CallExpr call |
      call.getCalleeName() = "QueryInt64" and
      (
        call.getArgument(0).(StringLit).getValue() = "from" or
        call.getArgument(0).(StringLit).getValue() = "to"
      ) and
      // In the publicdashboards API package
      call.getFile().getPackageName() = "api" and
      call.getFile().getRelativePath().matches("%publicdashboards%")
    |
      this.asExpr() = call
    )
  }
}

/**
 * Models the AnnotationsQueryDTO From/To fields as taint propagation points.
 */
class AnnotationsQueryDTOSink extends DataFlow::Node {
  AnnotationsQueryDTOSink() {
    // The `if query.From > 0 && query.To > 0` guard in xorm_store.go
    exists(SelectorExpr sel |
      (sel.getSelector().getName() = "From" or sel.getSelector().getName() = "To") and
      sel.getBase().getType().hasQualifiedName(_, "ItemQuery")
    |
      this.asExpr() = sel
    )
  }
}

class AnnotationTimerangeConfig extends TaintTracking::Configuration {
  AnnotationTimerangeConfig() { this = "AnnotationTimerangeConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof PublicDashboardAnnotationSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof AnnotationsQueryDTOSink
  }
}

from AnnotationTimerangeConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Annotation time range parameter from public dashboard request ($@) reaches SQL WHERE guard without zero-value validation, allowing from=0&to=0 to bypass all time filtering.",
  source.getNode(), "user-controlled from/to value"
