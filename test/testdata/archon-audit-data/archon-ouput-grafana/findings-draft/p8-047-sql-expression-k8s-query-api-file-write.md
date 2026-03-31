Phase: 10
Sequence: 047
Slug: sql-expression-k8s-query-api-file-write
Verdict: VALID
Rationale: The K8s aggregated query API (/apis/datasource.grafana.app/v0alpha1/) accepts SQL expressions and routes them through the same expr.Service instance as the REST API; its authorizer only checks for a valid user identity (no specific datasources:query RBAC check at the K8s layer), creating a second entry point for the p8-040 file write vulnerability.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-sql-expression-into-outfile-file-write.md
Origin-Pattern: AP-040

## Summary

The Grafana K8s API aggregation layer registers a query API builder at `pkg/registry/apis/query/` when either `queryService` or `grafanaAPIServerWithExperimentalAPIs` feature flags are enabled. This API surface accepts datasource queries including SQL expressions via the Kubernetes API machinery. The registered authorizer (at `register.go:128-139`) performs only a user identity check (`claims.AuthInfoFrom(ctx)`) and explicitly delegates "real" RBAC checks to the datasource loading phase. However, SQL expressions use the `__expr__` pseudo-datasource which does not go through the standard datasource RBAC check, potentially bypassing the "real" RBAC check entirely. The same `expr.Service` instance is wired into the K8s query path, and the same `DB.QueryFrames` method with the same missing `WithDisableFileWrites` control is used.

This variant requires two feature flags (`sqlExpressions` + one of `queryService`/`grafanaAPIServerWithExperimentalAPIs`) vs the one flag in p8-040.

## Location

- **Primary**: `pkg/registry/apis/query/register.go:128-139` -- K8s authorizer only checks user identity; no datasources:query RBAC at this boundary
- **Route**: K8s API path `/apis/datasource.grafana.app/v0alpha1/` (aggregated K8s API, port 6443 or proxied through :3000)
- **Expr wiring**: `register.go:329-351` -- `expr.ProvideService(...)` creates the same SQL expression service
- **Execution**: `query.go` -> `QueryData` -> `expr.Service.BuildPipeline` -> same `sql/db.go:71` path
- **Feature gate**: Requires BOTH `sqlExpressions` AND (`queryService` OR `grafanaAPIServerWithExperimentalAPIs`)

## Attacker Control

- **Input**: K8s API query request containing SQL expression query type
- **UNION bypass**: Same UNION syntax as p8-040
- **Minimum privilege**: Any authenticated user (K8s authorizer: `return authorizer.DecisionAllow, "", nil` for any valid identity)
- **Datasource RBAC**: SQL expressions use `__expr__` pseudo-datasource; datasource lookup at `query.go:482` checks `expr.IsDataSource(ds.UID)` -- the expression datasource does not trigger standard datasource permission check

## Trust Boundary Crossed

Authenticated user K8s API query context -> OS filesystem write capability. The K8s API layer's weaker authorization check (identity-only) bypasses the specific `datasources:query` RBAC check enforced at the REST API level, while routing to the same vulnerable SQL engine.

## Impact

- **Same as p8-040**: Arbitrary file write as Grafana process user
- **Additional concern**: K8s API path may be exposed differently in Kubernetes/Helm deployments (e.g., separate Service, different network policies), potentially accessible to users who lack access to the main `:3000` HTTP port

## Evidence

1. `register.go:122-125`: Registration guarded by `queryService` OR `grafanaAPIServerWithExperimentalAPIs` flags
2. `register.go:128-139`: K8s authorizer only verifies `claims.AuthInfoFrom(ctx)` -- no `datasources:query` RBAC check at this layer; comment says "real check will happen when the specific data sources are loaded"
3. `register.go:329-335`: `expr.ProvideService()` includes SQL expression configuration (`SQLExpressionCellLimit`, `SQLExpressionQueryLengthLimit`, etc.) -- same service as REST path
4. `query_test.go:174`: Test uses `featuremgmt.WithFeatures(featuremgmt.FlagSqlExpressions)` confirming SQL expressions work in this path
5. `nodes.go:128`: `FlagSqlExpressions` check still applies -- SQL expressions flag must be enabled
6. `pkg/expr/sql/db.go:71`: Same `mysql.NewContext()` call without `WithDisableFileWrites(true)`

## Reproduction Steps

1. Enable feature flags: `sqlExpressions = true` and `grafanaAPIServerWithExperimentalAPIs = true`
2. Restart Grafana
3. As any authenticated user, send a query to the K8s API endpoint with a SQL expression containing the UNION INTO OUTFILE payload
4. The same file write as p8-040 occurs

Note: This variant has higher preconditions (two feature flags vs one) and is MEDIUM severity due to the additional flag requirement.
