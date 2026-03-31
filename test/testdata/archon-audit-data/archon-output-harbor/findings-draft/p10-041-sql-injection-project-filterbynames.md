Phase: 10
Sequence: 041
Slug: sql-injection-project-filterbynames
Verdict: VALID
Rationale: FilterByNames in project/models/project.go wraps project name strings in single-quotes and concatenates directly into a SQL subquery via fmt.Sprintf, sharing the same anti-pattern as p7-003; project names are currently restricted by regex but the structural vulnerability remains and could become exploitable via future data path changes.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p7-003-sql-injection-fmt-sprintf.md
Origin-Pattern: AP-007

## Summary

`FilterByNames` in `src/pkg/project/models/project.go:256-266` builds a SQL subquery by wrapping each project name string in literal single-quote characters and concatenating them via `strings.Join`. There is no parameterization and no use of `orm.QuoteLiteral`. The pattern is structurally identical to p7-003's `fmt.Sprintf + FilterRaw()` anti-pattern. Although project names are currently restricted to `[a-z0-9._-]+` by `validProjectName` regex (preventing single-quote injection today), the query construction is unsafe-by-design and would become exploitable if:

- The regex validation is relaxed or bypassed
- Names arrive through a code path that skips `validProjectName` (e.g., migration, direct DB insert, replication from a remote Harbor with different validation)
- A future developer copies this pattern with a less-restricted string type

## Location

- `src/pkg/project/models/project.go:256-266` -- `FilterByNames` function
- `src/server/v2.0/handler/repository.go:144` -- robot token namespace -> `NamesQuery`
- `src/server/v2.0/handler/project.go:484` -- robot token namespace -> `NamesQuery`

## Attacker Control

Current: INDIRECT. Project names used in `NamesQuery.Names` originate from robot token permission namespaces (stored in DB, resolved via `proMgr.Get`). Project names are validated at creation time by `validProjectName` regex. However, a replication scenario copying projects from a remote registry with weaker validation could introduce names containing SQL metacharacters.

Hypothetical direct path: If `validProjectName` were widened to allow `'` (single quote), a project named `x' UNION SELECT password FROM harbor_user; --` would cause SQL injection in any `ListRepositories` or `ListProjects` call by a robot with that project permission.

## Trust Boundary Crossed

- TB-3 (Core API to PostgreSQL) -- same boundary as p7-003

## Impact

- Same as p7-003: confidentiality (data exfiltration via UNION), integrity (data modification)
- Robot account project enumeration affected -- ListRepositories and ListProjects handlers both trigger FilterByNames
- Regression risk: pattern is structurally dangerous and will become exploitable if name validation weakens

## Evidence

```go
// src/pkg/project/models/project.go:256-266
var names []string
for _, v := range query.Names {
    names = append(names, `'`+v+`'`)   // single-quote wrapping, NO parameterization
}
subQuery := fmt.Sprintf("SELECT project_id FROM project where name IN (%s)", strings.Join(names, ","))
// ...
return qs.FilterRaw("project_id", fmt.Sprintf("IN (%s)", subQuery))

// Compare: project.go:214 (uses orm.QuoteLiteral -- the safe pattern)
return qs.FilterRaw("owner_id", fmt.Sprintf("IN (SELECT user_id FROM harbor_user WHERE username = %s)", orm.QuoteLiteral(username)))
```

Note: `FilterByOwner` at line 214 correctly uses `orm.QuoteLiteral(username)` for the same type of string interpolation. `FilterByNames` does not.

## Reproduction Steps

1. (Currently blocked by name regex) Create a project with name containing SQL metacharacter
2. Create a robot account scoped to that project
3. Authenticate with robot account JWT
4. Call `GET /api/v2.0/repositories` or `GET /api/v2.0/projects`
5. `FilterByNames` would execute injected SQL payload
6. Recommended fix: replace `'`+v+`'` concatenation with `orm.QuoteLiteral(v)` or use `orm.ParamPlaceholderForIn` with parameterized query
