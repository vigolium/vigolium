Phase: 10
Sequence: 042
Slug: sql-injection-blob-filterbyartifactdigest
Verdict: VALID
Rationale: FilterByArtifactDigest and FilterByArtifactDigests in blob/models/blob.go concatenate string values with literal single-quotes directly into a FilterRaw SQL subquery with no parameterization, sharing the same unsafe fmt.Sprintf+FilterRaw pattern as p7-003; although digest values are currently validated by opencontainers/go-digest format, the structural vulnerability is present.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p7-003-sql-injection-fmt-sprintf.md
Origin-Pattern: AP-007

## Summary

`FilterByArtifactDigest` and `FilterByArtifactDigests` in `src/pkg/blob/models/blob.go:131` and `146` build SQL subqueries by wrapping string values in literal single-quotes without using parameterized queries or `orm.QuoteLiteral`:

```go
sql := fmt.Sprintf("IN (SELECT digest_blob FROM artifact_blob WHERE digest_af IN (%s))", `'`+v+`'`)
```

This is the same anti-pattern documented in p7-003. Digest strings (`sha256:...`) are currently gated by `opencontainers/go-digest.Parse()` which enforces `algorithm:hex` format. However, the SQL construction is structurally unsafe. Any future code path that passes a non-validated string to the `artifactDigest` keyword (bypassing digest format validation) would produce exploitable SQL injection.

## Location

- `src/pkg/blob/models/blob.go:131` -- `FilterByArtifactDigest`
- `src/pkg/blob/models/blob.go:143-146` -- `FilterByArtifactDigests`

## Attacker Control

Current: INDIRECT. Digest values are content-addressed SHA256 hashes validated by `go-digest.Parse()` before reaching these functions. The `algorithm:hex` format constraint blocks SQL metacharacters.

Risk: If `artifactDigest` keyword is used with an unvalidated string (e.g., from a new code path, config file, or replication adapter that skips digest validation), the single-quote concatenation becomes exploitable.

## Trust Boundary Crossed

- TB-3 (Core API to PostgreSQL)

## Impact

- Confidentiality: UNION-based extraction from arbitrary DB tables
- Integrity: modification of blob/artifact association records
- Regression risk: mirrors the pattern that caused CVE-2024-22261 in Harbor

## Evidence

```go
// src/pkg/blob/models/blob.go:131
func (b *Blob) FilterByArtifactDigest(..., value any) orm.QuerySeter {
    v, ok := value.(string)
    // ...
    sql := fmt.Sprintf("IN (SELECT digest_blob FROM artifact_blob WHERE digest_af IN (%s))", `'`+v+`'`)
    return qs.FilterRaw("digest", sql)   // SINK: FilterRaw with user-controlled string
}

// src/pkg/blob/models/blob.go:143-146
func (b *Blob) FilterByArtifactDigests(..., value any) orm.QuerySeter {
    // ...
    for _, v := range artifactDigests {
        afs = append(afs, `'`+v+`'`)    // single-quote wrapping, no parameterization
    }
    sql := fmt.Sprintf("IN (SELECT digest_blob FROM artifact_blob WHERE digest_af IN (%s))", strings.Join(afs, ","))
    return qs.FilterRaw("digest", sql)
}
```

## Reproduction Steps

1. (Currently blocked by go-digest format validation) Supply a digest string containing SQL metacharacters
2. Trigger a blob list operation that uses `artifactDigest` or `artifactDigests` keyword
3. `FilterByArtifactDigest(s)` would execute injected SQL payload
4. Recommended fix: use `orm.QuoteLiteral(v)` or `orm.ParamPlaceholderForIn` with actual query parameters instead of single-quote string concatenation
