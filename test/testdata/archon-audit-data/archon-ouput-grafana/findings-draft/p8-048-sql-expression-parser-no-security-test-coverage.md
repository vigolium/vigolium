Phase: 10
Sequence: 048
Slug: sql-expression-parser-no-security-test-coverage
Verdict: VALID
Rationale: The SQL expression allowlist test suite (parser_allow_test.go) has zero test cases verifying that INTO OUTFILE and INTO DUMPFILE are blocked; combined with the confirmed bypass, any future partial fix (e.g., adding INTO to a deny list) could be silently regressed without test detection.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-sql-expression-into-outfile-file-write.md
Origin-Pattern: AP-040

## Summary

The SQL expression parser allowlist (`parser_allow.go`) has a companion test file (`parser_allow_test.go`) that contains 15 positive test cases (queries that should be allowed) and zero negative test cases verifying that dangerous SQL constructs are rejected. The only negative security test exists in `service_sql_test.go` and covers only the `load_file()` function (which is blocked because it is not in the allowed function list). There are no tests verifying that:

1. `SELECT ... INTO OUTFILE` is rejected
2. `SELECT ... INTO DUMPFILE` is rejected
3. The UNION-based bypass `SELECT ... FROM A UNION SELECT ... FROM A INTO OUTFILE` is rejected
4. Other dangerous constructs (INSERT, UPDATE, DELETE, SET, CALL) are rejected

This is a structural variant of the AP-040 pattern because:
- The confirmed vulnerability (p8-040) exists partly because no test enforced correct behavior of the `*sqlparser.Into` allowlist entry
- Any remediation that adds a security check without adding tests is fragile
- The absence of negative tests is itself a security control failure that enables future regressions of any fix applied

The `db_test.go` file does not test any security boundary -- all tests are happy-path query execution tests.

## Location

- **Primary**: `pkg/expr/sql/parser_allow_test.go` -- 15 positive test cases, 0 negative security test cases
- **Secondary**: `pkg/expr/service_sql_test.go:81-99` -- only security test covers `load_file` blocking, not INTO OUTFILE/DUMPFILE
- **Missing coverage**:
  - No test for `INTO OUTFILE` being blocked
  - No test for `INTO DUMPFILE` being blocked
  - No test for UNION-based `INTO OUTFILE` bypass being blocked
  - No test for `INSERT`, `UPDATE`, `DELETE`, `SET`, `CALL`, `CREATE PROCEDURE` being blocked (these fall to `default: return false` but are untested)
- **Related**: `pkg/expr/sql/db_test.go` -- pure happy-path tests, no security boundary tests

## Attacker Control

This is a test coverage gap finding, not a directly exploitable vulnerability. However, the absence of security tests:
- Allows the existing vulnerability (p8-040) to persist undetected in automated CI
- Means a developer could add `case *sqlparser.Into: return` to a deny list but misspell it, and CI would not catch it
- Enables regression of any fix: if a future commit modifies the allowlist to fix p8-040, there is no test that will fail if the fix is incomplete or incorrect

## Trust Boundary Crossed

Development/CI boundary: Security controls exist in production code but are not verified by the test suite. A fix applied without tests could be silently regressed in a future PR.

## Impact

- **Regression risk**: Any future fix for p8-040/p8-045 can be silently regressed
- **Coverage gap**: The CI pipeline would not catch reintroduction of INTO OUTFILE/DUMPFILE exploitability
- **Missing test categories**: No negative tests for DML (INSERT/UPDATE/DELETE), DDL (CREATE TABLE/PROCEDURE/FUNCTION), TCL (BEGIN/COMMIT/ROLLBACK), or administrative (SET, FLUSH, RESET) statements

## Evidence

1. `parser_allow_test.go`: All 15 test cases are positive (expected `err: nil`); no negative test cases
2. `service_sql_test.go:81-99`: Only negative test is for `load_file()` function; no test for `INTO OUTFILE` or `INTO DUMPFILE`
3. `db_test.go`: Zero security boundary tests -- all tests verify correct query execution behavior
4. `parser_allow.go:113`: `case *sqlparser.Into: return` -- the confirmed vulnerable allowlist entry has no corresponding negative test
5. No test anywhere in the codebase runs `AllowQuery` with `INTO OUTFILE` and asserts it returns `false`

## Reproduction Steps

Run the test suite:
```
go test ./pkg/expr/sql/... -v -run TestAllowQuery
```
Observe that all test cases pass. Then observe that no test case with `INTO OUTFILE`, `INTO DUMPFILE`, or UNION-based `INTO OUTFILE` exists. The confirmed exploit from p8-040 would pass `AllowQuery` in any test context, with no test detecting this.
