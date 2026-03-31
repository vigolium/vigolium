Phase: 10
Sequence: 045
Slug: sql-expression-into-dumpfile-binary-write
Verdict: VALID
Rationale: SELECT INTO DUMPFILE shares the identical *sqlparser.Into allowlist entry and db.go execution context as INTO OUTFILE; it writes raw binary data without field/line terminators, enabling ELF binary or shared library injection.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-sql-expression-into-outfile-file-write.md
Origin-Pattern: AP-040

## Summary

The SQL Expression Engine allowlist at `parser_allow.go:113` permits the `*sqlparser.Into` AST node unconditionally. This covers both `INTO OUTFILE` (confirmed exploited, p8-040) and `INTO DUMPFILE` as both variants parse to the same `*sqlparser.Into` node. `INTO DUMPFILE` writes a single row as raw binary without MySQL field/line terminators, making it specifically suited to writing binary payloads such as ELF binaries, shared libraries (`.so` files), or other structured binary formats. The same 4-control failure chain applies: (1) allowlist bypass via UNION syntax, (2) `IsReadOnly:true` bypassed via `Into.IsReadOnly()` delegation to child SELECT, (3) `WithDisableFileWrites(true)` never called, (4) `secure_file_priv` defaults to `""`.

The attack flow for binary write: `SELECT UNHEX('<hex-elf-bytes>') FROM A UNION SELECT UNHEX('<hex-elf-bytes>') FROM A INTO DUMPFILE '/tmp/malicious.so'`, which writes a raw binary without terminators. A follow-up `SELECT ... INTO OUTFILE` can write an `/etc/ld.so.preload` entry or a cron job calling `LD_PRELOAD=/tmp/malicious.so`.

## Location

- **Primary**: `pkg/expr/sql/parser_allow.go:113` -- `case *sqlparser.Into: return` (covers both OUTFILE and DUMPFILE variants)
- **Secondary**: `pkg/expr/sql/db.go:71` -- `mysql.NewContext()` missing `WithDisableFileWrites(true)`
- **Secondary**: `pkg/expr/sql/db.go:82-84` -- `IsReadOnly: true` ineffective for Into node
- **Secondary**: `pkg/expr/sql/db.go:76-77` -- `secure_file_priv` commented out, default `""`
- **Engine**: go-mysql-server `rowexec/rel.go` -- `buildInto` checks `n.Dumpfile != ""` and writes raw bytes via `os.OpenFile`
- **Entry point**: `pkg/api/api.go:521` -- `POST /api/ds/query` (Viewer role)
- **Feature gate**: `pkg/expr/nodes.go:128` -- `toggles.IsEnabledGlobally(FlagSqlExpressions)`

## Attacker Control

- **Input**: SQL expression string in POST /api/ds/query request body
- **Payload construction**: UNION syntax required to bypass allowlist: `SELECT UNHEX('<hex>') FROM A UNION SELECT UNHEX('<hex>') FROM A INTO DUMPFILE '/path/to/binary'`
- **Content control**: Attacker fully controls file path and binary content; `UNHEX()` function allows arbitrary binary data (hex-encoded); `CHAR()` and `FROM_BASE64()` are also allowlisted for content encoding
- **Minimum privilege**: Viewer role (`datasources:query` permission)
- **Key difference from OUTFILE**: DUMPFILE writes exactly one row as raw bytes with no terminators, making it suitable for binary files (ELF, shared libraries) where terminators would corrupt the binary format

## Trust Boundary Crossed

Viewer-role user SQL expression execution context -> OS filesystem binary write capability. The go-mysql-server engine runs in-process sharing the Grafana OS process context. A Viewer crosses from data query privilege to OS-level binary file write as the Grafana service user.

## Impact

- **Shared library injection**: Write a malicious `.so` file to a writable path, then write `/etc/ld.so.preload` (via INTO OUTFILE) to cause RCE on next process spawn that loads shared libraries
- **ELF binary drop**: Write a setuid-capable binary if the OS/filesystem supports it
- **Binary configuration file overwrite**: Write structured binary config files (e.g., compiled PAM modules if writable)
- **Cron binary**: Write to `/usr/local/bin/` if writable, then arrange execution
- **Scope**: Same as p8-040 -- global when `sqlExpressions` flag enabled

## Evidence

1. `parser_allow.go:113`: `case *sqlparser.Into: return` -- unconditionally allows both OUTFILE and DUMPFILE variants (same AST node type)
2. `go-mysql-server/sql/planbuilder/dml.go:678-680`: planbuilder checks `into.Dumpfile != ""` to create `plan.NewInto(inScope.node, nil, "", into.Dumpfile)` -- both variants use `*plan.Into`
3. `go-mysql-server/sql/rowexec/rel.go:599-601`: `ctx.DisableFileWrites()` returns `false` (never set) -- guard bypassed for DUMPFILE as well as OUTFILE
4. `go-mysql-server/sql/rowexec/rel.go:604`: `secure_file_priv` defaults to `""` -- no path restriction
5. `go-mysql-server/sql/rowexec/rel.go:659-673`: `buildInto` handles Dumpfile separately from Outfile, writes raw bytes without any field/line terminators
6. `security/real-env-evidence/sql-expression-into-outfile-file-write/repro_test.go:35-45`: TestAllowQueryPermitsIntoDumpfile confirms `INTO DUMPFILE` passes the allowlist
7. `security/probe-workspace/sql-plugin-renderer/round-1-hypotheses.md:85`: PH-05 explicitly identifies INTO DUMPFILE as confirmed same code path

## Reproduction Steps

1. Enable `sqlExpressions` feature flag
2. As a Viewer-role user, send:
   ```
   POST /api/ds/query HTTP/1.1
   Content-Type: application/json

   {
     "queries": [
       {
         "refId": "A",
         "datasource": {"type": "testdata", "uid": "<uid>"},
         "scenarioId": "csv_content",
         "csvContent": "col\n41424344"
       },
       {
         "refId": "B",
         "datasource": {"type": "__expr__", "uid": "__expr__"},
         "type": "sql",
         "expression": "SELECT UNHEX('7f454c46') FROM A UNION SELECT UNHEX('7f454c46') FROM A INTO DUMPFILE '/tmp/grafana-poc-elf.bin'"
       }
     ],
     "from": "now-1h",
     "to": "now"
   }
   ```
3. Verify: `xxd /tmp/grafana-poc-elf.bin` shows raw bytes without any tab/newline terminators
4. For LD_PRELOAD escalation: write a malicious `.so` to a writable path via DUMPFILE, then write `/etc/ld.so.preload` content via OUTFILE
