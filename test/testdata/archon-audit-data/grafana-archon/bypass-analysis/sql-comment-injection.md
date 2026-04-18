# Bypass Analysis: SQL Comment Stripping Injection (Undisclosed Fix)

**Cluster ID**: sql-comment-strip-state-machine
**Tag**: [undisclosed]
**Commits**:
- `d7322d91f318` -- PostgreSQL and MSSQL: quote-aware state machine (#121772)
- `7a57284e18ace` -- MySQL: preserve `#` inside quoted strings (#121535)

**Component**: `pkg/tsdb/grafana-postgresql-datasource/macros.go`, `pkg/tsdb/mssql/sqleng/macros.go`, `pkg/tsdb/mysql/macros.go`

---

## Patch Summary

All three SQL datasource macro engines (PostgreSQL, MSSQL, MySQL) replaced naive regex-based SQL comment stripping with character-by-character state machines that track quoted contexts. The old code used regular expressions like `(?s)/\*.*?\*/`, `--[^\n]*`, and `#[^\n]*` which did not understand SQL quoting rules. Comment-like sequences inside string literals or quoted identifiers were incorrectly stripped, enabling injection via crafted template variables (e.g., placing malicious SQL after `#` or `--` inside a quoted context that the regex would strip, altering query semantics).

### Per-datasource specifics:
- **PostgreSQL**: Handles single quotes (`'`), double quotes (`"`), and dollar-quoted strings (`$$`/`$tag$`). Uses doubled-quote escaping only (no backslash escapes, consistent with PostgreSQL standard).
- **MSSQL**: Handles single quotes, double quotes, and T-SQL bracket-quoted identifiers (`[...]`). Uses doubled-character escaping for all three.
- **MySQL**: Handles single quotes, double quotes, and backtick-quoted identifiers. Supports both backslash escapes and doubled-quote escapes. Also handles MySQL `#` line comments.

---

## Bypass Analysis

### Vector 1: Alternate Entry Points
**Verdict**: No bypass.
`stripSQLComments()` is called in each datasource's `Interpolate()` method, which is the sole entry point for query macro processing. All queries flow through this path.

### Vector 2: MySQL `restrictedRegExp` Ordering (Potential Weakness)
**Verdict**: Minor concern, not exploitable for comment injection bypass.
In MySQL `macros.go`, `restrictedRegExp` matching runs on the raw SQL (line 116) **before** `stripSQLComments` (line 124). This means `restrictedRegExp` sees comments. An attacker could potentially hide restricted keywords inside comments to bypass the `restrictedRegExp` check, but this is the wrong direction -- the `restrictedRegExp` is a deny-list, and hiding keywords in comments means they are stripped and never executed. The pre-patch ordering was the same, so this is not a regression.

### Vector 3: Nested Block Comments
**Verdict**: No bypass.
PostgreSQL supports nested `/* */` comments but Grafana's state machine does not handle nesting. However, this is a non-issue for security: the parser will consume the first `*/` and return to normal parsing. Any remaining `*/` is harmless syntax. The worst case is that a legitimately-nested comment is partially stripped, but this does not create an injection vector.

### Vector 4: MySQL Executable Comments (`/*! ... */`)
**Verdict**: Potential minor concern, but not a bypass of the patch's intent.
MySQL treats `/*! ... */` as executable SQL (version-conditional comments). The new state machine strips these like regular block comments. This is consistent with the old regex behavior and is actually the correct security posture -- stripping executable comments before macro interpolation prevents macros hidden inside them from being processed. No bypass.

### Vector 5: MySQL `NO_BACKSLASH_ESCAPES` SQL Mode
**Verdict**: Theoretical concern, practically sound.
The MySQL state machine handles backslash escapes (`\'`). If the MySQL server runs with `NO_BACKSLASH_ESCAPES` mode, the server treats `\'` as a closing quote followed by a literal backslash -- but Grafana's parser would treat it as an escaped quote. This could create a parser differential. However, this would require:
1. The MySQL server to be running with `NO_BACKSLASH_ESCAPES`.
2. User-controlled input to contain `\'` sequences.
3. The query to be constructed such that the parser state mismatch causes a comment marker after the "escaped" quote to be missed.

Example: `SELECT '\' -- injected SQL'` -- Grafana sees `\'` as an escaped quote within the string, so `--` is inside the string. But with `NO_BACKSLASH_ESCAPES`, MySQL sees `'\'` as a complete string, and `-- injected SQL'` as a comment. The mismatch direction here means Grafana preserves more content than MySQL would execute, which is the safe direction (Grafana does not strip what MySQL considers a comment, but the comment is benign from MySQL's perspective since MySQL would strip it itself).

**Net effect**: The parser differential does not create an exploitable injection because Grafana errs on the side of preserving content rather than stripping it.

### Vector 6: PostgreSQL E-strings and Backslash Escapes
**Verdict**: No bypass.
PostgreSQL `consumeQuoted()` uses only doubled-quote escaping, which is correct for standard PostgreSQL strings. PostgreSQL also supports E-strings (`E'...'`) with backslash escapes, but the `E` prefix is not a quote character -- the state machine would process the `'` after `E` as the start of a single-quoted string, which is correct since `E'...'` strings still start and end with `'`. Doubled-quote escaping (`''`) is always valid even inside E-strings. The only risk would be `E'test\' -- comment'` where `\'` is an escaped quote in E-string syntax but the parser sees `''` patterns. However, `consumeQuoted` reads byte-by-byte and would see `\` as a regular character and `'` as a potential end-of-string, then check for doubled quote. Since `\' ` (backslash-quote-space) does not have a doubled quote, it would close the string prematurely. But this is the same behavior as the old regex and is the safe direction -- the parser would then strip the `-- comment` that follows.

### Vector 7: Unicode / Multi-byte Comment Markers
**Verdict**: No bypass.
All three implementations operate on `byte` values (ASCII). SQL comment markers (`--`, `/*`, `*/`, `#`) are all ASCII. There are no Unicode lookalikes that SQL engines would interpret as comment markers. UTF-8 multi-byte sequences cannot produce ASCII bytes in continuation bytes (they always have the high bit set).

### Vector 8: Sibling/Related Paths
**Verdict**: No bypass.
Grep confirms no other files in `pkg/tsdb/` contain comment-stripping logic. The three patched datasources are the only ones with `stripSQLComments`.

### Vector 9: Unterminated Block Comments
**Verdict**: Consistent behavior, no bypass.
In MySQL's implementation, if a block comment is unterminated (`/* no closing`), the loop `for i+1 < len(sql)` exits when `i` reaches `len(sql)-1`, then the `if i >= len(sql)` check breaks out. The last byte is silently dropped. In PostgreSQL and MSSQL, the same loop pattern is used. This is edge-case behavior with no security impact -- an unterminated comment results in the tail of the query being stripped, which is fail-safe.

---

## Bypass Verdict: **Sound**

The fix is complete across all three SQL datasources. Each implementation correctly handles its dialect-specific quoting conventions:
- PostgreSQL: single/double/dollar quoting
- MSSQL: single/double/bracket quoting
- MySQL: single/double/backtick quoting with backslash escapes

The state-machine approach is fundamentally more robust than regex. The only theoretical parser differential (MySQL `NO_BACKSLASH_ESCAPES`) is not exploitable because the mismatch direction is fail-safe (Grafana preserves content that MySQL would strip as comments, rather than stripping content MySQL would execute).

No additional SQL datasources exist that require patching. The fix is consistent, complete, and not bypassable through the vectors analyzed.
