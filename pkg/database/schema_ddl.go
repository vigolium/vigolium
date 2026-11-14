package database

// Schema DDL: one source, rendered per dialect.
//
// Hoisted out of CreateSchema so the names in it can be READ without executing
// it. SchemaReady needs to know which tables and indexes a current database is
// supposed to have, and the only trustworthy source for that is the same list
// CreateSchema applies. Keeping a second list beside it would drift on the first
// schema change and turn a missing table into a silently accepted one, which is
// exactly the failure the readiness check exists to prevent.
//
// Every statement is a TEMPLATE: a column whose spelling differs between SQLite
// and Postgres names its type with a token ({{AUTOINC_PK}}, {{BLOB}}, {{BOOL}},
// {{TRUE}}/{{FALSE}}, {{TIMESTAMP}}, {{JSON}}, {{FLOAT}}) and renderDDL spells it
// for the driver. This replaced string-rewriting SQLite DDL into Postgres, which
// matched column declarations by their exact text: a bool column whose
// declaration did not match a rewrite pattern reached Postgres as INTEGER, and
// every bool write to it failed there (chain_truncated did, for a while). With
// explicit tokens a column's dialect-sensitive type is declared at the column,
// and tests render both dialects (no server needed) to check that no
// SQLite-only token reaches Postgres and that both create the same catalog.
//
// Tables, column migrations and indexes all render through renderDDL — see
// schemaDDLStatements, the full ordered list CreateSchema issues.

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ddlTokens is every type token a schema template may use and how each dialect
// spells it. A token missing here would reach the server verbatim; the render
// tests reject any "{{" left in either dialect's output.
//
// Choices worth knowing before changing one:
//   - {{AUTOINC_PK}} is SERIAL (int4), not BIGSERIAL: existing Postgres stores
//     have int4 ids and INTEGER finding_id references, and a new store should
//     not get a different catalog from an old one.
//   - {{JSON}} is TEXT in both: queries compare JSON columns with the empty string and LIKE,
//     and cast to jsonb where they need JSON semantics; a jsonb column would
//     reject the empty string bun writes for a zero value. The token records
//     intent (and is cross-checked against the models' type:jsonb fields).
//   - {{FLOAT}} is DOUBLE PRECISION: Postgres REAL is 4 bytes, SQLite REAL is 8.
//   - {{BOOL}} is INTEGER 0/1 in SQLite (its only boolean) and BOOLEAN in
//     Postgres, which refuses to write a Go bool into an INTEGER column.
var ddlTokens = []struct{ token, sqlite, postgres string }{
	{"{{AUTOINC_PK}}", "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"},
	{"{{BLOB}}", "BLOB", "BYTEA"},
	{"{{BOOL}}", "INTEGER", "BOOLEAN"},
	{"{{TRUE}}", "1", "TRUE"},
	{"{{FALSE}}", "0", "FALSE"},
	{"{{TIMESTAMP}}", "TIMESTAMP", "TIMESTAMP"},
	{"{{JSON}}", "TEXT", "TEXT"},
	{"{{FLOAT}}", "REAL", "DOUBLE PRECISION"},
}

// ddlRenderers holds one replacer per dialect, built once from ddlTokens.
var ddlRenderers = sync.OnceValue(func() map[string]*strings.Replacer {
	lite := make([]string, 0, 2*len(ddlTokens))
	pg := make([]string, 0, 2*len(ddlTokens))
	for _, t := range ddlTokens {
		lite = append(lite, t.token, t.sqlite)
		pg = append(pg, t.token, t.postgres)
	}
	return map[string]*strings.Replacer{
		driverSQLite:   strings.NewReplacer(lite...),
		driverPostgres: strings.NewReplacer(pg...),
	}
})

// renderDDL spells one schema template for driver. Any driver other than
// Postgres gets the SQLite spelling, as every non-Postgres handle is SQLite.
func renderDDL(driver, tmpl string) string {
	if driver != driverPostgres {
		driver = driverSQLite
	}
	return ddlRenderers()[driver].Replace(tmpl)
}

// columnMigrationDDL is the template that adds one migrated column.
func columnMigrationDDL(m columnMigration) string {
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", m.Table, m.Column, m.Def)
}

// schemaDDLStatements renders, for driver, every DDL statement CreateSchema
// issues, in the order it issues them: tables, column migrations, indexes, then
// the deferrable http_records indexes.
func schemaDDLStatements(driver string) []string {
	out := make([]string, 0, len(schemaTables)+len(columnMigrations)+len(schemaIndexes)+len(recordSecondaryIndexes))
	for _, ddl := range schemaTables {
		out = append(out, renderDDL(driver, ddl))
	}
	for _, m := range columnMigrations {
		out = append(out, renderDDL(driver, columnMigrationDDL(m)))
	}
	for _, ddl := range schemaIndexes {
		out = append(out, renderDDL(driver, ddl))
	}
	for _, ddl := range recordSecondaryIndexes {
		out = append(out, renderDDL(driver, ddl))
	}
	return out
}

// boolColumn is a column the templates declare {{BOOL}}, with its default.
type boolColumn struct {
	Table, Column string
	Default       bool
}

// boolColumnLine matches a {{BOOL}} column declaration inside a CREATE TABLE
// template; boolDefault reads its default.
var (
	boolColumnLine = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+) \{\{BOOL\}\}(.*)$`)
	boolDefault    = regexp.MustCompile(`DEFAULT \{\{(TRUE|FALSE)\}\}`)
)

// schemaBoolColumns lists every {{BOOL}} column, parsed from the templates so
// the legacy Postgres conversion (convertLegacyBoolColumns) can never miss one
// the schema declares. Tables first, then column migrations; each column once.
var schemaBoolColumns = sync.OnceValue(func() []boolColumn {
	var out []boolColumn
	seen := map[string]bool{}
	add := func(table, column, rest string) {
		if seen[table+"."+column] {
			return
		}
		seen[table+"."+column] = true
		m := boolDefault.FindStringSubmatch(rest)
		out = append(out, boolColumn{Table: table, Column: column, Default: m != nil && m[1] == "TRUE"})
	}
	pattern := regexp.MustCompile(ddlObjectPattern)
	for _, ddl := range schemaTables {
		name := pattern.FindStringSubmatch(ddl)
		if name == nil {
			continue
		}
		for _, m := range boolColumnLine.FindAllStringSubmatch(ddl, -1) {
			add(name[1], m[1], m[2])
		}
	}
	for _, m := range columnMigrations {
		if rest, ok := strings.CutPrefix(m.Def, "{{BOOL}}"); ok {
			add(m.Table, m.Column, rest)
		}
	}
	return out
})

// schemaTables is every CREATE TABLE this binary expects, in dependency order.
var schemaTables = []string{
	// Schema versioning: lets CreateSchema skip one-time O(rows) backfills once
	// a database is current (see currentSchemaVersion), and carries the
	// compatibility guard's reader floor (see schema_guard.go). Single row, id
	// always 1.
	`CREATE TABLE IF NOT EXISTS schema_meta (
		id INTEGER PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		min_reader_version INTEGER NOT NULL DEFAULT 1,
		written_by TEXT,
		updated_at {{TIMESTAMP}},
		observation_history_since {{TIMESTAMP}}
	)`,
	// Multi-tenancy: users and projects
	`CREATE TABLE IF NOT EXISTS users (
		uuid TEXT PRIMARY KEY NOT NULL,
		email TEXT,
		name TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS projects (
		uuid TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		owner_uuid TEXT,
		config_path TEXT,
		tags {{JSON}},
		default_target TEXT,
		last_scan_at {{TIMESTAMP}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS scans (
		uuid TEXT PRIMARY KEY NOT NULL,
		project_uuid TEXT NOT NULL,
		name TEXT,
		description TEXT,
		status TEXT NOT NULL DEFAULT 'running',
		target TEXT,
		modules TEXT,
		threads INTEGER DEFAULT 0,
		scope_origin_mode TEXT,
		profile TEXT,
		source_path TEXT,
		source_type TEXT,
		tags {{JSON}},
		triggered_by TEXT,
		agentic_scan_uuid TEXT,
		http_record_uuid TEXT,
		scan_source TEXT,
		scan_mode TEXT,
		start_cursor_at {{TIMESTAMP}},
		start_cursor_uuid TEXT,
		cursor_at {{TIMESTAMP}},
		cursor_uuid TEXT,
		processed_count INTEGER DEFAULT 0,
		started_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		finished_at {{TIMESTAMP}},
		duration_ms INTEGER DEFAULT 0,
		total_requests INTEGER DEFAULT 0,
		total_findings INTEGER DEFAULT 0,
		critical_count INTEGER DEFAULT 0,
		high_count INTEGER DEFAULT 0,
		medium_count INTEGER DEFAULT 0,
		low_count INTEGER DEFAULT 0,
		info_count INTEGER DEFAULT 0,
		suspect_count INTEGER DEFAULT 0,
		error_message TEXT,
		storage_url TEXT,
		completeness TEXT,
		stop_reason TEXT,
		phase_outcomes {{JSON}},
		plan {{JSON}},
		heartbeat_at {{TIMESTAMP}},
		current_phase TEXT,
		pid INTEGER,
		runner_host TEXT,
		module_errors {{JSON}},
		extensions_failed {{JSON}},
		module_stats {{JSON}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS http_records (
		uuid TEXT PRIMARY KEY NOT NULL,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		scheme TEXT NOT NULL,
		hostname TEXT NOT NULL,
		port INTEGER NOT NULL,
		ip TEXT,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		url TEXT NOT NULL,
		http_version TEXT NOT NULL,
		request_content_type TEXT,
		request_content_length INTEGER DEFAULT 0,
		raw_request {{BLOB}},
		request_hash TEXT NOT NULL,
		request_authorization TEXT,
		status_code INTEGER DEFAULT 0,
		status_phrase TEXT,
		response_http_version TEXT,
		response_content_type TEXT,
		response_content_length INTEGER DEFAULT 0,
		raw_response {{BLOB}},
		response_hash TEXT,
		response_norm_hash TEXT,
		response_time_ms INTEGER DEFAULT 0,
		response_words INTEGER DEFAULT 0,
		has_response {{BOOL}} NOT NULL DEFAULT {{FALSE}},
		response_title TEXT,
		response_location TEXT,
		parameters {{JSON}},
		sent_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		received_at {{TIMESTAMP}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		source TEXT DEFAULT '',
		technology {{JSON}},
		content_hash TEXT,
		is_authenticated {{BOOL}} NOT NULL DEFAULT {{FALSE}},
		parent_uuid TEXT,
		target TEXT,
		root_uuid TEXT,
		chain_truncated {{BOOL}} NOT NULL DEFAULT {{FALSE}},
		remarks {{JSON}},
		risk_score INTEGER DEFAULT 0,
		surface_score INTEGER DEFAULT 0,
		body_compaction {{JSON}}
	)`,
	`CREATE TABLE IF NOT EXISTS analysis_artifacts (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		http_record_uuid TEXT NOT NULL,
		kind TEXT NOT NULL,
		filename TEXT,
		media_type TEXT,
		sha256 TEXT NOT NULL,
		byte_length INTEGER NOT NULL,
		content {{BLOB}} NOT NULL,
		metadata {{JSON}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		http_record_uuids {{JSON}} NOT NULL,
		scan_uuid TEXT,
		agentic_scan_uuid TEXT,
		url TEXT,
		hostname TEXT,
		module_id TEXT NOT NULL,
		module_name TEXT NOT NULL,
		module_type TEXT DEFAULT '',
		finding_source TEXT DEFAULT '',
		record_kind TEXT NOT NULL DEFAULT 'finding',
		evidence_grade TEXT DEFAULT '',
		module_short TEXT DEFAULT '',
		description TEXT,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL DEFAULT 'firm',
		tags {{JSON}},
		status TEXT DEFAULT 'triaged',
		status_note TEXT,
		status_actor TEXT,
		status_updated_at {{TIMESTAMP}},
		remediation TEXT,
		cwe_id TEXT,
		cvss_score {{FLOAT}} DEFAULT 0,
		source_file TEXT,
		repo_name TEXT,
		matched_at {{JSON}},
		extracted_results {{JSON}},
		additional_evidence {{JSON}},
		request TEXT,
		response TEXT,
		origin_record_uuid TEXT,
		insertion_point {{JSON}},
		payload TEXT,
		verification {{JSON}},
		verified_at {{TIMESTAMP}},
		finding_hash TEXT NOT NULL,
		found_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen_at {{TIMESTAMP}}
	)`,
	// Schema v6: a finding hash that no longer names a row — a pre-v6 content
	// hash re-keyed to identity v2, or a duplicate folded into a survivor —
	// mapped to the finding that absorbed it, so old hashes keep resolving.
	`CREATE TABLE IF NOT EXISTS finding_hash_aliases (
		project_uuid TEXT NOT NULL,
		alias_hash TEXT NOT NULL,
		finding_id INTEGER NOT NULL,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS finding_records (
		finding_id INTEGER NOT NULL,
		record_uuid TEXT NOT NULL,
		PRIMARY KEY (finding_id, record_uuid)
	)`,
	// One row per (finding, scan that observed it). findings.scan_uuid only
	// names the MOST RECENT observer — a re-detection overwrites it — so "was
	// this finding seen by scan A" and "which findings are new in scan B" are
	// unanswerable from the findings row alone. Written in the same transaction
	// as the finding save (insert and re-detection alike); keyed so a repeat
	// within one scan is idempotent. finding_hash is denormalized so a diff can
	// compare two scans by hash without joining back through ids that differ
	// across merged stores. Rows from before schema v3 are a one-time backfill
	// of (scan_uuid, found_at); schema_meta.observation_history_since marks
	// where complete history starts.
	// Dynamic-assessment coverage ledger (ECON-4): one row per (scan, record)
	// saying which module tiers / modules finished on it, so a curtailed scan
	// resumes and tiered passes skip finished records.
	`CREATE TABLE IF NOT EXISTS scan_record_progress (
		scan_uuid TEXT NOT NULL,
		record_uuid TEXT NOT NULL,
		project_uuid TEXT NOT NULL,
		tier_done SMALLINT NOT NULL DEFAULT -1,
		passive_done {{BOOL}} NOT NULL DEFAULT {{FALSE}},
		timed_out INTEGER NOT NULL DEFAULT 0,
		done_bits {{BLOB}},
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (scan_uuid, record_uuid)
	)`,
	`CREATE TABLE IF NOT EXISTS finding_observations (
		project_uuid TEXT NOT NULL,
		finding_id INTEGER NOT NULL,
		finding_hash TEXT NOT NULL,
		scan_uuid TEXT NOT NULL,
		observed_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (finding_id, scan_uuid)
	)`,
	// Append-only lifecycle history: one row per status change. The findings
	// row carries the CURRENT verdict (status, status_note, status_actor,
	// status_updated_at); this table is the provenance behind it.
	`CREATE TABLE IF NOT EXISTS finding_status_events (
		id {{AUTOINC_PK}},
		finding_id INTEGER NOT NULL,
		project_uuid TEXT NOT NULL,
		from_status TEXT,
		to_status TEXT NOT NULL,
		note TEXT,
		actor TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS scopes (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		rule_type TEXT NOT NULL,
		host_pattern TEXT,
		path_pattern TEXT,
		content_type_pattern TEXT,
		methods {{JSON}},
		ports {{JSON}},
		schemes {{JSON}},
		priority INTEGER NOT NULL DEFAULT 100,
		enabled {{BOOL}} NOT NULL DEFAULT {{TRUE}},
		hit_count INTEGER DEFAULT 0,
		last_matched_at {{TIMESTAMP}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS oast_interactions (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		unique_id TEXT NOT NULL,
		full_id TEXT NOT NULL,
		protocol TEXT NOT NULL,
		q_type TEXT,
		raw_request TEXT,
		raw_response TEXT,
		remote_address TEXT,
		interacted_at {{TIMESTAMP}} NOT NULL,
		target_url TEXT,
		parameter_name TEXT,
		injection_type TEXT,
		module_id TEXT,
		finding_id INTEGER,
		payload TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// OAST payload context, keyed by the locally minted nonce. Lets a callback
	// that arrives out of band (a fixed OAST URL, `oast ingest`) be attributed
	// to the scan, module, target and parameter that planted it, after the
	// in-memory tracker of the planting process is gone.
	// Schema v6: interactsh sessions a scan kept open (oast.keep_session) so a
	// later `vigolium oast poll` or the server's poller collects late callbacks.
	// Key material is redacted from every export.
	`CREATE TABLE IF NOT EXISTS oast_sessions (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		server_url TEXT NOT NULL,
		correlation_id TEXT NOT NULL,
		secret_key TEXT,
		private_key TEXT,
		public_key TEXT,
		token TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_polled_at {{TIMESTAMP}},
		closed_at {{TIMESTAMP}}
	)`,
	`CREATE TABLE IF NOT EXISTS oast_payloads (
		nonce TEXT PRIMARY KEY NOT NULL,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		class TEXT,
		module_id TEXT,
		target_url TEXT,
		param TEXT,
		request_hash TEXT,
		payload TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS agentic_scans (
		id {{AUTOINC_PK}},
		uuid TEXT NOT NULL UNIQUE,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		mode TEXT NOT NULL,
		agent_name TEXT NOT NULL,
		input_raw TEXT,
		input_type TEXT,
		target_url TEXT,
		vuln_type TEXT,
		module_names {{JSON}},
		template_id TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		current_phase TEXT,
		phases_run {{JSON}},
		finding_count INTEGER DEFAULT 0,
		record_count INTEGER DEFAULT 0,
		saved_count INTEGER DEFAULT 0,
		source_path TEXT,
		source_type TEXT,
		token_usage {{JSON}},
		retry_count INTEGER DEFAULT 0,
		parent_run_uuid TEXT,
		input_record_count INTEGER DEFAULT 0,
		attack_plan TEXT,
		triage_result TEXT,
		prompt_sent TEXT,
		agent_raw_output TEXT,
		error_message TEXT,
		result_json TEXT,
		storage_url TEXT,
		session_id TEXT,
		session_dir TEXT,
		started_at {{TIMESTAMP}},
		completed_at {{TIMESTAMP}},
		duration_ms INTEGER DEFAULT 0,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS authentication_hostnames (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		hostname TEXT NOT NULL,
		session_name TEXT NOT NULL,
		session_role TEXT DEFAULT '',
		position INTEGER DEFAULT 0,
		session_token TEXT,
		headers {{JSON}},
		login_url TEXT,
		login_method TEXT,
		login_content_type TEXT,
		login_body TEXT,
		login_request TEXT,
		login_response TEXT,
		extract_rules {{JSON}},
		source TEXT DEFAULT '',
		hydrated_at {{TIMESTAMP}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// One row per (run, endpoint): what this scan observed about a HOST, as
	// opposed to about one exchange with it.
	//
	// Normalized rather than stored on http_records. The per-row objection
	// that keeps the full DNS answer off the record still stands — a sweep
	// writes several rows per host and a redirect chain alone is three, so
	// columns would hold many identical copies of one answer — but it is an
	// argument against DUPLICATING the answer, not against keeping it. Here
	// it is written once per endpoint per run and referenced by hostname and
	// port.
	//
	// Keyed by scan_uuid so a re-probe RECORDS a new observation instead of
	// overwriting the old one: "what did the host resolve to when we scanned
	// it in March" is a question a report has to be able to answer, and an
	// upsert keyed on hostname alone would destroy the answer every time the
	// host was scanned again. UNIQUE(scan_uuid, hostname, port) makes a
	// repeat within ONE run idempotent, which is the only case where
	// overwriting is correct.
	//
	// complete distinguishes a lookup that ran and found nothing from one
	// that was cut short (a cancelled or budget-limited prefetch). Without
	// it an empty answer is unreadable: "this host has no AAAA record" and
	// "we never got to this host" are different facts about the scan.
	`CREATE TABLE IF NOT EXISTS host_observations (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		hostname TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0,
		observed_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		dns_a {{JSON}},
		dns_aaaa {{JSON}},
		dns_cname {{JSON}},
		dns_mx {{JSON}},
		dns_ns {{JSON}},
		dns_txt {{JSON}},
		dns_soa {{JSON}},
		dns_caa {{JSON}},
		tls {{JSON}},
		fingerprint {{JSON}},
		not_found {{JSON}},
		favicon {{JSON}},
		complete {{BOOL}} NOT NULL DEFAULT {{FALSE}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_uuid, hostname, port)
	)`,
	`CREATE TABLE IF NOT EXISTS scan_logs (
		id {{AUTOINC_PK}},
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT NOT NULL,
		level TEXT NOT NULL,
		phase TEXT,
		message TEXT NOT NULL,
		metadata TEXT,
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// Durable autopilot: one row per bounded operator section (a Reset() +
	// reconstructed-brief cycle). Only written when autopilot_mode != legacy.
	`CREATE TABLE IF NOT EXISTS agent_sections (
		id {{AUTOINC_PK}},
		uuid TEXT NOT NULL UNIQUE,
		agentic_scan_uuid TEXT,
		project_uuid TEXT,
		seq INTEGER NOT NULL DEFAULT 0,
		kind TEXT,
		status TEXT NOT NULL DEFAULT 'running',
		task TEXT,
		closing_summary TEXT,
		rotation_reason TEXT,
		turn_count INTEGER NOT NULL DEFAULT 0,
		input_tokens INTEGER NOT NULL DEFAULT 0,
		output_tokens INTEGER NOT NULL DEFAULT 0,
		error_message TEXT,
		started_at {{TIMESTAMP}},
		ended_at {{TIMESTAMP}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// Durable autopilot: verify-before-promote candidates. Each proposed
	// finding lands here first (status=proposed), a fresh-context verifier
	// grades it, and confirmed ones are promoted into findings. Only
	// written when autopilot_mode != legacy. UNIQUE(agentic_scan_uuid,
	// dedup_hash) backs the ON CONFLICT dedup on SaveCandidate.
	`CREATE TABLE IF NOT EXISTS agent_finding_candidates (
		id {{AUTOINC_PK}},
		uuid TEXT NOT NULL UNIQUE,
		agentic_scan_uuid TEXT,
		project_uuid TEXT,
		section_uuid TEXT,
		title TEXT,
		severity TEXT,
		description TEXT,
		remediation TEXT,
		cwe_id TEXT,
		source_file TEXT,
		url TEXT,
		hostname TEXT,
		confidence TEXT,
		class TEXT,
		status TEXT NOT NULL DEFAULT 'proposed',
		verdict_reason TEXT,
		evidence_grade TEXT,
		record_uuids {{JSON}},
		oast_ids {{JSON}},
		request TEXT,
		response TEXT,
		dedup_hash TEXT NOT NULL DEFAULT '',
		promoted_finding_id INTEGER NOT NULL DEFAULT 0,
		tags {{JSON}},
		created_at {{TIMESTAMP}} NOT NULL DEFAULT CURRENT_TIMESTAMP,
		verified_at {{TIMESTAMP}}
	)`,
}

// schemaIndexes is every index this binary expects. Applied after the column
// migrations, since some of them reference columns added there.
var schemaIndexes = []string{
	"CREATE INDEX IF NOT EXISTS idx_scan_record_progress_project_scan ON scan_record_progress(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_project_record ON analysis_artifacts(project_uuid, http_record_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_scan ON analysis_artifacts(scan_uuid)",
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_artifacts_record_kind_hash ON analysis_artifacts(http_record_uuid, kind, sha256)",

	// -- host_observations --
	// The read is "what did this run see for this endpoint", issued once per
	// emitted record, so (project, scan, hostname, port) is the exact lookup.
	// The scan-less variant backs the fallback read for a caller that knows
	// the project but not which run to trust, which takes the most recent.
	// The only index this table needs beyond its UNIQUE(scan_uuid, hostname,
	// port) constraint. It covers the project-wide read - newest observation
	// for an endpoint, ORDER BY id DESC LIMIT 1 - with id in the index so the
	// lookup never fetches a table row per observation. The scan-scoped read
	// is served by the unique constraint's own index, so a third
	// (project_uuid, scan_uuid, hostname, port) index bought nothing and cost
	// a b-tree insertion on every observation written.
	"CREATE INDEX IF NOT EXISTS idx_host_obs_project_host_id ON host_observations(project_uuid, hostname, port, id)",

	// -- findings: project-aware composite indexes --
	"CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_uuid, severity)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_module ON findings(project_uuid, module_id)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_found_at ON findings(project_uuid, found_at)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_module_type ON findings(project_uuid, module_type)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_finding_source ON findings(project_uuid, finding_source)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_record_kind ON findings(project_uuid, record_kind)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_scan ON findings(project_uuid, scan_uuid)",
	// Covers aggregateScanFindings (SELECT severity, COUNT(*) WHERE scan_uuid = ?
	// GROUP BY severity), which runs on every scan-status tick. scan_uuid is not
	// the leading column of idx_findings_project_scan, so without this the count
	// fell back to a full findings scan each tick; (scan_uuid, severity) makes it
	// index-only.
	"CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_uuid, severity)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_hostname ON findings(project_uuid, hostname)",
	// Backs the per-round dynamic-assessment dedup grouping
	// (DeduplicateFindings / GroupFindingsByValue): the WHERE narrows on
	// (project_uuid, hostname) and the window function partitions by
	// (module_id, severity, …) ordered by created_at. Indexing all five lets
	// the host-scoped scan resolve from the index and arrive partially
	// pre-ordered for the PARTITION BY, instead of a full findings scan + sort
	// every feedback round. (matched_url is a json_extract expression and
	// stays per-row, but the module_id/severity prefix is satisfied here.)
	"CREATE INDEX IF NOT EXISTS idx_findings_project_host_module_sev ON findings(project_uuid, hostname, module_id, severity, created_at)",
	// Sparse (nullzero column) — used by agent end-of-run summaries and
	// webhook notifications to count findings per agentic-scan run.
	"CREATE INDEX IF NOT EXISTS idx_findings_agentic_scan ON findings(agentic_scan_uuid)",
	// Dedup is scoped per project: the same finding_hash may legitimately
	// recur across projects without one project's finding suppressing
	// another's. Backs ON CONFLICT (project_uuid, finding_hash).
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_project_hash_unique ON findings(project_uuid, finding_hash)",

	// -- finding_records --
	"CREATE INDEX IF NOT EXISTS idx_finding_records_record_uuid ON finding_records(record_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_finding_records_finding_id ON finding_records(finding_id)",

	// -- finding_observations --
	// Lookups by finding_id ride the (finding_id, scan_uuid) primary key.
	// "Which findings did scan X observe" and "which scans observed hash H"
	// are the two diff-side reads, both project-scoped.
	"CREATE INDEX IF NOT EXISTS idx_finding_obs_project_scan ON finding_observations(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_finding_obs_project_hash ON finding_observations(project_uuid, finding_hash)",

	// -- finding_hash_aliases --
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_hash_aliases_project_hash ON finding_hash_aliases(project_uuid, alias_hash)",
	"CREATE INDEX IF NOT EXISTS idx_finding_hash_aliases_finding ON finding_hash_aliases(finding_id)",
	// -- finding_status_events --
	"CREATE INDEX IF NOT EXISTS idx_finding_status_events_finding ON finding_status_events(finding_id, id)",
	"CREATE INDEX IF NOT EXISTS idx_finding_status_events_project_created ON finding_status_events(project_uuid, created_at)",

	// -- scans --
	"CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans(project_uuid, created_at)",

	// -- scopes --
	"CREATE INDEX IF NOT EXISTS idx_scopes_project_enabled_priority ON scopes(project_uuid, enabled, priority)",

	// -- oast_interactions --
	"CREATE INDEX IF NOT EXISTS idx_oast_project_scan ON oast_interactions(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_oast_interactions_unique_id ON oast_interactions(unique_id)",

	// -- oast_sessions --
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_oast_sessions_project_corr ON oast_sessions(project_uuid, correlation_id)",
	"CREATE INDEX IF NOT EXISTS idx_oast_sessions_open ON oast_sessions(project_uuid, scan_uuid, closed_at)",
	// -- oast_payloads -- (nonce lookups ride the primary key)
	"CREATE INDEX IF NOT EXISTS idx_oast_payloads_project_scan ON oast_payloads(project_uuid, scan_uuid)",

	// -- agentic_scans --
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_uuid ON agentic_scans(uuid)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_status ON agentic_scans(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_created ON agentic_scans(project_uuid, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_scan ON agentic_scans(scan_uuid)",

	// -- authentication_hostnames --
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_authentication_hostnames_unique ON authentication_hostnames(project_uuid, hostname, session_name)",
	"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_hostname ON authentication_hostnames(project_uuid, hostname)",
	"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_scan ON authentication_hostnames(project_uuid, scan_uuid)",

	// -- scan_logs --
	"CREATE INDEX IF NOT EXISTS idx_scan_logs_project_scan ON scan_logs(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)",

	// -- projects --
	"CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_uuid)",

	// -- agent_sections (durable autopilot) --
	"CREATE INDEX IF NOT EXISTS idx_agent_sections_agentic_scan ON agent_sections(agentic_scan_uuid, seq)",
	"CREATE INDEX IF NOT EXISTS idx_agent_sections_project ON agent_sections(project_uuid)",

	// -- agent_finding_candidates (durable autopilot) --
	"CREATE INDEX IF NOT EXISTS idx_agent_candidates_agentic_scan ON agent_finding_candidates(agentic_scan_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_agent_candidates_project ON agent_finding_candidates(project_uuid)",
	// Backs ON CONFLICT (agentic_scan_uuid, dedup_hash) DO NOTHING in SaveCandidate.
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_candidates_dedup ON agent_finding_candidates(agentic_scan_uuid, dedup_hash)",
}

// recordSecondaryIndexes are the non-unique read indexes on http_records.
//
// They are kept apart from the rest of CreateSchema's index list because they
// are the only ones a BULK LOAD can safely postpone: nothing depends on them for
// correctness (uuid is the PRIMARY KEY, and that is what the merge's
// INSERT OR IGNORE dedups on), and they are the most expensive to maintain
// incrementally — thirteen b-tree insertions per row, most of them keyed on a
// random uuid, so every insert dirties thirteen pages in thirteen different
// places. Building them once after the rows are in lets SQLite sort instead.
//
// See DeferRecordIndexes for who postpones them, and CreateRecordIndexes for
// when they are built.
var recordSecondaryIndexes = []string{
	// -- http_records: project-aware composite indexes --
	"CREATE INDEX IF NOT EXISTS idx_records_project_hostname ON http_records(project_uuid, hostname)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_created_uuid ON http_records(project_uuid, created_at, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_sent_at ON http_records(project_uuid, sent_at)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_host_method_status ON http_records(project_uuid, hostname, method, status_code)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_scheme_host_port ON http_records(project_uuid, scheme, hostname, port)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_risk_score ON http_records(project_uuid, risk_score)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_surface_score ON http_records(project_uuid, surface_score)",
	// The dynamic-assessment page order (ECON-10): one (risk, surface) bucket
	// is an equality prefix, so a bucket page is an in-order index range scan
	// with no temp b-tree sort.
	"CREATE INDEX IF NOT EXISTS idx_records_project_risk_order ON http_records(project_uuid, risk_score DESC, surface_score DESC, created_at, uuid)",
	// Covering index for findDuplicateRecord: the duplicate probe filters on
	// (project_uuid, method, hostname, path, url[, request_hash]) and selects
	// only uuid. Indexing all of those plus uuid lets the lookup resolve
	// entirely from the index (no per-candidate table row fetch). The old
	// 4-column version (…, path) is dropped in CreateSchema so this definition
	// takes effect on existing databases.
	"CREATE INDEX IF NOT EXISTS idx_records_dedup ON http_records(project_uuid, method, hostname, path, url, request_hash, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_request_hash ON http_records(request_hash)",
	"CREATE INDEX IF NOT EXISTS idx_records_response_hash ON http_records(response_hash)",
	// Supports DeduplicateDeparosByNormHash: narrows the full http_records scan to
	// the (project, deparos) subset and surfaces response_norm_hash for the
	// reflected-URL-robust dedup pass run after discovery.
	"CREATE INDEX IF NOT EXISTS idx_records_norm_hash ON http_records(project_uuid, source, response_norm_hash)",
	// -- http_records: scan_uuid index --
	"CREATE INDEX IF NOT EXISTS idx_records_project_scan ON http_records(project_uuid, scan_uuid)",
	// -- http_records: source-filtered cursor scan (scan-on-receive) --
	// Supports WHERE source IN (...) AND created_at > cursor filters in
	// DBInputSource.fetchNextBatch and Repository.CountRecordsAfterCursorBySource.
	"CREATE INDEX IF NOT EXISTS idx_records_project_source_created ON http_records(project_uuid, source, created_at, uuid)",
}

// columnMigration is one additive column an existing database may be missing.
type columnMigration struct{ Table, Column, Def string }

// columnMigrations is the SINGLE list of columns this binary expects on an
// existing database. Data rather than a sequence of method calls, because it has
// two consumers that must never disagree: CreateSchema APPLIES it, and
// missingColumns ASKS it. Expressing "ask instead of apply" as a mode flag on
// the mutating method meant a field on the shared *DB handle that silently
// turned every addColumn into a no-op for whoever else held that handle.
//
// Notes that used to sit on individual calls:
//   - surface_score is separate from risk_score deliberately: risk_score holds
//     anomaly_ranking's batch percentile, a different scale from different
//     inputs, and one column cannot carry both without the later writer silently
//     erasing the other. DEFAULT 0 reads as "no surface signals", the correct
//     floor for every row that predates the column.
//   - The project_uuid entries are appended at init from
//     projectUUIDMigrationTables, which is narrower than projectOwnedTables: the
//     newer project-scoped tables declare the column in their own CREATE TABLE
//     and need neither the ALTER nor the O(rows) backfill.
var columnMigrations = []columnMigration{
	{"scans", "coverage_modules", "{{JSON}}"},
	{"findings", "request", "TEXT"},
	{"findings", "response", "TEXT"},
	{"http_records", "request_authorization", "TEXT"},
	{"http_records", "response_title", "TEXT"},
	{"http_records", "response_words", "INTEGER DEFAULT 0"},
	{"http_records", "response_norm_hash", "TEXT"},
	{"http_records", "response_location", "TEXT"},
	{"http_records", "source", "TEXT DEFAULT ''"},
	{"http_records", "remarks", "{{JSON}}"},
	{"http_records", "risk_score", "INTEGER DEFAULT 0"},
	{"http_records", "surface_score", "INTEGER DEFAULT 0"},
	{"findings", "confidence", "TEXT NOT NULL DEFAULT 'firm'"},
	{"findings", "scan_uuid", "TEXT"},
	{"findings", "module_type", "TEXT DEFAULT ''"},
	{"findings", "finding_source", "TEXT DEFAULT ''"},
	{"findings", "record_kind", "TEXT NOT NULL DEFAULT 'finding'"},
	{"findings", "evidence_grade", "TEXT DEFAULT ''"},
	{"findings", "module_short", "TEXT DEFAULT ''"},
	{"scans", "scan_source", "TEXT"},
	{"scans", "scan_mode", "TEXT"},
	{"scans", "start_cursor_at", "{{TIMESTAMP}}"},
	{"scans", "start_cursor_uuid", "TEXT"},
	{"scans", "cursor_at", "{{TIMESTAMP}}"},
	{"scans", "cursor_uuid", "TEXT"},
	{"scans", "processed_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "session_id", "TEXT"},
	{"projects", "tags", "{{JSON}}"},
	{"projects", "default_target", "TEXT"},
	{"projects", "last_scan_at", "{{TIMESTAMP}}"},
	{"scans", "profile", "TEXT"},
	{"scans", "source_path", "TEXT"},
	{"scans", "source_type", "TEXT"},
	{"scans", "http_record_uuid", "TEXT"},
	{"scans", "tags", "{{JSON}}"},
	{"scans", "triggered_by", "TEXT"},
	{"scans", "agentic_scan_uuid", "TEXT"},
	{"http_records", "scan_uuid", "TEXT"},
	{"http_records", "technology", "{{JSON}}"},
	{"http_records", "content_hash", "TEXT"},
	{"http_records", "is_authenticated", "{{BOOL}} NOT NULL DEFAULT {{FALSE}}"},
	{"http_records", "parent_uuid", "TEXT"},
	{"http_records", "target", "TEXT"},
	{"http_records", "root_uuid", "TEXT"},
	{"http_records", "chain_truncated", "{{BOOL}} NOT NULL DEFAULT {{FALSE}}"},
	{"findings", "agentic_scan_uuid", "TEXT"},
	{"findings", "url", "TEXT"},
	{"findings", "hostname", "TEXT"},
	{"findings", "status", "TEXT DEFAULT 'triaged'"},
	{"findings", "remediation", "TEXT"},
	{"findings", "cwe_id", "TEXT"},
	{"findings", "cvss_score", "{{FLOAT}} DEFAULT 0"},
	{"findings", "source_file", "TEXT"},
	{"findings", "repo_name", "TEXT"},
	{"agentic_scans", "source_path", "TEXT"},
	{"agentic_scans", "token_usage", "{{JSON}}"},
	{"agentic_scans", "retry_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "parent_run_uuid", "TEXT"},
	{"agentic_scans", "input_record_count", "INTEGER DEFAULT 0"},
	{"agentic_scans", "session_dir", "TEXT"},
	{"agentic_scans", "protocol", "TEXT"},
	{"agentic_scans", "model", "TEXT"},
	{"agentic_scans", "total_input_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"agentic_scans", "total_output_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"agentic_scans", "estimated_cost_usd", "{{FLOAT}} NOT NULL DEFAULT 0"},
	{"scans", "storage_url", "TEXT"},
	{"scans", "scope_origin_mode", "TEXT"},
	{"agentic_scans", "storage_url", "TEXT"},
	{"oast_interactions", "finding_id", "INTEGER"},
	{"oast_interactions", "payload", "TEXT"},
	{"scopes", "content_type_pattern", "TEXT"},
	{"scopes", "hit_count", "INTEGER DEFAULT 0"},
	{"scopes", "last_matched_at", "{{TIMESTAMP}}"},
	{"authentication_hostnames", "session_token", "TEXT"},
	{"authentication_hostnames", "hydrated_at", "{{TIMESTAMP}}"},
	// Scan completeness. Nullable with NO default on purpose: an empty value
	// means "unknown", which is what a row written by an older binary — or by a
	// caller that has no outcome data — honestly is. A DEFAULT of 'complete'
	// would retroactively declare every historical scan fully covered.
	{"scans", "completeness", "TEXT"},
	{"scans", "stop_reason", "TEXT"},
	{"scans", "phase_outcomes", "{{JSON}}"},
	// Body compaction marker (`db compact`). Nullable with no default: NULL
	// means the stored bodies are the bodies as captured, which is what every
	// row written before this column existed honestly holds.
	{"http_records", "body_compaction", "{{JSON}}"},
	// Schema v2: the compatibility guard (schema_guard.go). min_reader_version
	// defaults to 1, which backfills every existing row with the floor a v1
	// store has always had.
	{"schema_meta", "min_reader_version", "INTEGER NOT NULL DEFAULT 1"},
	{"schema_meta", "written_by", "TEXT"},
	{"schema_meta", "updated_at", "{{TIMESTAMP}}"},
	// Schema v3. Every column nullable with no default: NULL honestly means
	// "not recorded" for every row an older binary wrote.
	//   - findings: the current verdict's provenance (the full history is
	//     finding_status_events), what `finding verify` needs to replay a
	//     finding (the baseline record, insertion point and payload), and the
	//     last verification result (JSON) kept apart from status.
	//   - scans: run liveness (heartbeat, phase, pid, host), the resolved plan
	//     (JSON), and the per-module error / failed-extension tallies (JSON)
	//     that scan.finished reads back from the row.
	{"findings", "status_note", "TEXT"},
	{"findings", "status_actor", "TEXT"},
	{"findings", "status_updated_at", "{{TIMESTAMP}}"},
	{"findings", "origin_record_uuid", "TEXT"},
	{"findings", "insertion_point", "{{JSON}}"},
	{"findings", "payload", "TEXT"},
	{"findings", "verification", "{{JSON}}"},
	{"findings", "verified_at", "{{TIMESTAMP}}"},
	{"scans", "plan", "{{JSON}}"},
	{"scans", "heartbeat_at", "{{TIMESTAMP}}"},
	{"scans", "current_phase", "TEXT"},
	{"scans", "pid", "INTEGER"},
	{"scans", "runner_host", "TEXT"},
	{"scans", "module_errors", "{{JSON}}"},
	{"scans", "extensions_failed", "{{JSON}}"},
	{"schema_meta", "observation_history_since", "{{TIMESTAMP}}"},
	// Schema v4: host facts beyond A/AAAA/CNAME and TLS — the other DNS record
	// types `vigolium dns` resolves, and what the fingerprint phase concluded
	// about an origin plus its not-found baseline. Nullable with no default:
	// NULL means "not observed", which is what every older row honestly holds.
	{"host_observations", "dns_mx", "{{JSON}}"},
	{"host_observations", "dns_ns", "{{JSON}}"},
	{"host_observations", "dns_txt", "{{JSON}}"},
	{"host_observations", "dns_soa", "{{JSON}}"},
	{"host_observations", "dns_caa", "{{JSON}}"},
	{"host_observations", "fingerprint", "{{JSON}}"},
	{"host_observations", "not_found", "{{JSON}}"},
	// Schema v5: the origin's icon as the probe phase's --favicon hashed it.
	// Nullable, no default: NULL means "not fetched".
	{"host_observations", "favicon", "{{JSON}}"},
	// Schema v6: finding identity v2. last_seen_at is set on every re-detection;
	// NULL means no v6 binary has re-detected the row.
	{"findings", "last_seen_at", "{{TIMESTAMP}}"},
	// scans.module_stats: the per-module ledger (database.ModuleStat).
	{"scans", "module_stats", "{{JSON}}"},
}

func init() {
	for _, table := range projectUUIDMigrationTables {
		columnMigrations = append(columnMigrations, columnMigration{
			Table: table, Column: "project_uuid",
			Def: fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", DefaultProjectUUID),
		})
	}
}
