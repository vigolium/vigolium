package cli

import (
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dnsresolve"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/scanplan"
)

// schema_registry.go declares the -j document shapes `vigolium schema`
// publishes, one table like command_traits.go: the item type and the
// command-specific top-level keys of each registered command.
//
// Several views are built as maps (compactFindingView, compactRecordView,
// bodyView: --fields projects them, and keys appear only when set). Their
// typed mirrors below are the schema's source; schema_registry_test.go keeps
// each mirror's key set equal to the selectable --fields vocabulary and the
// emitted keys a subset of it, so a key added to a builder without its mirror
// fails a test instead of shipping undocumented.

// findingViewSchema mirrors compactFindingView (`finding -j`, the scan
// document's items, `scan diff` rows). Keys emitted only when set are
// omitempty; --fields may drop any key.
type findingViewSchema struct {
	ID                 int64                           `json:"id,omitempty"`
	FindingHash        string                          `json:"finding_hash,omitempty"`
	Severity           string                          `json:"severity"`
	Confidence         string                          `json:"confidence"`
	ModuleID           string                          `json:"module_id"`
	ModuleName         string                          `json:"module_name"`
	ModuleType         string                          `json:"module_type"`
	FindingSource      string                          `json:"finding_source"`
	RecordKind         string                          `json:"record_kind"`
	EvidenceGrade      string                          `json:"evidence_grade"`
	Short              string                          `json:"short,omitempty"`
	Description        string                          `json:"description,omitempty"`
	URL                string                          `json:"url,omitempty"`
	Hostname           string                          `json:"hostname,omitempty"`
	MatchedAt          []string                        `json:"matched_at,omitempty"`
	ExtractedResults   []string                        `json:"extracted_results,omitempty"`
	AdditionalEvidence []string                        `json:"additional_evidence,omitempty"`
	Tags               []string                        `json:"tags,omitempty"`
	CWEID              string                          `json:"cwe_id,omitempty"`
	CVSSScore          float64                         `json:"cvss_score,omitempty"`
	Remediation        string                          `json:"remediation,omitempty"`
	Status             string                          `json:"status,omitempty"`
	StatusNote         string                          `json:"status_note,omitempty"`
	StatusActor        string                          `json:"status_actor,omitempty"`
	ScanUUID           string                          `json:"scan_uuid,omitempty"`
	AgenticScanUUID    string                          `json:"agentic_scan_uuid,omitempty"`
	RepoName           string                          `json:"repo_name,omitempty"`
	SourceFile         string                          `json:"source_file,omitempty"`
	FoundAt            string                          `json:"found_at"`
	HTTPRecordUUIDs    []string                        `json:"http_record_uuids,omitempty"`
	OriginRecordUUID   string                          `json:"origin_record_uuid,omitempty"`
	InsertionPoint     *database.FindingInsertionPoint `json:"insertion_point,omitempty"`
	Payload            string                          `json:"payload,omitempty"`
	Verification       *database.FindingVerification   `json:"verification,omitempty"`
	VerifiedAt         string                          `json:"verified_at,omitempty"`
	ResponseEvidence   string                          `json:"response_evidence,omitempty"`
	Request            string                          `json:"request,omitempty"`
	Response           string                          `json:"response,omitempty"`
	Records            []recordViewSchema              `json:"records,omitempty"`
	RecordsTotal       int                             `json:"records_total,omitempty"`
	RecordsTruncated   bool                            `json:"records_truncated,omitempty"`
	RecordsError       string                          `json:"records_error,omitempty"`
}

// recordViewSchema mirrors compactRecordView (`traffic -j`, a finding's
// --with-records rows). The host facts (a, aaaa, cname, tls) are merged in at
// the top level, as database.HostFacts marshals them.
type recordViewSchema struct {
	UUID                  string `json:"uuid"`
	Method                string `json:"method"`
	URL                   string `json:"url"`
	Host                  string `json:"host"`
	StatusCode            int    `json:"status_code"`
	ResponseContentType   string `json:"response_content_type"`
	ResponseContentLength int64  `json:"response_content_length"`
	ResponseTimeMS        int64  `json:"response_time_ms"`
	ResponseWords         int64  `json:"response_words"`
	Source                string `json:"source"`
	ScanUUID              string `json:"scan_uuid,omitempty"`
	SentAt                string `json:"sent_at,omitempty"`
	ResponseTitle         string `json:"response_title,omitempty"`
	IP                    string `json:"ip,omitempty"`
	RiskScore             int    `json:"risk_score,omitempty"`
	SurfaceScore          int    `json:"surface_score,omitempty"`
	IsAuthenticated       bool   `json:"is_authenticated,omitempty"`
	database.HostFacts
	Technology     []string                 `json:"technology,omitempty"`
	Remarks        []string                 `json:"remarks,omitempty"`
	BodyCompaction *database.BodyCompaction `json:"body_compaction,omitempty"`
	Request        *bodyViewSchema          `json:"request,omitempty"`
	Response       *bodyViewSchema          `json:"response,omitempty"`
	// UUIDShort and ResponseHeaders appear only when --fields names them.
	UUIDShort       string `json:"uuid_short,omitempty"`
	ResponseHeaders string `json:"response_headers,omitempty"`
	// MatchesNotFound appears when --fields names it and the record's origin
	// has a not-found baseline (or the record is a 404/410).
	MatchesNotFound *bool `json:"matches_not_found,omitempty"`
}

// bodyViewSchema mirrors bodyView: one request or response, headers verbatim
// and the body decoded, capped and stubbed when binary.
type bodyViewSchema struct {
	RawHeaders      string `json:"raw_headers,omitempty"`
	BodySize        int64  `json:"body_size,omitempty"`
	BodySizeAtLeast int64  `json:"body_size_at_least,omitempty"`
	BodySHA256      string `json:"body_sha256,omitempty"`
	DecoderCapped   bool   `json:"decoder_capped,omitempty"`
	DecoderLimit    int64  `json:"decoder_limit,omitempty"`
	DecoderHint     string `json:"decoder_hint,omitempty"`
	BodyOmitted     string `json:"body_omitted,omitempty"`
	Body            string `json:"body,omitempty"`
	BodyTruncated   bool   `json:"body_truncated,omitempty"`
}

// scanDiffItemSchema is one `scan diff` row: the finding view plus the class.
type scanDiffItemSchema struct {
	findingViewSchema
	// Change is new, unchanged, fixed or not_reobserved.
	Change        string `json:"change"`
	FirstSeenScan string `json:"first_seen_scan,omitempty"`
}

// Extras: each command's own top-level keys. omitempty = optional.

type provenanceExtras struct {
	// ProvenanceWarning is scan_not_found or scan_uuid_not_stamped when a
	// --scan-uuid read matched nothing for a reason worth naming.
	ProvenanceWarning string `json:"provenance_warning,omitempty"`
	ProvenanceDetail  string `json:"provenance_detail,omitempty"`
}

type curlExtras struct {
	// Skipped counts rows with no stored request to render (--curl).
	Skipped int `json:"skipped,omitempty"`
	// Redacted says credentials were masked (--curl --redact-auth).
	Redacted bool `json:"redacted,omitempty"`
}

type trafficExtras struct {
	provenanceExtras
	curlExtras
	// NotFoundExcluded counts records --exclude-not-found removed from the page.
	NotFoundExcluded *int `json:"not_found_excluded,omitempty"`
}

type findingExtras struct {
	curlExtras
	// FindingsTotal is the matched finding count under --curl, where total
	// counts the rendered rows.
	FindingsTotal int64 `json:"findings_total,omitempty"`
}

type endpointsExtras struct {
	provenanceExtras
	RecordsScanned    int64 `json:"records_scanned"`
	Capped            bool  `json:"capped"`
	UnbucketedRecords int64 `json:"unbucketed_records"`
	Collapse          int   `json:"collapse,omitempty"`
}

type paramsExtras struct {
	provenanceExtras
	RecordsScanned int64 `json:"records_scanned"`
	Capped         bool  `json:"capped"`
	ValuesRedacted bool  `json:"values_redacted"`
}

// scanDocExtras are the scan document's top-level keys (scan_document.go).
type scanDocExtras struct {
	ScanUUID     string   `json:"scan_uuid,omitempty"`
	ScanUUIDs    []string `json:"scan_uuids"`
	Persisted    bool     `json:"persisted"`
	Stateless    bool     `json:"stateless"`
	Status       string   `json:"status"`
	Completeness string   `json:"completeness"`
	Reasons      []string `json:"reasons"`
	StopReason   string   `json:"stop_reason,omitempty"`
	// ScopeDropped counts the records scope rules refused, per rule class
	// (host, path, static_file, status_code, …). Intent, not lost coverage.
	ScopeDropped      map[string]int64        `json:"scope_dropped,omitempty"`
	Targets           []scanDocTarget         `json:"targets"`
	TargetsNotScanned []string                `json:"targets_not_scanned"`
	PhaseOutcomes     []database.PhaseOutcome `json:"phase_outcomes"`
	// Caveats is the coverage statement derived from phase_outcomes and module
	// errors (database.CoverageCaveats).
	Caveats []database.Caveat `json:"caveats"`
	// Artifacts are the files the run wrote; Next the suggested follow-ups.
	Artifacts []scanArtifact `json:"artifacts"`
	Next      []scanNextStep `json:"next"`
	// Baseline is set with --baseline or an ignore file; null otherwise.
	Baseline         *baselineCounts `json:"baseline"`
	Modules          scanDocModules  `json:"modules"`
	CountsBySeverity map[string]int  `json:"counts_by_severity"`
	Candidates       int64           `json:"candidates"`
	Observations     int64           `json:"observations"`
	Errors           []scanDocError  `json:"errors"`
	ItemsTruncated   bool            `json:"items_truncated"`
	// Plan is the scan's stored plan (scans.plan, the `schema plan` document),
	// verbatim; null when the row has none or the document spans several scans.
	Plan       *scanplan.Plan `json:"plan"`
	DurationMS int64          `json:"duration_ms"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
}

type scanDiffExtras struct {
	Base                 scanDiffSideView `json:"base"`
	Head                 scanDiffSideView `json:"head"`
	Comparable           bool             `json:"comparable"`
	ComparabilityReasons []string         `json:"comparability_reasons"`
	History              string           `json:"history"`
	Counts               map[string]int   `json:"counts"`
	IncludeDismissed     bool             `json:"include_dismissed"`
}

type findingMarkExtras struct {
	// Status is the verdict written.
	Status    string                         `json:"status"`
	Unchanged []database.FindingStatusChange `json:"unchanged"`
	NotFound  []string                       `json:"not_found"`
}

type projectUseExtras struct {
	Created         bool              `json:"created"`
	PreviousProject string            `json:"previous_project"`
	ActivatedScope  string            `json:"activated_scope"`
	ActiveFile      string            `json:"active_file"`
	Env             map[string]string `json:"env"`
}

type projectDeleteExtras struct {
	Found   bool `json:"found"`
	Aborted bool `json:"aborted,omitempty"`
}

type oastIngestExtras struct {
	// Format is the callback log format read.
	Format     string `json:"format"`
	Callbacks  int    `json:"callbacks"`
	Matched    int    `json:"matched"`
	Unmatched  int    `json:"unmatched"`
	Duplicates int    `json:"duplicates"`
}

type oastPollExtras struct {
	// Sessions is how many kept sessions were polled.
	Sessions   int `json:"sessions"`
	Correlated int `json:"correlated"`
	Findings   int `json:"findings"`
}

type moduleToggleExtras struct {
	ModulesChanged int    `json:"modules_changed"`
	ConfigPath     string `json:"config_path"`
}

// registerCommandSchema registers c with its kind taken from the
// -j document's declared kind, so the two tables cannot disagree.
func registerCommandSchema(c contract.Command) {
	if c.Kind == "" {
		c.Kind = envelopeKindForDeclared(machineKinds[c.Name])
	}
	contract.RegisterCommand(c)
}

// envelopeKindForDeclared is the `kind` a command declared as k renders
// (stream commands render a read envelope under -j).
func envelopeKindForDeclared(k machineKind) string {
	switch k {
	case kindStream:
		return string(kindRead)
	case kindRead, kindMutation, kindScan:
		return string(k)
	}
	return ""
}

func init() {
	curlVariant := []contract.Variant{{Flag: "--curl", Item: curlItem{}}}

	registerCommandSchema(contract.Command{Name: "finding", Item: findingViewSchema{}, Variants: curlVariant,
		Extras: findingExtras{}, Description: "Stored findings as finding views; --curl rows render each finding's request as a curl command."})
	registerCommandSchema(contract.Command{Name: "traffic", Item: recordViewSchema{}, Variants: curlVariant,
		Extras: trafficExtras{}, Description: "Stored HTTP records; --curl rows render each request as a curl command."})
	registerCommandSchema(contract.Command{Name: "endpoints", Item: database.EndpointView{},
		Extras: endpointsExtras{}, Description: "Endpoints (origin + path template) aggregated from stored traffic."})
	registerCommandSchema(contract.Command{Name: "params", Item: database.ParamView{},
		Extras: paramsExtras{}, Description: "Parameters by endpoint and location, aggregated from stored traffic."})
	registerCommandSchema(contract.Command{Name: "log ls", Item: logRowView{}, Extras: logLsExtras{},
		Description: "Native and agentic scan sessions with liveness (effective_status, stale, last_write_at); --reap adds reaped and status_files_removed."})
	registerCommandSchema(contract.Command{Name: "scan status", Item: scanStatusView{}, ItemsKind: contract.ItemsObject,
		Description: "One scan's live status: phase, progress, liveness, ETA and the stored plan."})
	registerCommandSchema(contract.Command{Name: "scan wait", Item: findingViewSchema{}, Extras: scanDocExtras{},
		Description: "The finished scan's scan document (the one scan -j prints, rebuilt from the stored row), printed once the scan ends."})
	registerCommandSchema(contract.Command{Name: "scan diff", Item: scanDiffItemSchema{}, Extras: scanDiffExtras{},
		Description: "Findings classified new / unchanged / fixed / not_reobserved between two scans."})
	for _, name := range []string{"scan", "run", "scan-url", "scan-request"} {
		var variants []contract.Variant
		desc := "The scan document: one document per invocation, items are finding views."
		if name == "run" {
			// `run fingerprint` reports the origins it fingerprinted, as
			// `fingerprint -j` does, not findings.
			variants = []contract.Variant{{Flag: "the fingerprint phase (run fingerprint)", Item: hostView{}}}
			desc = "The scan document: items are finding views, or host views for `run fingerprint`."
		}
		registerCommandSchema(contract.Command{Name: name, Item: findingViewSchema{}, Extras: scanDocExtras{},
			Variants: variants, Description: desc})
	}

	// Mutations.
	registerCommandSchema(contract.Command{Name: "finding mark", Item: database.FindingStatusChange{},
		Extras: findingMarkExtras{}, Description: "Findings whose status changed; unchanged and not_found list the rest."})
	registerCommandSchema(contract.Command{Name: "project create", Item: projectMutationView{},
		Description: "The project created."})
	registerCommandSchema(contract.Command{Name: "project use", Item: projectMutationView{}, Extras: projectUseExtras{},
		Description: "The project activated (or created with --create)."})
	registerCommandSchema(contract.Command{Name: "project delete", Item: projectDeleteView{}, Extras: projectDeleteExtras{},
		Description: "The project deleted, with what it held."})
	registerCommandSchema(contract.Command{Name: "oast ingest", Item: oast.IngestedFinding{}, Extras: oastIngestExtras{},
		Description: "Findings saved from logged OAST callbacks; the counters say how the callbacks were attributed."})
	registerCommandSchema(contract.Command{Name: "oast poll", Item: oast.PollResult{}, Extras: oastPollExtras{},
		Description: "One item per kept OAST session polled: callbacks collected, how many correlated to a planted payload, and whether it was closed."})
	registerCommandSchema(contract.Command{Name: "extensions lint", Item: extLintFile{}, Extras: extLintExtras{},
		Description: "One item per linted file with its issues (severity, line, col, message, rule); summary counts them. ok is false exactly when there are errors (exit 1, lint_failed)."})
	for _, name := range []string{"module enable", "module disable"} {
		registerCommandSchema(contract.Command{Name: name, Item: moduleToggleView{}, Extras: moduleToggleExtras{},
			Description: "Every module the search matched, each saying whether this run flipped it."})
	}

	// The last off-contract commands (B8).
	registerCommandSchema(contract.Command{Name: "db seed", Item: seedTableView{}, Extras: seedExtras{},
		Description: "Sample rows written per table; a row already present is skipped and not counted."})
	registerCommandSchema(contract.Command{Name: "extensions example", Item: extExampleView{}, Extras: extExampleExtras{},
		Description: "Copy-pasteable example extensions; code is omitted under --list."})
	registerCommandSchema(contract.Command{Name: "extensions preset", Item: extPresetView{}, Extras: extPresetExtras{},
		Description: "Every preset file considered (installed, skipped, failed) plus vigolium.d.ts (updated or current)."})
	registerCommandSchema(contract.Command{Name: "extensions types", Item: extTypesView{}, ItemsKind: contract.ItemsObject,
		Description: "vigolium.d.ts: the file written with -o, or the declarations inline as content."})
	registerCommandSchema(contract.Command{Name: "config ls", Item: configEntrySchema{}, Extras: configLsExtras{},
		Description: "Every settable key with its typed value (string credentials redacted), default, type and source layer (default, file, env:NAME, project, flag)."})
	registerCommandSchema(contract.Command{Name: "config env", Item: configEnvSchema{}, Extras: configEnvExtras{},
		Description: "Every VIGOLIUM_* variable the binary reads: set or not, value (credentials redacted), the settings key it overrides."})
	registerCommandSchema(contract.Command{Name: "import", Extras: importExtras{},
		Description: "items is always []; the import counters stay at the top level (a parse, a SQLite merge, or a live bridge import)."})
	registerCommandSchema(contract.Command{Name: "js", Item: jsEvalItem{}, ItemsKind: contract.ItemsObject,
		Description: "The script's return value as JSON (null for undefined)."})
	registerCommandSchema(contract.Command{Name: "extensions eval", Item: jsEvalItem{}, ItemsKind: contract.ItemsObject,
		Description: "The code's return value as JSON (null for undefined), as `js -j`. With --record-uuid the document is `extensions run`'s."})
	registerCommandSchema(contract.Command{Name: "log", Item: logLineView{}, Extras: logShowExtras{},
		Description: "`log <uuid> -j`: the session log's lines (the --tail/--full window) with its identity and liveness."})
	registerCommandSchema(contract.Command{Name: "fingerprint", Item: hostView{}, Extras: scanDocExtras{},
		Description: "The scan document of a fingerprint run whose items are the origins it fingerprinted (the `hosts` view)."})
	registerCommandSchema(contract.Command{Name: "dns", Item: dnsresolve.Answer{}, Extras: dnsExtras{},
		Description: "One answer per name: every record type asked for, each record with its TTL, and how many answers were stored."})
	registerCommandSchema(contract.Command{Name: "hosts", Item: hostView{},
		Description: "Stored host facts per host:port: DNS, TLS certificate, fingerprint report and not-found baseline, with the survey facts lifted to the top."})
	registerCommandSchema(contract.Command{Name: "match-not-found", Item: matchNotFoundItem{}, Extras: matchNotFoundExtras{},
		Description: "One verdict per stdin line, in order: whether the response is its origin's not-found page (known false without a baseline or a body), and why; lines that did not parse are counted in failed."})
	registerCommandSchema(contract.Command{Name: "schema flags", Item: flagUsageView{}, Extras: schemaFlagsExtras{},
		Description: "One command's flags (for_command): name, shorthand, type, default, description, inherited."})
	registerCommandSchema(contract.Command{Name: "schema storage", Item: storageTable{},
		Description: "The database's tables with columns, row counts, purpose, and the -j field a column surfaces as."})
	registerCommandSchema(contract.Command{Name: "fuzz", Item: fuzz.Result{}, Extras: fuzzExtras{},
		Description: "The run summary: items are the top-ranked matched results (total is every match); --fields projects them."})
	registerCommandSchema(contract.Command{Name: "replay", Item: replayOutput{}, Extras: replayExtras{},
		Variants:    []contract.Variant{{Flag: "--once", Item: replayOnceView{}}, {Flag: "--dry-run", Item: replayDryRunView{}}},
		Description: "One row per replayed record: the baseline, the replay and their diff, and saved_record_uuid when the exchange was stored. A single source is one item; a bulk run counts failed rows. --once prints one compact item instead."})
	registerCommandSchema(contract.Command{Name: "ingest", Item: ingestedRecord{}, Extras: ingestExtras{},
		Description: "The records the ingest left in the store (capped; items_truncated says more exist), with why any were not stored."})
	registerCommandSchema(contract.Command{Name: "traffic body", Item: trafficBodyReceipt{}, ItemsKind: contract.ItemsObject,
		Description: "A receipt for one extracted body: size, sha256, completeness and where it was written."})
	registerCommandSchema(contract.Command{Name: "traffic headers", Item: trafficHeadersReceipt{}, ItemsKind: contract.ItemsObject,
		Description: "One stored message's headers as an ordered array (repeated headers kept)."})
	// The database maintenance commands, finding load and project list.
	registerCommandSchema(contract.Command{Name: "db stats", Item: database.DatabaseStats{}, ItemsKind: contract.ItemsObject,
		StreamFlag: "--watch", Description: "Row counts and breakdowns for the store (one object)."})
	registerCommandSchema(contract.Command{Name: "db list", Extras: dbListExtras{}, StreamFlag: "--watch",
		Description: "Rows of one table: records and findings as their -j views, scans as scan rows, any other table as column maps; with no table, the table names (and with one, its columns under --columns)."})
	registerCommandSchema(contract.Command{Name: "db clean", Item: dbCleanView{}, Extras: dbCleanExtras{},
		Description: "Rows deleted (or, with --dry-run, matched) per table; aborted when the confirmation was declined."})
	registerCommandSchema(contract.Command{Name: "db compact", Item: database.CompactSummary{}, ItemsKind: contract.ItemsObject,
		Description: "The compaction summary: bodies replaced by their head, bytes reclaimed, whether the file was vacuumed."})
	registerCommandSchema(contract.Command{Name: "db reset", Item: dbResetView{}, Extras: dbResetExtras{},
		Description: "The database deleted and recreated; aborted when the confirmation was declined."})
	registerCommandSchema(contract.Command{Name: "db migrate", Item: database.MigrateResult{}, ItemsKind: contract.ItemsObject,
		Description: "The schema versions before and after, and the migrations applied."})
	registerCommandSchema(contract.Command{Name: "finding load", Item: int64(0), Extras: findingLoadExtras{},
		Description: "The ids of the findings stored (total counts them); parsed, saved and skipped count the input."})
	registerCommandSchema(contract.Command{Name: "project list", Item: projectListView{},
		Description: "Every project in the store, marking the active one."})

	for _, name := range []string{"export", "db export"} {
		registerCommandSchema(contract.Command{Name: name, Item: exportFileView{}, Extras: exportReceiptExtras{},
			Description: "A receipt: the files written (-j needs -o; the export itself never shares stdout with the document) and their counts."})
	}
}

// dbListExtras are `db list -j`'s top-level keys beyond the common ones.
type dbListExtras struct {
	Table   string   `json:"table,omitempty"`
	Columns []string `json:"columns,omitempty"`
}

// dbCleanExtras are `db clean -j`'s top-level keys (all absent when aborted).
type dbCleanExtras struct {
	Mode        string `json:"mode,omitempty"`
	Scope       string `json:"scope,omitempty"`
	StoreWide   bool   `json:"store_wide,omitempty"`
	RowsMatched int64  `json:"rows_matched,omitempty"`
	RowsDeleted int64  `json:"rows_deleted,omitempty"`
	Aborted     bool   `json:"aborted,omitempty"`
}

// dbResetExtras are `db reset -j`'s top-level keys.
type dbResetExtras struct {
	Aborted bool `json:"aborted,omitempty"`
}

// findingLoadExtras are `finding load -j`'s top-level keys.
type findingLoadExtras struct {
	Format  string `json:"format"`
	Parsed  int    `json:"parsed"`
	Saved   int    `json:"saved"`
	Skipped int    `json:"skipped"`
}

// dnsExtras are `dns -j`'s top-level keys.
type dnsExtras struct {
	Stored int `json:"stored"`
}

// schemaFlagsExtras are `schema flags -j`'s top-level keys.
type schemaFlagsExtras struct {
	ForCommand string `json:"for_command"`
}

// fuzzExtras are fuzz -j's top-level keys: fuzzJSONSummary (which embeds this
// type) without the top_results it moves to items.
type fuzzExtras struct {
	Target    string `json:"target"`
	Positions int    `json:"positions"`
	Payloads  int    `json:"payloads"`
	// Sent counts payload sends; SentTotal every request, baseline samples
	// and calibration probes included.
	Sent            int           `json:"sent"`
	SentTotal       int           `json:"sent_total"`
	Matched         int           `json:"matched"`
	Calibrated      int           `json:"calibrated"`
	Errors          int           `json:"errors"`
	Baseline        fuzz.Baseline `json:"baseline"`
	Anomalies       []fuzz.Result `json:"anomalies,omitempty"`
	AnomaliesElided int           `json:"anomalies_elided,omitempty"`
	SentViaBurp     bool          `json:"sent_via_burp,omitempty"`
	OrganizerPushed int           `json:"organizer_pushed,omitempty"`
	// SavedRecordUUIDs are the exchanges `--save` stored (source "fuzz").
	SavedRecordUUIDs []string `json:"saved_record_uuids,omitempty"`
	Pace             fuzzPace `json:"pace"`
	// Next is the follow-up that confirms the anomalies; it sends traffic.
	Next []scanNextStep `json:"next,omitempty"`
}

// replayExtras are replay -j's top-level keys (bulk runs count failures).
type replayExtras struct {
	Failed int `json:"failed,omitempty"`
}

// ingestExtras are ingest -j's top-level keys.
//
// A local ingest reports what landed (records_*); a remote one (-s/--server)
// reports what it submitted (records_submitted, errors). Every key is optional
// because each mode carries only its own.
type ingestExtras struct {
	RecordsIngested int64 `json:"records_ingested,omitempty"`
	RecordsFailed   int64 `json:"records_failed,omitempty"`
	RecordsSkipped  int64 `json:"records_skipped,omitempty"`
	// RecordsWritten counts the rows this run added; records already stored
	// count in records_ingested but not here, and changed follows this.
	RecordsWritten   int64             `json:"records_written,omitempty"`
	RecordsSubmitted int64             `json:"records_submitted,omitempty"`
	Errors           int64             `json:"errors,omitempty"`
	DurationMS       int64             `json:"duration_ms,omitempty"`
	InputFormat      string            `json:"input_format,omitempty"`
	RecordSource     string            `json:"record_source,omitempty"`
	ItemsTruncated   bool              `json:"items_truncated,omitempty"`
	FailureReasons   map[string]int64  `json:"failure_reasons,omitempty"`
	Failures         []core.DropSample `json:"failures,omitempty"`
	// WouldIngest is what `ingest --dry-run` parsed: the requests a real run
	// would fetch and store.
	WouldIngest int64 `json:"would_ingest,omitempty"`
}

// trafficBodyReceipt mirrors `traffic body -j`.
type trafficBodyReceipt struct {
	UUID            string   `json:"uuid"`
	URL             string   `json:"url"`
	Side            string   `json:"side"`
	Representation  string   `json:"representation"`
	Bytes           int      `json:"bytes"`
	SHA256          string   `json:"sha256"`
	Complete        bool     `json:"complete"`
	Transformations []string `json:"transformations"`
	Empty           bool     `json:"empty"`
	Output          string   `json:"output,omitempty"`
}

// trafficHeadersReceipt mirrors `traffic headers -j`.
type trafficHeadersReceipt struct {
	UUID      string        `json:"uuid"`
	URL       string        `json:"url"`
	Side      string        `json:"side"`
	Headers   []headerEntry `json:"headers"`
	Count     int           `json:"count"`
	StartLine string        `json:"start_line,omitempty"`
	Name      string        `json:"name,omitempty"`
	Present   *bool         `json:"present,omitempty"`
}

// seedExtras are the top-level keys of `db seed -j`.
type seedExtras struct {
	RowsInserted int `json:"rows_inserted"`
}

// importExtras mirrors the top-level keys `import -j` keeps (importResultJSON,
// mergeResultJSON, burpImportResultJSON). Which set appears depends on the
// source, so every key is optional.
// configEntrySchema mirrors configcmd's configEntryView.
type configEntrySchema struct {
	Key       string `json:"key"`
	Value     any    `json:"value"`
	Display   string `json:"display"`
	Default   any    `json:"default"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Redacted  bool   `json:"redacted"`
}

// configLsExtras are config ls's top-level keys.
type configLsExtras struct {
	ConfigPath  string `json:"config_path"`
	Redacted    bool   `json:"redacted"`
	Filter      string `json:"filter"`
	Effective   bool   `json:"effective"`
	ProjectUUID string `json:"project_uuid,omitempty"`
}

// configEnvSchema mirrors configcmd's configEnvView.
type configEnvSchema struct {
	Name         string `json:"name"`
	Set          bool   `json:"set"`
	Value        string `json:"value,omitempty"`
	Redacted     bool   `json:"redacted"`
	Sensitive    bool   `json:"sensitive"`
	OverridesKey string `json:"overrides_key,omitempty"`
	Template     bool   `json:"template,omitempty"`
	Description  string `json:"description"`
}

// configEnvExtras are config env's top-level keys.
type configEnvExtras struct {
	Redacted bool `json:"redacted"`
}

type importExtras struct {
	// A parsed source (JSONL, audit directory, HAR, …).
	AgenticScanUUID         string         `json:"agentic_scan_uuid,omitempty"`
	RecordsImported         int            `json:"records_imported,omitempty"`
	RecordsSkippedDuplicate int            `json:"records_skipped_duplicate,omitempty"`
	FindingsTotal           int            `json:"findings_total,omitempty"`
	FindingsSaved           int            `json:"findings_saved,omitempty"`
	FindingsSkipped         int            `json:"findings_skipped,omitempty"`
	FindingsFailed          int            `json:"findings_failed,omitempty"`
	Severity                map[string]int `json:"severity,omitempty"`
	ParseErrors             int            `json:"parse_errors,omitempty"`
	SessionDir              string         `json:"session_dir,omitempty"`
	StorageURL              string         `json:"storage_url,omitempty"`

	// Per envelope type (http_record, finding, scan, oast_interaction, scope,
	// agentic_scan): rows written, rows already present, rows of a type this
	// import does not store (module, scope without --include-scopes).
	ImportedByType   map[string]int `json:"imported_by_type,omitempty"`
	DuplicatesByType map[string]int `json:"duplicates_by_type,omitempty"`
	SkippedTypes     map[string]int `json:"skipped_types,omitempty"`

	// A SQLite merge.
	MergedFrom           string `json:"merged_from,omitempty"`
	RecordsMerged        int    `json:"records_merged,omitempty"`
	FindingsMerged       int    `json:"findings_merged,omitempty"`
	FindingsDeduped      int    `json:"findings_deduped,omitempty"`
	ScansMerged          int    `json:"scans_merged,omitempty"`
	AgenticScansMerged   int    `json:"agentic_scans_merged,omitempty"`
	ProjectsMerged       int    `json:"projects_merged,omitempty"`
	FindingRecordsMerged int    `json:"finding_records_merged,omitempty"`
	OASTMerged           int    `json:"oast_merged,omitempty"`

	// A multi-source import: every source with its outcome, and how many
	// failed (the totals above cover the rest).
	Sources       []importSourceStatus `json:"sources,omitempty"`
	SourcesFailed int                  `json:"sources_failed,omitempty"`

	// Artifacts requested alongside the import.
	ReportPath string   `json:"report_path,omitempty"`
	UploadedTo []string `json:"uploaded_to,omitempty"`

	// A live Burp/Caido bridge import (burpbridge.ImportResult).
	BridgeURL string   `json:"bridge_url,omitempty"`
	Source    string   `json:"source,omitempty"`
	Matched   int64    `json:"matched,omitempty"`
	Selected  int      `json:"selected,omitempty"`
	Inserted  int      `json:"inserted,omitempty"`
	Updated   int      `json:"updated,omitempty"`
	Unchanged int      `json:"unchanged,omitempty"`
	Skipped   int      `json:"skipped,omitempty"`
	Oversized int      `json:"oversized,omitempty"`
	Errors    []string `json:"errors,omitempty"`
}
