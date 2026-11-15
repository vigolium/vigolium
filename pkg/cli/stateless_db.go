package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/uptrace/bun"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// globalGlobDB is the --glob-db flag: a glob pattern of local result files
// (.sqlite/.jsonl exports, audit folders, archives) that are merged into one
// throwaway scratch SQLite FILE and read with project scoping off. Registered on the
// read/query commands (finding, traffic, export) and on import. Providing it
// implies stateless-read semantics, so -S is optional alongside it.
var globalGlobDB string

// globalGlobStrict is --glob-strict: fail the read on the first --glob-db source
// that cannot be imported, instead of skipping it. The default stays
// best-effort, because a glob over an engagement directory routinely matches a
// half-written file from a run still in progress and failing the whole read over
// it would be worse than reading the rest.
var globalGlobStrict bool

// globDBSkippedFiles records the --glob-db matches that did NOT make it into the
// merge, in match order, with the reason. Reported on stderr as it happens and in
// the -j envelope's glob_sources at the end, so "matched 40, loaded 37" is a
// fact a consumer can read rather than three warnings it had to scrape.
var globDBSkippedFiles []globSkippedFile

// globDBMatchedCount is how many files the pattern expanded to, before any of
// them were tried.
var globDBMatchedCount int

// globDBParseErrors totals the JSONL lines the merge could not read across every
// loaded source. Those files ARE in the merge (minus those lines), so they are
// not "skipped" — but a consumer deciding whether the corpus is complete needs
// to know, and a stderr warning is not something a -j reader sees.
var globDBParseErrors int

// globSkippedFile is one --glob-db match that was not merged, and why.
type globSkippedFile struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// globImportPath is the importer each --glob-db match is routed through. A
// package var purely as a test seam: the rollback below only matters for a
// source that fails PARTWAY, which no real fixture produces on demand.
var globImportPath = dbimport.ImportPath

// globDBSources records what each --glob-db source file contributed to the
// merged scratch DB, captured in match order by openGlobDB. The findings merge
// assigns fresh sequential autoincrement ids per file, so a finding whose id
// falls in a file's (findingLo, findingHi] range came from that file — which lets
// the finding tree show one db-path root per source file so an analyst sees
// where each finding originated. Empty when not reading through --glob-db.
var globDBSources []globDBSource

// globRecordFile caches the http_record uuid → --glob-db file attribution for
// the records a renderer has actually selected. It is filled on demand by
// resolveGlobRecordSources, not during the merge: the merged corpus can be
// millions of rows and the tree prints a page of them, so an entry per merged
// row was heap spent to answer a question about a few hundred.
//
// http_records are keyed by uuid with no exposed integer id, so attribution goes
// through the scratch rowid (globDBSource.recordLo/recordHi) rather than the
// uuid directly. Empty when not reading through --glob-db.
var globRecordFile map[string]string

// globDBSkipped is the skip set the merge actually ran with, recorded by
// openGlobDB alongside globDBSources and globRecordFile. Anything that needs a
// record the merge may have left out asks globMergeOmittedRecords() rather than
// re-deriving the answer from the flags: the merge is what decided, so a second
// derivation elsewhere is one that can disagree — and the symptom of disagreeing
// is silently empty request/response bytes, not an error.
var globDBSkipped globDBSkipSet

// globMergeOmittedRecords reports whether a --glob-db merge ran and left record
// rows or bodies out of the result, so evidence has to be fetched from the source
// files instead (loadGlobFindingRecords). False for a single --db source, which
// is queried in place with nothing omitted.
func globMergeOmittedRecords() bool {
	return len(globDBSources) > 0 && (globDBSkipped.Records || globDBSkipped.RecordBodies)
}

// globDBSkipSet lets a read command tell openGlobDB which parts of the merge it
// will never read, so they can be skipped. Every field is a negative opt-in and
// the zero value merges everything, so a command that passes nothing — or a new
// one that doesn't know about this — stays correct.
//
// This exists because openGlobDB copies every source whole before the first
// WHERE runs, so anything merged is paid for up front. Over a large glob (a few
// hundred result files is ~10 GB, ~98% of it raw request/response blobs) that is
// minutes of I/O and disk for rows the command will never look at. The merge
// target is a scratch FILE rather than an in-memory database precisely so an
// unskipped merge cannot exceed physical memory — it was in-memory once, and a
// corpus this size collapsed into swap — but skipping what is not read is still
// the difference between seconds and minutes.
//
// Each field is only safe when nothing downstream reads what it drops, and the
// failure mode is silent wrong output rather than an error — so build one from an
// explicit per-command predicate (findingNeedsRecords, trafficRendersRawBodies)
// rather than ad hoc at a call site.
type globDBSkipSet struct {
	// Records omits the http_records table entirely. Safe only for a reader that
	// never resolves a finding's linked records: findings embed their own
	// request/response inline and finding_records has no foreign key into
	// http_records, so findings and the junction still merge intact.
	Records bool

	// RecordBodies keeps every http_records row but omits its
	// raw_request/raw_response columns (~96% of the table's bytes, and nullable).
	// Because rows are kept, counts and metadata predicates are unaffected. Unsafe
	// for anything that prints the raw corpus or filters over it in SQL, where the
	// absent columns make LIKE match nothing (see QueryFilters.UsesRawCorpus).
	// Ignored when Records is set.
	RecordBodies bool

	// RecordFileMap omits the record-uuid → source-file map, whose only consumer
	// is the traffic tree's per-file root labels (globSourceForRecord). Building
	// it re-scans every merged record and holds an entry per row, so a reader that
	// isn't the traffic tree should skip it. See skipRecordFileMap for how Records
	// implies this.
	RecordFileMap bool

	// Findings omits findings, the finding↔record junction, and OAST
	// interactions. Safe only for a reader that never shows a finding and never
	// filters records by one — derive the second half from
	// QueryFilters.UsesLinkedFindings rather than asserting it, since `--severity`
	// joins findings from the RECORDS query and a skip there matches nothing
	// without erroring.
	//
	// It is the one skip that saves Go heap rather than destination bytes. Those
	// three tables need finding-id remapping, so unlike the uuid-keyed tables
	// they cannot be copied set-based: every row is read into a Go slice before
	// the write transaction opens, and a finding row carries its inline request,
	// response, and evidence strings. For `traffic`, which never resolves a
	// finding, that whole corpus is read, held, and copied to be ignored.
	Findings bool
}

// skipRecordFileMap reports whether the record→file map should be left unbuilt.
// Skipping the records themselves implies it: there would be nothing to map.
func (s globDBSkipSet) skipRecordFileMap() bool {
	return s.Records || s.RecordFileMap
}

// expandUserHome resolves a leading ~ (bare, or "~/…") in a path or glob pattern
// to the current user's home directory, leaving everything else byte-for-byte
// intact so glob metacharacters survive.
//
// It matters most for --glob-db: the pattern has to be single-quoted to keep the
// shell from expanding the glob itself, which also suppresses the shell's tilde
// expansion — so '~/scans/*.sqlite' arrives here literally, and filepath.Glob
// has no notion of ~ and would match nothing. ~user is not resolved.
func expandUserHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// globDBMatches expands a --glob-db pattern to the local files it names. Shared
// by every consumer of the flag so one wording of "no such pattern" / "matched
// nothing" reaches the user regardless of which command asked. SQLite sidecars
// (-wal, -shm, -journal) are never sources: a `*.sqlite*` pattern would
// otherwise match a database's own WAL as a second, broken database.
func globDBMatches(pattern string) ([]string, error) {
	matches, err := globSourceFiles(pattern)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		//vigolium:not-usage filesystem state, not the command line
		return nil, fmt.Errorf("--glob-db %q matched no files", pattern)
	}
	return matches, nil
}

// globSourceFiles expands a --glob-db pattern, dropping SQLite sidecars.
func globSourceFiles(pattern string) ([]string, error) {
	matches, err := filepath.Glob(expandUserHome(pattern))
	if err != nil {
		return nil, usageErrorf("invalid --glob-db pattern %q: %w", pattern, err)
	}
	return slices.DeleteFunc(matches, database.IsSQLiteSidecar), nil
}

// openGlobSourceFile opens one --glob-db match as a queryable database, for the
// paths that read matches one at a time rather than merging them: the streaming
// Burp copy (saveGlobToBurp) and the lazy finding-evidence hydration
// (loadGlobFindingRecords). The returned closer disposes of the handle and of
// any temp file behind it.
//
// A plain SQLite result file is queried in place, with no copy, so the memory
// cost is the result set rather than the file. Anything else a glob can match (a
// JSONL export, an archive, an audit folder) has no queryable form on disk and is
// loaded through the same importer the merged path uses — into a temp file for
// the same reason the merge uses one, since a single source can be large enough
// to matter on its own.
//
// It deliberately does not go through clicommon.GetDB: that caches one connection
// process-wide, so the second file — and every file after it — would silently be
// answered by the first.
//
// The SQLite open is read-only, and that is not a precaution — a writable open of
// someone's engagement archive rewrites it just by being opened: the DSN sets
// journal_mode=WAL (which rewrites the header of a file left in `delete` mode and
// changes its hash), the open runs wal_checkpoint(TRUNCATE) over both the main
// file and its sidecar, a background checkpointer starts truncating the WAL every
// five minutes, and Close runs PRAGMA optimize to write sqlite_stat1. `--glob-db`
// is a read: none of that may happen to the files it names.
func openGlobSourceFile(ctx context.Context, path string) (*database.DB, func(), error) {
	if isSQLite, err := database.IsSQLiteFile(path); err == nil && isSQLite {
		cfg := config.DefaultDatabaseConfig()
		cfg.Driver = "sqlite"
		cfg.SQLite.Path = path
		cfg.SQLite.ReadOnly = true
		db, err := database.NewDB(cfg)
		if err != nil {
			return nil, nil, err
		}
		return db, func() { _ = db.Close() }, nil
	}

	db, dir, err := newTempDB("source")
	if err != nil {
		return nil, nil, err
	}
	closeDB := func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
	if err := db.EnsureSchemaReady(ctx); err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("initialize scratch schema: %w", err)
	}
	if _, err := dbimport.ImportPath(ctx, database.NewRepository(db), path, "", dbimport.Options{}); err != nil {
		closeDB()
		return nil, nil, err
	}
	return db, closeDB, nil
}

// globDBSource is one --glob-db file and the id ranges it added to the scratch
// database. Each merge runs to completion before the next begins, and rows are
// inserted with fresh sequential ids/rowids, so a file owns one contiguous range
// per table.
type globDBSource struct {
	file      string
	findingLo int64 // findings with id in (findingLo, findingHi] came from this file
	findingHi int64
	recordLo  int64 // http_records with rowid in (recordLo, recordHi] came from this file
	recordHi  int64
}

// globDBMergedCount reports how many files openGlobDB merged.
func globDBMergedCount() int { return len(globDBSources) }

// globSourceForFinding returns the source file a merged finding id came from, or
// "" if it can't be attributed (single-DB read, or a deduped row).
func globSourceForFinding(id int64) string {
	return globSourceInRange(id, func(s globDBSource) (int64, int64) { return s.findingLo, s.findingHi })
}

// globSourceForRecordRowID maps a scratch-database rowid back to the file whose
// merge inserted it.
func globSourceForRecordRowID(rowid int64) string {
	return globSourceInRange(rowid, func(s globDBSource) (int64, int64) { return s.recordLo, s.recordHi })
}

// globSourceInRange finds the source whose half-open (lo, hi] range contains id.
//
// One implementation for both id spaces so the boundary convention cannot be
// fixed in one and missed in the other. Binary search rather than a scan: the
// ranges are appended in merge order and each file's hi is the next file's lo, so
// they are already sorted — and the caller resolves one id per rendered record,
// which over an 854-file glob made a linear probe O(records x files).
func globSourceInRange(id int64, bounds func(globDBSource) (lo, hi int64)) string {
	i := sort.Search(len(globDBSources), func(i int) bool {
		_, hi := bounds(globDBSources[i])
		return id <= hi
	})
	if i == len(globDBSources) {
		return ""
	}
	lo, hi := bounds(globDBSources[i])
	if id > lo && id <= hi {
		return globDBSources[i].file
	}
	return ""
}

// globSourceForRecord returns the source file a merged http_record uuid came
// from, or "" when not attributable (single-DB read, a deduped row, or a uuid
// that resolveGlobRecordSources was not given).
//
// It answers from a cache that covers only the records a renderer actually
// selected — call resolveGlobRecordSources with the page first.
func globSourceForRecord(uuid string) string { return globRecordFile[uuid] }

// resolveGlobRecordSources fills the uuid → source-file cache for these records
// and no others. Idempotent: a uuid already resolved is not looked up again, so
// the tree's two consumers (redirect hydration, then the per-file roots) share
// one lookup.
//
// It exists because the attribution used to be built eagerly, during the merge,
// by selecting every inserted uuid back out and holding a map entry per row. On
// the corpora --glob-db is for — hundreds of files, millions of records — that
// map is hundreds of megabytes of Go heap, allocated to answer a question about
// the few hundred rows that survive the WHERE clause and get printed.
//
// The rowid ranges recorded at merge time replace it: they cost one small struct
// per FILE, and turning a uuid into a file is then one indexed lookup over the
// selected page. This mirrors how finding attribution has always worked.
func resolveGlobRecordSources(ctx context.Context, db *database.DB, records []*database.HTTPRecord) {
	// No ranges were recorded, so there is nothing any query could resolve —
	// return before issuing one rather than asking and discarding every row.
	if db == nil || len(globDBSources) == 0 || globDBSkipped.skipRecordFileMap() {
		return
	}
	if globRecordFile == nil {
		globRecordFile = make(map[string]string)
	}
	pending := make([]string, 0, len(records))
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if _, seen := globRecordFile[rec.UUID]; !seen {
			// Seeded as unattributable so a uuid the query does not return is
			// still "asked and answered" — otherwise every unattributable record
			// is re-queried by the next consumer, which is the opposite of the
			// shared lookup this cache promises.
			globRecordFile[rec.UUID] = ""
			pending = append(pending, rec.UUID)
		}
	}
	if len(pending) == 0 {
		return
	}

	for chunk := range slices.Chunk(pending, database.SQLChunkSize) {
		rows, err := db.NewSelect().
			Model((*database.HTTPRecord)(nil)).
			ColumnExpr("uuid").
			ColumnExpr("rowid").
			Where("uuid IN (?)", bun.List(chunk)).
			Rows(ctx)
		if err != nil {
			// Attribution is a display detail: without it the tree falls back to
			// a single shared root, which is the pre---glob-db rendering rather
			// than a wrong one. Failing the listing over it would be worse.
			zap.L().Debug("glob record attribution unavailable", zap.Error(err))
			return
		}
		for rows.Next() {
			var uuid string
			var rowid int64
			if err := rows.Scan(&uuid, &rowid); err != nil {
				continue
			}
			globRecordFile[uuid] = globSourceForRecordRowID(rowid)
		}
		_ = rows.Close()
	}
}

// maxRowID returns the current MAX(col) of a table (0 when empty), used to
// snapshot per-file id/rowid ranges around each glob merge. col is a fixed
// literal ("id"/"rowid"), not user input.
//
// A failed probe reads as 0, which is right for its caller: attribution degrades
// to "unattributable", the pre---glob-db rendering. Anything that would DELETE
// relative to the answer must use maxRowIDStrict instead — there, 0 means
// "remove every row in the table".
func maxRowID(ctx context.Context, db *database.DB, table, col string) int64 {
	id, _ := maxRowIDStrict(ctx, db, table, col)
	return id
}

// maxRowIDStrict is maxRowID with the error kept.
func maxRowIDStrict(ctx context.Context, db *database.DB, table, col string) (int64, error) {
	var id int64
	if err := db.SQLDB().QueryRowContext(ctx, fmt.Sprintf("SELECT COALESCE(MAX(%s), 0) FROM %s", col, table)).Scan(&id); err != nil {
		return 0, fmt.Errorf("read MAX(%s) of %s: %w", col, table, err)
	}
	return id, nil
}

// globMergeMarks is the scratch database's high-water mark in every table a
// --glob-db merge writes to, taken immediately before one source is imported.
//
// It exists because ImportPath is not atomic: the JSONL importer flushes records
// in batches as it parses, and the SQLite merge commits per table, so a source
// that fails on its last line has already written everything before it. Without a
// mark to undo back to, `--glob-db '*.jsonl'` over a directory with one truncated
// file answered queries from a silently half-merged corpus — and reported the
// file as "skipped", which said the opposite.
//
// projects is deliberately absent: a projects row is shared metadata that a later
// source may legitimately reference, and the rows this would remove carry no scan
// data. Leaving them costs an unreferenced row in a throwaway database.
type globMergeMarks struct {
	findings     int64
	records      int64
	agenticScans int64
	scans        int64
	oast         int64
}

// globMergeMarksAt snapshots the scratch database. Any probe failure is returned
// rather than defaulted, because a 0 here would make the rollback below delete
// the whole table.
func globMergeMarksAt(ctx context.Context, db *database.DB) (globMergeMarks, error) {
	var (
		m   globMergeMarks
		err error
	)
	for _, probe := range []struct {
		dst   *int64
		table string
		col   string
	}{
		// findings/agentic_scans/oast_interactions have an AUTOINCREMENT integer
		// id; scans and http_records are keyed by uuid, so their insertion order
		// is only visible through the implicit rowid.
		{&m.findings, "findings", "id"},
		{&m.records, "http_records", "rowid"},
		{&m.agenticScans, "agentic_scans", "id"},
		{&m.scans, "scans", "rowid"},
		{&m.oast, "oast_interactions", "id"},
	} {
		if *probe.dst, err = maxRowIDStrict(ctx, db, probe.table, probe.col); err != nil {
			return globMergeMarks{}, err
		}
	}
	return m, nil
}

// rollbackGlobMerge removes everything inserted into the scratch database after
// marks were taken, undoing one failed source's partial merge.
//
// Not a transaction: ImportPath owns its own transactions (several, in the SQLite
// merge) and runs on the shared connection, so wrapping it in an outer one is not
// available. These statements are, which is why the marks are per-source rather
// than a savepoint.
func rollbackGlobMerge(ctx context.Context, db *database.DB, marks globMergeMarks) error {
	for _, stmt := range []struct {
		sql  string
		mark int64
	}{
		// finding_records before findings: it is keyed by finding_id, and once the
		// findings are gone the junction rows are orphans with nothing to identify
		// them by.
		{"DELETE FROM finding_records WHERE finding_id > ?", marks.findings},
		{"DELETE FROM findings WHERE id > ?", marks.findings},
		{"DELETE FROM http_records WHERE rowid > ?", marks.records},
		{"DELETE FROM agentic_scans WHERE id > ?", marks.agenticScans},
		{"DELETE FROM scans WHERE rowid > ?", marks.scans},
		{"DELETE FROM oast_interactions WHERE id > ?", marks.oast},
	} {
		if _, err := db.ExecContext(ctx, stmt.sql, stmt.mark); err != nil {
			return fmt.Errorf("%s: %w", stmt.sql, err)
		}
	}
	return nil
}

// statelessReadRequested reports whether a read/query command should source its
// data from a standalone file rather than the shared project DB — true under
// -S/--stateless, whenever --glob-db is set (which implies stateless), or when
// $VIGOLIUM_DB_PATH pinned the shell to a session database.
//
// Every read path funnels through here (openReadDB, openExportDB,
// effectiveProjectUUID), which is why the env var implies its read semantics
// here rather than by enumerating command names: a command is covered the
// moment it asks this question, including ones that never register -S at all
// (`fuzz -u <uuid>` resolves a record through effectiveProjectUUID).
func statelessReadRequested() bool {
	return globalStateless || strings.TrimSpace(globalGlobDB) != "" || dbPathEnvAutoStateless
}

// statelessSourceError reports why path cannot back a stateless read, or nil
// when it can. openStatelessDB surfaces the error; applyDBPathEnv only needs the
// yes/no (statelessSourceUsable) to decide whether to imply a stateless read at
// all. Both read the same rule, so the gate can't drift from the opener whose
// outcome it exists to predict.
func statelessSourceError(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		//vigolium:not-usage stat failure; classified source_missing by the wrapped os error
		return fmt.Errorf("--db %q: %w", path, err)
	}
	if info.IsDir() {
		//vigolium:not-usage filesystem state, not the command line
		return fmt.Errorf("--db %q is a directory; expected a .jsonl export or .sqlite file", path)
	}
	return nil
}

// statelessSourceUsable reports whether path can back a stateless read.
func statelessSourceUsable(path string) bool { return statelessSourceError(path) == nil }

// openReadDB returns the database for read/query commands (traffic, finding).
// Under -S/--stateless (or --glob-db) it reads from the --db source directly (a
// JSONL export or a standalone SQLite file) or the merged --glob-db set;
// otherwise it returns the shared project DB.
//
// skip narrows what a --glob-db merge copies; pass the zero globDBSkipSet to
// merge everything (it is ignored unless --glob-db is set).
func openReadDB(skip globDBSkipSet) (*database.DB, error) {
	if statelessReadRequested() {
		return openStatelessDB(skip)
	}
	return getDB()
}

// readSourcePath names the SOURCE this read is about: the thing another
// invocation could be pointed at, which is not always the file that was opened.
//
// Under a stateless read the opened database is a scratch file deleted on exit,
// so the answer is the source that was loaded into it. Otherwise it is the path
// clicommon recorded at open — the single resolution of
// --db → VIGOLIUM_DB_PATH → config → default, already settled by the time any
// caller asks. Re-deriving that tail is how a label ends up naming a file
// nothing opened.
func readSourcePath() string {
	if statelessReadRequested() {
		if raw := strings.TrimSpace(globalDB); raw != "" {
			return raw
		}
	}
	return strings.TrimSpace(clicommon.OpenedDBPath())
}

// displayDBPath returns a human-readable label for the database currently being
// read, used as the root node of the traffic/finding --tree views (home
// shortened to ~).
func displayDBPath() string {
	// A glob is a pattern, not a single file — make the merged nature explicit.
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" {
		if n := globDBMergedCount(); n > 0 {
			return fmt.Sprintf("%s (%d databases merged)", terminal.ShortenHome(pattern), n)
		}
		return terminal.ShortenHome(pattern)
	}
	if src := readSourcePath(); src != "" {
		return terminal.ShortenHome(src)
	}
	return terminal.ShortenHome(config.DefaultDatabaseConfig().SQLite.Path)
}

// explicitProjectSelected reports whether the operator named a project, by flag
// or by the equivalent environment variable.
//
// It is the flags, not the resolution: resolveProjectUUID falls back to the
// persisted active project and then to the default project, so a non-empty
// result there says nothing about whether anyone asked. root.go folds
// VIGOLIUM_PROJECT_UUID / VIGOLIUM_PROJECT_NAME into these globals before any
// command body runs, so both ways of asking are covered here.
func explicitProjectSelected() bool {
	return strings.TrimSpace(globalProjectUUID) != "" || strings.TrimSpace(globalProjectName) != ""
}

// effectiveProjectUUID is the project filter for read/query commands.
//
// Default scoping for a standalone source (-S/--stateless, --glob-db, or a
// VIGOLIUM_DB_PATH pin) is off, because the file carries whatever project_uuid
// it was exported under and scoping to the local active project would show
// nothing. But an operator who NAMES a project is asking for a filter, and
// silently ignoring it meant `finding -S --db merged.jsonl --project-uuid X`
// listed every project in the file while looking like it had narrowed.
//
// --project-name under a standalone source is the one case this rejects rather
// than honors, and the reason is which store the name is looked up in.
// resolveProjectUUID resolves a name through getDB, which is the --db path — so
// for a standalone .sqlite (including a VIGOLIUM_DB_PATH pin) it hits the source
// and is correct whenever it is called. A JSONL export and a --glob-db merge
// have no project registry at all (projects are not an exported type), so the
// lookup would silently resolve against the DEFAULT database and then filter the
// standalone source by a UUID that matches nothing in it: an empty result that
// reads exactly like "this file has no findings". The error names
// --project-uuid, which needs no lookup and works on every source.
func effectiveProjectUUID() (string, error) {
	if !statelessReadRequested() {
		return resolveProjectUUID()
	}
	if !explicitProjectSelected() {
		return "", nil
	}
	if strings.TrimSpace(globalProjectUUID) == "" && statelessSourceLacksProjects() {
		return "", usageErrorf(
			"--project-name cannot be resolved against %s: a JSONL export and a --glob-db merge carry no project registry to look the name up in.\n\nUse --project-uuid %s, which needs no lookup",
			statelessSourceLabel(), "<uuid>")
	}
	uuid, err := resolveProjectUUID()
	if err != nil {
		return "", err
	}
	noteEnvProjectFilter(uuid)
	return uuid, nil
}

// statelessSourceLacksProjects reports whether the standalone source for this
// read is one that carries no projects table rows — a JSONL export loaded into a
// scratch database, or a --glob-db merge of them.
func statelessSourceLacksProjects() bool {
	if strings.TrimSpace(globalGlobDB) != "" {
		return true
	}
	path := strings.TrimSpace(globalDB)
	return path != "" && isJSONLSource(path)
}

// statelessSourceLabel names the standalone source for an error message.
func statelessSourceLabel() string {
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" {
		return "--glob-db " + pattern
	}
	return "--db " + strings.TrimSpace(globalDB)
}

// noteEnvProjectFilter prints one line when the project filter applied to a
// standalone read came from the environment rather than from the command line.
//
// A flag is visible in the command the operator just typed; an exported
// VIGOLIUM_PROJECT_UUID is not, and "my export has 400 rows but vigolium shows
// 3" is otherwise a long debugging session. Printed at most once per process,
// and never in a machine-output mode.
func noteEnvProjectFilter(uuid string) {
	if !projectFromEnv || uuid == "" || machineOutputMode() {
		return
	}
	envProjectNoticeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "%s project filter %s from %s applied to a stateless read\n",
			terminal.InfoSymbol(), terminal.BoldYellow(uuid), terminal.BoldCyan("$VIGOLIUM_PROJECT_*"))
	})
}

var envProjectNoticeOnce sync.Once

// openStatelessDB resolves the -S/--stateless data source named by --db. The
// source may be either:
//
//   - a standalone .sqlite file — opened directly (read-only intent), or
//   - a {"type":...,"data":{...}} JSONL export (e.g. from
//     `vigolium scan --format jsonl`) — loaded into a throwaway scratch SQLite
//     file so every existing filter / sort / display path runs unchanged.
//
// Callers query with ProjectUUID="" (project scoping off), so all rows in the
// file are shown regardless of the project_uuid they were exported under.
func openStatelessDB(skip globDBSkipSet) (*database.DB, error) {
	// --glob-db expands to many files merged into one scratch DB; it takes
	// precedence over a single --db source.
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" {
		return openGlobDB(pattern, skip)
	}
	if strings.TrimSpace(globalDB) == "" {
		return nil, usageErrorf("--stateless requires --db <file.jsonl|file.sqlite> or --glob-db <pattern>")
	}
	path := globalDB
	if err := statelessSourceError(path); err != nil {
		return nil, err
	}

	if isJSONLSource(path) {
		return loadStatelessJSONL(path)
	}
	// Standalone SQLite: open directly via the shared connection cache (honours
	// --config); --db already points the cache at this file.
	return clicommon.GetDB(globalConfig, path)
}

// loadStatelessJSONL parses a {type,data} JSONL export into a fresh scratch
// SQLite file and returns it. The finding↔record linkage is preserved by the
// importer, so finding --raw / --with-records resolves linked records too.
func loadStatelessJSONL(path string) (*database.DB, error) {
	ctx := context.Background()

	db, err := newScratchDB("stateless")
	if err != nil {
		return nil, err
	}
	if err := db.EnsureSchemaReady(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize scratch schema: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open --db %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// PreserveProjectUUID: this scratch database is a read-only view of the file,
	// so each row keeps the project it was exported under. Stamping the default
	// project over them made the project_uuid in `finding -S -j` output a fact
	// about the reader, and made an explicit --project-uuid filter over the source
	// match either everything or nothing. The "" target still homes a row that
	// carried no project of its own.
	res, err := dbimport.ImportJSONL(ctx, database.NewRepository(db), f, "", dbimport.Options{
		PreserveProjectUUID: true,
		ImportScopes:        true,
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to load JSONL from %q: %w", path, err)
	}

	fmt.Fprintf(os.Stderr, "%s Stateless: loaded %d HTTP record(s) and %d finding(s) from %s\n",
		terminal.InfoSymbol(), res.RecordsImported, res.FindingsTotal, terminal.Cyan(filepath.Base(path)))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// openGlobDB expands pattern to local result files and merges them all into a
// single throwaway scratch SQLite FILE (not an in-memory database — a merge of
// several exports does not have to fit in RAM), which callers query with
// project scoping off. Each match is imported by its own detected type via
// dbimport.ImportPath (SQLite→SQLite merge, JSONL export, audit folder, or
// archive), so a glob can mix formats. A match that fails to import is skipped
// with a warning rather than aborting the whole read. Returns an error when the
// pattern is invalid, matches nothing, or nothing could be loaded.
func openGlobDB(pattern string, skip globDBSkipSet) (*database.DB, error) {
	matches, err := globDBMatches(pattern)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	db, err := newScratchDB("glob")
	if err != nil {
		return nil, err
	}
	// The scratch store is filled once and then only read, which is the one shape
	// that can postpone the http_records read indexes: during the merge they are
	// thirteen b-tree insertions per row, keyed mostly on a random uuid, and no
	// query runs until every file is in. They are built below, once, over the
	// finished table.
	db.DeferRecordIndexes()
	if err := db.EnsureSchemaReady(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize scratch schema: %w", err)
	}
	repo := database.NewRepository(db)

	// projectUUID "" plus PreserveProjectUUID → every source keeps each row's
	// original project, which is what a SQLite merge already did. JSONL rows used
	// to be re-homed onto the default project instead, so a glob of two projects'
	// exports read back as one project and an explicit --project-uuid over the
	// merge matched nothing. Callers query with ProjectUUID="" unless the operator
	// named a project.
	globDBSources = nil
	globDBSkippedFiles = nil
	globDBParseErrors = 0
	globDBMatchedCount = len(matches)
	globDBSkipped = skip
	globRecordFile = make(map[string]string)
	// Both decisions are properties of the skip set, not of any one file.
	trackFiles := !skip.skipRecordFileMap()
	trackFindings := !skip.Findings

	// Each file's high-water mark is the next file's low-water mark — merges run
	// strictly in sequence against a private scratch database, so nothing else
	// can insert between them. Carrying the marks forward halves the probes and,
	// more importantly, makes the ranges contiguous by construction rather than
	// by two separate reads agreeing.
	var fMark, rMark int64
	var loaded, totalRecords, totalFindings int
	for _, m := range matches {
		marks, markErr := globMergeMarksAt(ctx, db)
		if markErr != nil {
			_ = db.Close()
			//vigolium:not-usage database failure during the merge
			return nil, fmt.Errorf("--glob-db: cannot snapshot the scratch database before %s: %w", m, markErr)
		}
		res, impErr := globImportPath(ctx, repo, m, "", dbimport.Options{
			SkipHTTPRecords:     skip.Records,
			SkipRecordBodies:    skip.RecordBodies,
			SkipFindings:        skip.Findings,
			PreserveProjectUUID: true,
			ImportScopes:        true,
		})
		// A source whose findings the scratch store refused is a source that did
		// not fully load, even though ImportPath returns no error for it. Counting
		// it as loaded would attribute a gap in the merged corpus to the source
		// file rather than to this read.
		if impErr == nil && res != nil && res.FindingsFailed > 0 {
			impErr = fmt.Errorf("%d finding(s) could not be stored in the merge", res.FindingsFailed)
		}
		// Unparseable lines are different: the rest of the file is real data, and
		// dropping a 40,000-line export over one truncated line would lose more
		// than it protects. So a lenient read keeps it and SAYS so — under
		// --glob-strict, where the caller has asked for no short answers, it is a
		// failure like any other.
		if impErr == nil && res != nil && res.ParseErrors > 0 {
			globDBParseErrors += res.ParseErrors
			if globalGlobStrict {
				impErr = fmt.Errorf("%d line(s) could not be parsed", res.ParseErrors)
			} else {
				fmt.Fprintf(os.Stderr, "%s --glob-db: %s: %d line(s) could not be parsed and were dropped\n",
					terminal.WarningSymbol(), terminal.Cyan(m), res.ParseErrors)
			}
		}
		if impErr != nil {
			// Undo whatever it managed to write. ImportPath commits as it goes, so
			// "skipped" used to mean "partially merged and reported as absent" —
			// the one outcome a merged read cannot survive, because nothing
			// downstream can tell a truncated source from a short one.
			if rbErr := rollbackGlobMerge(ctx, db, marks); rbErr != nil {
				_ = db.Close()
				// rbErr is the %w cause; impErr is flattened to its text on
				// purpose. An import failure routinely wraps os.ErrNotExist, and
				// adding that to the chain makes classifyErrorCode report
				// source_missing — which names a missing file when what actually
				// happened is an inconsistent scratch database.
				//vigolium:not-usage database failure during the merge
				return nil, fmt.Errorf("--glob-db: %s failed to import (%s) and its partial rows could not be removed, so the merge is inconsistent: %w",
					m, impErr.Error(), rbErr)
			}
			if globalGlobStrict {
				_ = db.Close()
				//vigolium:not-usage import failure during the merge
				return nil, fmt.Errorf("--glob-db: %s: %w", m, impErr)
			}
			globDBSkippedFiles = append(globDBSkippedFiles, globSkippedFile{File: m, Error: impErr.Error()})
			fmt.Fprintf(os.Stderr, "%s --glob-db: skipped %s: %v\n", terminal.WarningSymbol(), terminal.Cyan(m), impErr)
			continue
		}
		src := globDBSource{file: m}
		// Recording a range is the whole cost of attribution now: one scalar
		// probe per file per id space, versus a scan of every inserted row. A
		// reader resolves ids out of it on demand — see resolveGlobRecordSources.
		if trackFindings {
			src.findingLo = fMark
			fMark = maxRowID(ctx, db, "findings", "id")
			src.findingHi = fMark
		}
		if trackFiles {
			src.recordLo = rMark
			rMark = maxRowID(ctx, db, "http_records", "rowid")
			src.recordHi = rMark
		}
		globDBSources = append(globDBSources, src)
		loaded++
		totalRecords += res.RecordsImported
		totalFindings += res.FindingsTotal
	}
	if loaded == 0 {
		_ = db.Close()
		//vigolium:not-usage every source failed to load, after I/O
		return nil, fmt.Errorf("--glob-db %q: none of the %d matched file(s) could be loaded", pattern, len(matches))
	}

	// The load is over; build what the reads need. Failing here is not fatal —
	// without the indexes the queries still answer correctly, just by scanning —
	// so it warns rather than discarding a merge that may have taken minutes.
	if err := db.CreateRecordIndexes(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s --glob-db: read indexes unavailable, queries will be slower: %v\n",
			terminal.WarningSymbol(), err)
	}
	// Plan against the merged row counts rather than SQLite's defaults; the
	// statistics the sources carried describe their own tables, not this one.
	//
	// Bounded: the scratch store has no sqlite_stat1 and thirteen indexes that
	// were just built, so a plain `PRAGMA optimize` treats every one as stale and
	// scans it in full — minutes of b-tree reads over the merged corpus with
	// nothing rendered yet. analysis_limit is SQLite's documented sampling cap and
	// gives the planner the same order-of-magnitude estimates in milliseconds.
	if _, err := db.ExecContext(ctx, "PRAGMA analysis_limit=400"); err != nil {
		zap.L().Debug("could not bound scratch ANALYZE sampling", zap.Error(err))
	}
	db.Optimize(ctx)

	// A skipped table's counter is 0, and printing that would claim the source
	// files held no traffic (or no findings) when they were simply not copied.
	// Report only what was actually merged.
	var parts []string
	if !skip.Records {
		parts = append(parts, fmt.Sprintf("%d HTTP record(s)", totalRecords))
	}
	if !skip.Findings {
		parts = append(parts, fmt.Sprintf("%d finding(s)", totalFindings))
	}
	counts := strings.Join(parts, ", ")
	if counts == "" {
		counts = "metadata only"
	}
	// State the denominator. "merged 37 files" next to a pattern that matched 40
	// reads as a complete answer unless the three warnings above happened to still
	// be on screen.
	skipNote := ""
	if n := len(globDBSkippedFiles); n > 0 {
		skipNote = fmt.Sprintf(" (%d of %d skipped)", n, globDBMatchedCount)
	}
	fmt.Fprintf(os.Stderr, "%s Stateless: merged %d file(s)%s — %s — from %s\n",
		terminal.InfoSymbol(), loaded, skipNote, counts, terminal.Cyan(pattern))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// attachGlobSources records, in the -j envelope, what the --glob-db pattern
// matched and what actually made it into the merge.
//
// Without it the only account of a skipped source was a stderr warning, which a
// driver consuming stdout never sees — so a merged read over a directory with one
// unreadable file returned a short, well-formed, confident answer. `matched` and
// `loaded` differing is the signal; `skipped` says which files and why.
//
// It is attached for every --glob-db read, including the clean one, so a consumer
// can assert matched == loaded rather than infer completeness from an absent key.
func attachGlobSources(env *agentEnvelope) {
	pattern := strings.TrimSpace(globalGlobDB)
	if env == nil || pattern == "" {
		return
	}
	skipped := globDBSkippedFiles
	if skipped == nil {
		skipped = []globSkippedFile{}
	}
	env.With("glob_sources", map[string]any{
		"pattern":      pattern,
		"matched":      globDBMatchedCount,
		"loaded":       globDBMergedCount(),
		"skipped":      skipped,
		"parse_errors": globDBParseErrors,
	})
}

// openExportDB returns the database for `vigolium export`. It honors --glob-db
// (merge a glob of result files) and -S/--stateless (a single standalone --db
// source) so the export commands can read from ad-hoc files, falling back to the
// shared project DB. Export already reads whole-DB (project scoping off), so a
// standalone source needs no further project handling.
func openExportDB() (*database.DB, error) {
	if statelessReadRequested() {
		// Export streams whole records, bodies included, so it merges everything.
		return openStatelessDB(globDBSkipSet{})
	}
	return getDB()
}

// isJSONLSource decides whether --db points at a JSONL export (true) or a
// SQLite database (false). It trusts a known extension, otherwise sniffs the
// file header: SQLite files begin with the magic string "SQLite format 3\0",
// while a JSONL export begins with '{'.
func isJSONLSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson":
		return true
	case ".sqlite", ".sqlite3", ".db":
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	head := buf[:n]
	if database.HasSQLiteHeader(head) {
		return false
	}
	// First non-whitespace byte: '{' marks a JSON envelope line.
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
