package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/replay/jar"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	replayRecordUUID     string
	replayFindingID      int64
	replayInput          string
	replayInputFile      string
	replayMutations      []string
	replayRawRequest     string
	replayRawRequestFile string
	replayHeaders        []string
	replayAuthSession    string
	replaySessionID      string
	replayNoCookies      bool
	replayNoRedirects    bool
	replayTargetURL      string
	replayTimeout        time.Duration
	replayInReplaceTop   bool
	replayOutputPath     string
	replayPretty         bool

	// Bulk-selection flags — when any is set, replay iterates the matching
	// stored records instead of a single source (mirrors `traffic --replay`,
	// but each record runs through the mutation/diff engine).
	replayAll         bool
	replayBulkHost    string
	replayBulkMethods []string
	replayBulkStatus  []int
	replayBulkPath    string
	replayBulkSource  string
	replayBulkSearch  string
	replayBulkBody    string
	replayBulkLimit   int
	replayConcurrency int
)

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Mutate a stored or supplied HTTP request and diff baseline vs replay",
	Long: `Replay an HTTP request — stored record, finding evidence, curl command, raw HTTP, ` +
		`Burp XML, base64, or URL — with optional insertion-point mutations, and emit a ` +
		`baseline-vs-replay diff (status, length, content-hash, payload reflection).

The same engine that powers the autopilot's in-process replay_request tool. Use this
to drive vigolium externally (Claude Code, Cursor, Pi, CI scripts) — the JSON output
shape is stable so an agent can confirm a finding without parsing terminal output.

Cookies set by one replay persist to the next when --session-id is provided. Routes
through HTTP_PROXY / HTTPS_PROXY (or --proxy) for Burp-style inspection.

Bulk mode: pass --all (or any of --host/--method/--status/--path/--source/--search/
--body) to replay every matching stored record instead of a single source — like
'vigolium traffic --replay', but each record runs through the mutation/diff engine
and results stream as JSONL (one object per record). Any --mutate is applied to
every record that has that insertion point; without --mutate each record is re-sent
verbatim. Throttle with -c/--concurrency and read a standalone export with -S --db.`,
	// Example is set in usage.go (replayExamples) so it renders colored like the
	// other commands via FormatExamples.
	RunE: runReplay,
}

func init() {
	rootCmd.AddCommand(replayCmd)
	f := replayCmd.Flags()

	// Source flags — exactly one of these resolves the baseline.
	f.StringVarP(&replayRecordUUID, "record-uuid", "u", "", "Stored HTTP record UUID to use as baseline")
	f.Int64Var(&replayFindingID, "finding-id", 0, "Finding ID — replay the finding's linked record (or its stored evidence)")
	f.StringVarP(&replayInput, "input", "i", "", "Raw input: curl, raw HTTP, Burp XML, base64, URL, or '-' for stdin")
	f.StringVar(&replayInputFile, "input-file", "", "Read --input value from a file")

	// Mutations / raw override.
	f.StringArrayVarP(&replayMutations, "mutate", "m", nil,
		"Insertion-point mutation 'name=...,type=...,payload=...' or 'name:type:payload' (repeatable)")
	f.StringVar(&replayRawRequest, "raw-request", "", "Full raw HTTP request override (mutually exclusive with --mutate)")
	f.StringVar(&replayRawRequestFile, "raw-request-file", "", "Read --raw-request from a file")

	// Header / auth merges.
	f.StringArrayVarP(&replayHeaders, "header", "H", nil, "Extra request header 'Name: value' (repeatable, overrides baseline)")
	f.StringVar(&replayAuthSession, "auth-session", "", "Auth session name to merge headers from (from 'vigolium auth list')")

	// Session / cookies.
	f.StringVar(&replaySessionID, "session-id", "",
		"Persist cookies across calls under ~/.vigolium/replay-jars/<id>.json")
	f.BoolVar(&replayNoCookies, "no-cookies", false, "Don't carry cookies (overrides --session-id)")

	// Network behaviour.
	f.BoolVar(&replayNoRedirects, "no-redirects", false, "Don't follow 30x redirects")
	f.StringVarP(&replayTargetURL, "target", "t", "", "Override scheme/host/port (e.g. https://staging.example.com)")
	f.DurationVar(&replayTimeout, "timeout", replay.DefaultTimeout, "Per-request timeout (e.g. 30s, 1m)")

	// Result handling.
	f.BoolVar(&replayInReplaceTop, "in-replace", false,
		"When the source is a stored record, update its stored response with the replay")
	f.StringVarP(&replayOutputPath, "output", "o", "", "Write JSON result to this file (default: stdout)")
	f.BoolVar(&replayPretty, "pretty", false, "Human-readable summary instead of JSON")

	// Bulk selection — mirror the traffic filters. Setting any of these (or
	// --all) switches replay into bulk mode over the matching stored records.
	f.BoolVarP(&replayAll, "all", "a", false, "Bulk: replay every matched stored record (lifts the -n/--limit cap); re-send all stored traffic")
	f.StringVar(&replayBulkHost, "host", "", "Bulk: filter records by hostname pattern (wildcard supported)")
	f.StringSliceVar(&replayBulkMethods, "method", nil, "Bulk: filter records by HTTP method (repeatable)")
	f.IntSliceVar(&replayBulkStatus, "status", nil, "Bulk: filter records by stored status code (repeatable)")
	f.StringVar(&replayBulkPath, "path", "", "Bulk: filter records by URL path pattern")
	f.StringVar(&replayBulkSource, "source", "", "Bulk: filter records by source (scanner, ingest-cli, ingest-proxy, seed, ...)")
	f.StringVar(&replayBulkSearch, "search", "", "Bulk: fuzzy-search records across URLs, paths, and hostnames")
	f.StringVar(&replayBulkBody, "body", "", "Bulk: filter records whose request/response body contains this text")
	f.IntVarP(&replayBulkLimit, "limit", "n", 100, "Bulk: max records to replay (use --all to lift the cap)")
	f.IntVarP(&replayConcurrency, "concurrency", "c", 10, "Bulk: concurrent replays; keep low to avoid overwhelming an intercepting proxy like Burp")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read records from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
}

func runReplay(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mutations, err := parseReplayMutations()
	if err != nil {
		return err
	}

	rawOverride, err := loadReplayRawOverride()
	if err != nil {
		return err
	}
	if rawOverride != nil && len(mutations) > 0 {
		return fmt.Errorf("--mutate and --raw-request / --raw-request-file are mutually exclusive")
	}

	pj, jarLoaded, jarErr := openReplayJar()
	if jarErr != nil {
		fmt.Fprintf(os.Stderr, "%s replay: cookie jar disabled (%v)\n", terminal.WarningSymbol(), jarErr)
	}
	rr := &replayRun{
		mutations:   mutations,
		rawOverride: rawOverride,
		client:      newReplayClient(pj, replayTimeout),
		pj:          pj,
		jarLoaded:   jarLoaded,
	}

	// Bulk mode: iterate every matching stored record through the same engine.
	if replayBulkRequested() {
		return runReplayBulk(ctx, rr)
	}

	src, err := resolveReplaySource(ctx)
	if err != nil {
		return err
	}

	overlay, err := buildReplayOverlay(ctx, src)
	if err != nil {
		return err
	}

	if replayTargetURL != "" {
		if err := applyTargetOverride(src, replayTargetURL); err != nil {
			return err
		}
	}

	out, err := rr.one(ctx, src, overlay)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}

	saveReplayJar(pj)

	if replayPretty {
		return emitReplayPretty(out)
	}
	return emitReplayJSON(out)
}

// replayRun bundles the per-invocation replay settings that don't vary across
// records, so the single-source and bulk paths share one call shape instead of
// threading the same five values through every signature.
type replayRun struct {
	mutations   []replay.Mutation
	rawOverride []byte
	client      *http.Client
	pj          *jar.PersistentJar
	jarLoaded   int
}

// newReplayClient builds the shared HTTP client for replay: the persistent
// cookie jar (when --session-id is set) plus --proxy routing, preserving the
// InsecureSkipVerify TLS config NewDefaultClient installs.
func newReplayClient(pj *jar.PersistentJar, timeout time.Duration) *http.Client {
	var jarForClient http.CookieJar
	if pj != nil {
		jarForClient = pj
	}
	client := replay.NewDefaultClient(jarForClient, timeout)
	if globalProxy != "" {
		if px, perr := url.Parse(globalProxy); perr == nil {
			if t, ok := client.Transport.(*http.Transport); ok {
				t.Proxy = http.ProxyURL(px)
			}
		}
	}
	return client
}

// saveReplayJar persists the cookie jar (no-op when --session-id is unset),
// warning to stderr on failure. Shared by the single-source and bulk paths.
func saveReplayJar(pj *jar.PersistentJar) {
	if pj == nil {
		return
	}
	if err := pj.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "%s replay: could not save cookie jar: %v\n", terminal.WarningSymbol(), err)
	}
}

// one runs a single source through the engine and returns the assembled
// output. Shared by single-source and bulk (per-record) replay. It honors
// --in-replace for stored records; the caller owns the cookie jar's lifecycle.
func (rr *replayRun) one(ctx context.Context, src *replaySource, overlay map[string]string) (*replayOutput, error) {
	opts := replay.Options{
		BaselineRequest:      src.BaselineRequest,
		BaselineResponse:     src.BaselineResponse,
		BaselineStatus:       src.BaselineStatus,
		BaselineResponseTime: src.BaselineResponseTime,
		Mutations:            rr.mutations,
		RawRequest:           rr.rawOverride,
		Scheme:               src.Scheme,
		Hostname:             src.Hostname,
		Port:                 src.Port,
		HeaderOverlay:        overlay,
		NoRedirects:          replayNoRedirects,
		Client:               rr.client,
	}

	result, err := replay.Do(ctx, opts)
	if err != nil {
		return nil, err
	}

	if replayInReplaceTop {
		if err := persistReplayResponse(ctx, src, result); err != nil {
			fmt.Fprintf(os.Stderr, "%s replay: --in-replace failed: %v\n", terminal.WarningSymbol(), err)
		}
	}

	return buildReplayOutput(src, result, rr.jarLoaded, rr.pj), nil
}

// replaySource is the resolved baseline a replay diffs against. It can
// come from a stored record (with response), a finding (linked record OR
// inline evidence), or freshly-parsed input bytes (no stored response →
// the engine will synthesize a baseline by re-sending).
type replaySource struct {
	BaselineRequest      []byte
	BaselineResponse     []byte
	BaselineStatus       int
	BaselineResponseTime int64

	Scheme   string
	Hostname string
	Port     int

	RecordUUID  string
	FindingID   int64
	InputType   string
	OriginLabel string
}

func resolveReplaySource(ctx context.Context) (*replaySource, error) {
	set := 0
	if replayRecordUUID != "" {
		set++
	}
	if replayFindingID > 0 {
		set++
	}
	if replayInput != "" || replayInputFile != "" {
		set++
	}
	if set > 1 {
		return nil, fmt.Errorf("--record-uuid, --finding-id and --input/--input-file are mutually exclusive")
	}

	// openReadDB honors -S/--stateless: a standalone .sqlite/.jsonl export via
	// --db, project scoping off. Falls back to the project DB otherwise.
	db, dbErr := openReadDB()
	var repo *database.Repository
	if dbErr == nil {
		repo = database.NewRepository(db)
	}

	switch {
	case replayRecordUUID != "":
		if repo == nil {
			return nil, fmt.Errorf("--record-uuid requires database access: %w", dbErr)
		}
		return sourceFromRecord(ctx, repo, replayRecordUUID)

	case replayFindingID > 0:
		if repo == nil {
			return nil, fmt.Errorf("--finding-id requires database access: %w", dbErr)
		}
		return sourceFromFinding(ctx, repo, replayFindingID)

	case replayInput != "" || replayInputFile != "":
		return sourceFromInput(ctx, repo, replayInput, replayInputFile)

	default:
		if data, ok := readStdinIfPiped(); ok {
			return sourceFromInputString(ctx, repo, data, "")
		}
		return nil, fmt.Errorf("no source specified: pass one of --record-uuid, --finding-id, --input, or pipe a request on stdin")
	}
}

func sourceFromRecord(ctx context.Context, repo *database.Repository, uuid string) (*replaySource, error) {
	rec, err := repo.GetRecordByUUID(ctx, uuid)
	if errors.Is(err, sql.ErrNoRows) || rec == nil {
		return nil, fmt.Errorf("no record with uuid %q", uuid)
	}
	if err != nil {
		return nil, fmt.Errorf("load record %q: %w", uuid, err)
	}
	if pid, _ := effectiveProjectUUID(); pid != "" && rec.ProjectUUID != pid {
		return nil, fmt.Errorf("record %q does not belong to the current project", uuid)
	}
	return sourceFromDBRecord(rec), nil
}

// sourceFromFinding resolves a finding to a baseline. Preference order:
//  1. First HTTPRecordUUIDs entry that loads — uses the canonical record
//     (which has correct host/port/scheme metadata).
//  2. Finding.Request / Finding.Response — for findings imported without
//     a backing HTTPRecord (audit findings, jsonl imports).
//
// We use the same priority order the UI does so the operator and the
// CLI see the same evidence.
func sourceFromFinding(ctx context.Context, repo *database.Repository, id int64) (*replaySource, error) {
	finding, err := repo.GetFindingByID(ctx, id)
	if err != nil || finding == nil {
		return nil, fmt.Errorf("load finding #%d: %w", id, err)
	}
	if pid, _ := effectiveProjectUUID(); pid != "" && finding.ProjectUUID != pid {
		return nil, fmt.Errorf("finding #%d does not belong to the current project", id)
	}

	for _, uuid := range finding.HTTPRecordUUIDs {
		rec, err := repo.GetRecordByUUID(ctx, uuid)
		if err == nil && rec != nil {
			src := sourceFromDBRecord(rec)
			src.FindingID = finding.ID
			src.OriginLabel = fmt.Sprintf("finding #%d via record %s", finding.ID, rec.UUID)
			return src, nil
		}
	}

	if finding.Request == "" {
		return nil, fmt.Errorf("finding #%d has no linked HTTPRecord and no inline request — can't replay", id)
	}
	src, err := sourceFromRawRequest([]byte(finding.Request), []byte(finding.Response), finding.URL)
	if err != nil {
		return nil, fmt.Errorf("finding #%d inline evidence: %w", id, err)
	}
	src.FindingID = finding.ID
	src.OriginLabel = fmt.Sprintf("finding #%d (inline evidence)", finding.ID)
	return src, nil
}

func sourceFromInput(ctx context.Context, repo *database.Repository, inline, file string) (*replaySource, error) {
	var data string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read --input-file %q: %w", file, err)
		}
		data = string(b)
	case inline == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		data = string(b)
	default:
		data = inline
	}
	return sourceFromInputString(ctx, repo, data, file)
}

// sourceFromInputString delegates to the agent input normalizer so a
// curl/raw/burp string from an external driver parses the same way it
// would in autopilot.
func sourceFromInputString(ctx context.Context, repo *database.Repository, data, label string) (*replaySource, error) {
	if strings.TrimSpace(data) == "" {
		return nil, fmt.Errorf("input is empty")
	}
	records, err := input.NormalizeInput(ctx, data, "", repo)
	if err != nil {
		return nil, fmt.Errorf("normalize input: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no HTTP requests found in input")
	}
	rr := records[0]
	if rr.Request() == nil {
		return nil, fmt.Errorf("input did not yield a request")
	}
	rawReq := rr.Request().Raw()
	u, err := rr.URL()
	if err != nil || u == nil || u.URL == nil {
		return nil, fmt.Errorf("could not extract URL from input")
	}
	it := input.DetectInputType(data)
	src := &replaySource{
		BaselineRequest: rawReq,
		Scheme:          u.Scheme,
		Hostname:        u.Hostname(),
		Port:            portFromURL(u.URL),
		InputType:       string(it),
		OriginLabel:     fmt.Sprintf("input (%s)", it),
	}
	if rr.Response() != nil {
		raw := rr.Response().Raw()
		src.BaselineResponse = raw
		src.BaselineStatus = rr.Response().StatusCode()
	}
	if label != "" {
		src.OriginLabel = fmt.Sprintf("file %s", label)
	}
	return src, nil
}

func sourceFromRawRequest(rawReq, rawResp []byte, urlStr string) (*replaySource, error) {
	if len(rawReq) == 0 {
		return nil, fmt.Errorf("no raw request bytes")
	}
	if _, err := httpmsg.ParseRawRequestWithURL(string(rawReq), urlStr); err != nil {
		return nil, fmt.Errorf("parse raw request: %w", err)
	}
	u, err := url.Parse(urlStr)
	if err != nil || u == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL %q on finding", urlStr)
	}
	return &replaySource{
		BaselineRequest:  rawReq,
		BaselineResponse: rawResp,
		Scheme:           u.Scheme,
		Hostname:         u.Hostname(),
		Port:             portFromURL(u),
	}, nil
}

// applyTargetOverride rewrites src's destination. The baseline request
// bytes (Host header, path) are left verbatim; only the socket we aim
// at changes — that's how an operator confirms a finding against a
// different env without re-deriving the request.
func applyTargetOverride(src *replaySource, target string) error {
	u, err := url.Parse(target)
	if err != nil || u == nil || u.Hostname() == "" {
		return fmt.Errorf("invalid --target %q: %w", target, err)
	}
	src.Scheme = u.Scheme
	src.Hostname = u.Hostname()
	src.Port = portFromURL(u)
	return nil
}

func portFromURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

func parseReplayMutations() ([]replay.Mutation, error) {
	var out []replay.Mutation
	for i, s := range replayMutations {
		if strings.TrimSpace(s) == "" {
			continue
		}
		m, err := replay.ParseMutationFlag(s)
		if err != nil {
			return nil, fmt.Errorf("--mutate[%d]: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

func loadReplayRawOverride() ([]byte, error) {
	switch {
	case replayRawRequest != "" && replayRawRequestFile != "":
		return nil, fmt.Errorf("--raw-request and --raw-request-file are mutually exclusive")
	case replayRawRequestFile != "":
		b, err := os.ReadFile(replayRawRequestFile)
		if err != nil {
			return nil, fmt.Errorf("read --raw-request-file %q: %w", replayRawRequestFile, err)
		}
		return b, nil
	case replayRawRequest != "":
		return []byte(replayRawRequest), nil
	}
	return nil, nil
}

// buildReplayOverlay: --auth-session headers are merged first, then
// --header K:V flags win last so an operator can override stored auth.
// Honors -S/--stateless (openReadDB/effectiveProjectUUID) so every DB touchpoint
// in the command reads from the same source.
func buildReplayOverlay(ctx context.Context, src *replaySource) (map[string]string, error) {
	overlay := map[string]string{}

	if replayAuthSession != "" {
		db, err := openReadDB()
		if err != nil {
			return nil, fmt.Errorf("--auth-session requires database access: %w", err)
		}
		repo := database.NewRepository(db)
		pid, _ := effectiveProjectUUID()
		rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, pid, src.Hostname)
		if err != nil {
			return nil, fmt.Errorf("lookup auth sessions: %w", err)
		}
		found := false
		for _, row := range rows {
			if row.SessionName == replayAuthSession {
				for k, v := range row.Headers {
					overlay[k] = v
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("auth session %q not found for hostname %s", replayAuthSession, src.Hostname)
		}
	}

	headers, err := parseReplayHeaderFlags()
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		overlay[k] = v
	}
	return overlay, nil
}

// parseReplayHeaderFlags parses the repeatable --header flags into an overlay
// map, erroring on the first malformed entry. Host-independent, so the bulk
// path parses it once and reuses it across records.
func parseReplayHeaderFlags() (map[string]string, error) {
	overlay := map[string]string{}
	for i, h := range replayHeaders {
		name, value, err := replay.ParseHeaderFlag(h)
		if err != nil {
			return nil, fmt.Errorf("--header[%d]: %w", i, err)
		}
		overlay[name] = value
	}
	return overlay, nil
}

func openReplayJar() (*jar.PersistentJar, int, error) {
	if replayNoCookies || replaySessionID == "" {
		return nil, 0, nil
	}
	path := jar.PathFor(replaySessionID)
	if path == "" {
		return nil, 0, fmt.Errorf("could not resolve jar path (set VIGOLIUM_HOME or HOME)")
	}
	return jar.Open(path)
}

func persistReplayResponse(ctx context.Context, src *replaySource, result *replay.Result) error {
	if src.RecordUUID == "" {
		return fmt.Errorf("--in-replace requires a stored record (got %s)", src.OriginLabel)
	}
	if result.Replay == nil || result.Replay.Error != "" {
		return fmt.Errorf("--in-replace skipped: replay had no usable response")
	}
	body := result.Replay.RawBody
	if body == nil {
		// Defensive: the engine populates RawBody on every successful
		// send. If we ever stop doing that, refuse rather than write
		// the clipped excerpt back as the canonical body.
		return fmt.Errorf("--in-replace skipped: engine did not return body bytes")
	}
	db, err := getDB()
	if err != nil {
		return err
	}
	repo := database.NewRepository(db)

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", result.Replay.Status, http.StatusText(result.Replay.Status))
	for k, vs := range result.Replay.Headers {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	raw := append([]byte(b.String()), body...)

	update := &database.RecordResponseUpdate{
		StatusCode:            result.Replay.Status,
		StatusPhrase:          http.StatusText(result.Replay.Status),
		ResponseHTTPVersion:   "HTTP/1.1",
		ResponseContentType:   result.Replay.Headers.Get("Content-Type"),
		ResponseContentLength: int64(result.Replay.ResponseLen),
		RawResponse:           raw,
		ResponseHash:          result.Replay.ContentHash,
		ResponseTimeMs:        result.Replay.ResponseTimeMs,
	}
	return repo.UpdateRecordResponse(ctx, src.RecordUUID, update)
}

// replayOutput is the JSON shape emitted to stdout / --output. It wraps
// the engine's Result with the source attribution and cookie-jar status
// the caller (often an agent) needs to chain calls.
type replayOutput struct {
	Source           string         `json:"source"`
	RecordUUID       string         `json:"record_uuid,omitempty"`
	FindingID        int64          `json:"finding_id,omitempty"`
	InputType        string         `json:"input_type,omitempty"`
	Target           string         `json:"target"`
	SessionID        string         `json:"session_id,omitempty"`
	CookiesPreloaded int            `json:"cookies_preloaded,omitempty"`
	JarPath          string         `json:"jar_path,omitempty"`
	Result           *replay.Result `json:"result"`
	// Error is set (with Result nil) only in bulk mode when a single record
	// fails to replay, so one bad record doesn't abort the JSONL stream.
	Error string `json:"error,omitempty"`
}

func buildReplayOutput(src *replaySource, result *replay.Result, jarLoaded int, pj *jar.PersistentJar) *replayOutput {
	target := src.Hostname
	if src.Port > 0 {
		target = fmt.Sprintf("%s://%s:%d", src.Scheme, src.Hostname, src.Port)
	} else if src.Scheme != "" {
		target = fmt.Sprintf("%s://%s", src.Scheme, src.Hostname)
	}
	out := &replayOutput{
		Source:     src.OriginLabel,
		RecordUUID: src.RecordUUID,
		FindingID:  src.FindingID,
		InputType:  src.InputType,
		Target:     target,
		SessionID:  replaySessionID,
		Result:     result,
	}
	if pj != nil {
		out.JarPath = pj.Path()
		out.CookiesPreloaded = jarLoaded
	}
	return out
}

// openReplayOutputWriter returns the JSON sink for replay output: stdout, or
// --output if set. The returned close func is a no-op for stdout. Shared by the
// single-source (indented object) and bulk (JSONL stream) paths.
func openReplayOutputWriter() (io.Writer, func(), error) {
	if replayOutputPath == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(replayOutputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create --output %q: %w", replayOutputPath, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// emitReplayJSON pretty-prints the result. Agents that want compact
// JSON should pipe through `jq -c .`.
func emitReplayJSON(out *replayOutput) error {
	w, closeOut, err := openReplayOutputWriter()
	if err != nil {
		return err
	}
	defer closeOut()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func emitReplayPretty(out *replayOutput) error {
	fmt.Printf("%s %s\n", terminal.Cyan("→"), out.Source)
	fmt.Printf("  target: %s\n", out.Target)
	if out.SessionID != "" {
		fmt.Printf("  session: %s (preloaded %d cookies, jar: %s)\n",
			out.SessionID, out.CookiesPreloaded, out.JarPath)
	}
	if out.Result == nil || out.Result.Replay == nil || out.Result.Baseline == nil {
		return fmt.Errorf("no result")
	}
	b, r, d := out.Result.Baseline, out.Result.Replay, out.Result.Diff
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "BASELINE", "REPLAY")
	tbl.AddRow("Status",
		colorStatus(fmt.Sprintf("%d", b.Status), b.Status),
		colorStatus(fmt.Sprintf("%d", r.Status), r.Status))
	tbl.AddRow("Length",
		fmt.Sprintf("%d", b.ResponseLen),
		fmt.Sprintf("%d (Δ%+d)", r.ResponseLen, d.LengthDelta))
	tbl.AddRow("Hash", clicommon.Truncate(b.ContentHash, 16), clicommon.Truncate(r.ContentHash, 16))
	tbl.AddRow("Time (ms)",
		fmt.Sprintf("%d", b.ResponseTimeMs),
		fmt.Sprintf("%d", r.ResponseTimeMs))
	tbl.Print()
	if r.Error != "" {
		fmt.Printf("  %s replay error: %s\n", terminal.ErrorPrefix(), r.Error)
	}
	if d.Interpretation != "" {
		fmt.Printf("  %s %s\n", terminal.InfoSymbol(), d.Interpretation)
	}
	if len(d.ReflectsPayload) > 0 {
		fmt.Printf("  %s reflected payloads: %s\n", terminal.WarnPrefix(), strings.Join(d.ReflectsPayload, ", "))
	}
	if len(out.Result.Unmatched) > 0 {
		fmt.Printf("  %s unmatched insertion points: %s\n",
			terminal.WarnPrefix(), strings.Join(out.Result.Unmatched, ", "))
	}
	if out.Result.AdditionalGroups > 0 {
		fmt.Printf("  %s %d additional payload group(s) not sent — re-run to fire them\n",
			terminal.InfoSymbol(), out.Result.AdditionalGroups)
	}
	return nil
}
