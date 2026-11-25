package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Requests sent by hand leave a record: `replay` stores the exchange it sent
// (source "replay") by default, so the confirming request has a UUID to cite,
// attach to a finding or diff later; `fuzz --save` stores the exchanges the run
// kept (source "fuzz"), or every one with --save=all. Both sources are evidence
// (database.EvidenceRecordSources): a later scan never re-attacks them.
//
// Nothing is stored under --read-only (a database guarantee) or -S (a
// standalone read that never writes the project store).

var (
	replaySave   bool
	replayNoSave bool
	replayOnce   bool
	fuzzSave     string
)

// Fuzz save modes.
const (
	fuzzSaveAnomalies = "anomalies"
	fuzzSaveAll       = "all"
)

// fuzzSaveCap bounds how many exchanges one fuzz run stores (each holds a
// response body in memory until the run ends).
const fuzzSaveCap = 1000

// replayOnceBodyCap bounds the body `replay --once` prints.
const replayOnceBodyCap = 16 * 1024

func init() {
	rf := replayCmd.Flags()
	rf.BoolVar(&replaySave, "save", false, "Store the exchange sent (source \"replay\") and report its saved_record_uuid. On by default for a single replay; bulk replay stores only with --save")
	rf.BoolVar(&replayNoSave, "no-save", false, "Do not store the exchange sent")
	rf.BoolVar(&replayOnce, "once", false, "Send the request once (no baseline, no diff) and print a compact result: saved record_uuid, status, final_url and a bounded body")

	ff := fuzzCmd.Flags()
	ff.StringVar(&fuzzSave, "save", "", "Store payload exchanges (source \"fuzz\"): --save keeps the ones the run kept (matched/anomalous), --save=all every one (capped at 1000)")
	ff.Lookup("save").NoOptDefVal = fuzzSaveAnomalies
}

// handSendSaver stores hand-sent exchanges. A nil saver, or one with a skip
// reason, stores nothing.
type handSendSaver struct {
	repo        *database.Repository
	projectUUID string
	source      string
	// skip says why nothing is stored ("" when saving).
	skip string
	// row is the invocation's scans row (invocationScanRow), created on the
	// first store and stamped on every record this saver writes.
	row *invocationScanRow
}

// scanUUID is the invocation's scan row, created on first use (target names
// it then).
func (s *handSendSaver) scanUUID(ctx context.Context, target string) string {
	return s.row.ensure(ctx, s.repo, s.projectUUID, target)
}

// lineage is the lineage every record this saver stores carries: its scan
// row, plus remarks.
func (s *handSendSaver) lineage(ctx context.Context, target string, remarks ...string) database.RecordLineage {
	return database.RecordLineage{ScanUUID: s.scanUUID(ctx, target), Remarks: remarks}
}

// newHandSendSaver opens the project store for writes unless saving is off
// or the invocation forbids writes.
func newHandSendSaver(source string, enabled bool) *handSendSaver {
	s := &handSendSaver{source: source, row: newInvocationScanRow(source)}
	switch {
	case !enabled:
		s.skip = "disabled"
	case globalReadOnly:
		s.skip = "read_only"
	case statelessReadRequested():
		s.skip = "stateless"
	}
	if s.skip != "" {
		return s
	}
	db, err := getDB()
	if err != nil {
		s.skip = "database_unavailable"
		fmt.Fprintf(os.Stderr, "%s not storing the exchange: %v\n", terminal.WarningSymbol(), err)
		return s
	}
	project, err := resolveProjectUUID()
	if err != nil {
		s.skip = "project_unresolved"
		fmt.Fprintf(os.Stderr, "%s not storing the exchange: %v\n", terminal.WarningSymbol(), err)
		return s
	}
	s.repo, s.projectUUID = database.NewRepository(db), project
	return s
}

// active reports whether exchanges are stored.
func (s *handSendSaver) active() bool { return s != nil && s.skip == "" && s.repo != nil }

// save stores one exchange: the request bytes sent to origin (scheme://host
// [:port]) and the response summary. A transport error (no response) is not
// stored. Returns the new record's UUID.
func (s *handSendSaver) save(ctx context.Context, origin string, rawRequest []byte, resp *replay.Summary) (string, error) {
	if !s.active() {
		return "", nil
	}
	rr, err := handSentExchange(origin, rawRequest, resp)
	if rr == nil || err != nil {
		return "", err
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return s.repo.SaveRecordWithLineage(saveCtx, rr, s.source, s.projectUUID, s.lineage(saveCtx, origin))
}

// handSentExchange is the exchange to store for rawRequest sent to origin and
// its response summary; nil for a transport error (no response).
func handSentExchange(origin string, rawRequest []byte, resp *replay.Summary) (*httpmsg.HttpRequestResponse, error) {
	if len(rawRequest) == 0 || resp == nil || resp.Status <= 0 || resp.Error != "" {
		return nil, nil
	}
	rr, err := httpmsg.ParseRawRequestWithURL(string(rawRequest), origin)
	if err != nil {
		return nil, fmt.Errorf("parse the sent request: %w", err)
	}
	return rr.WithResponse(httpmsg.NewHttpResponseWithDuration(rawReplayResponse(resp), time.Duration(resp.ResponseTimeMs)*time.Millisecond)), nil
}

// validateReplaySaveFlags checks the save and --once flags against the rest
// of the command line.
func validateReplaySaveFlags(bulk bool) error {
	if replaySave && replayNoSave {
		return usageErrorf("--save and --no-save contradict each other; pick one")
	}
	if !replayOnce {
		return nil
	}
	switch {
	case bulk:
		return usageErrorf("--once sends one request; it cannot be combined with a bulk selection (--all, --host, a search term, …)")
	case replayWithBrowser:
		return usageErrorf("--once reports a response; --with-browser navigates and has none")
	case replaySendBaseline:
		return usageErrorf("--once sends the request once; drop --baseline")
	}
	return nil
}

// replaySaveEnabled is the effective save switch: on for a single replay
// unless --no-save, off for bulk unless --save; never with --in-replace (the
// stored record is updated instead) or --with-browser (no response).
func replaySaveEnabled(bulk bool) bool {
	if replayNoSave || replayInReplace || replayWithBrowser {
		return false
	}
	return replaySave || !bulk
}

// saveReplayExchange stores one replay's exchange and returns the new
// record's UUID ("" when nothing was stored).
func saveReplayExchange(ctx context.Context, s *handSendSaver, src *replaySource, result *replay.Result) string {
	if !s.active() || result == nil || result.Replay == nil {
		return ""
	}
	raw := result.RawMutatedRequest
	if len(raw) == 0 {
		raw = src.BaselineRequest
	}
	uuid, err := s.save(ctx, replaySourceURL(src), raw, result.Replay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s replay: could not store the exchange: %v\n", terminal.WarningSymbol(), err)
		return ""
	}
	return uuid
}

// sentRequest is the request a replay sends — override when set, else the
// baseline — and the URL it resolves to against src's destination.
func sentRequest(src *replaySource, override []byte) (raw []byte, sentURL string) {
	raw = src.BaselineRequest
	if len(override) > 0 {
		raw = override
	}
	sentURL = replaySourceURL(src)
	if rr, err := httpmsg.ParseRawRequestWithURL(string(raw), sentURL); err == nil {
		if u, uerr := rr.URL(); uerr == nil && u != nil {
			sentURL = u.String()
		}
	}
	return raw, sentURL
}

// replayOnceView is what `replay --once` prints: one send, reduced to what a
// caller cites and reads.
type replayOnceView struct {
	RecordUUID   string `json:"record_uuid"`
	Saved        bool   `json:"saved"`
	SaveSkipped  string `json:"save_skipped,omitempty"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	FinalURL     string `json:"final_url"`
	Status       int    `json:"status"`
	ResponseTime int64  `json:"response_time_ms"`
	ContentType  string `json:"content_type,omitempty"`
	Length       int    `json:"response_length"`
	Body         string `json:"body"`
	// BodyTruncated says Body holds only the first bytes of the response.
	BodyTruncated bool   `json:"body_truncated"`
	Error         string `json:"error,omitempty"`
}

// newReplayOnceView reduces a replay output to the --once view.
func newReplayOnceView(out *replayOutput, src *replaySource, saver *handSendSaver) replayOnceView {
	v := replayOnceView{RecordUUID: out.SavedRecordUUID, Saved: out.SavedRecordUUID != ""}
	if saver != nil && saver.skip != "" && saver.skip != "disabled" {
		v.SaveSkipped = saver.skip
	}
	var mutated []byte
	if out.Result != nil {
		mutated = out.Result.RawMutatedRequest
	}
	raw, sentURL := sentRequest(src, mutated)
	v.Method, v.URL = requestMethodOf(raw), sentURL
	if out.Result == nil || out.Result.Replay == nil {
		return v
	}
	r := out.Result.Replay
	v.Status, v.ResponseTime, v.Length, v.Error = r.Status, r.ResponseTimeMs, r.ResponseLen, r.Error
	v.FinalURL = r.FinalURL
	if v.FinalURL == "" {
		v.FinalURL = v.URL
	}
	if r.Headers != nil {
		v.ContentType = r.Headers.Get("Content-Type")
	}
	body := r.RawBody
	if len(body) > replayOnceBodyCap {
		body, v.BodyTruncated = body[:replayOnceBodyCap], true
	}
	v.Body = string(body)
	return v
}

// emitReplayOnce prints the --once result.
func emitReplayOnce(cmd *cobra.Command, v replayOnceView) error {
	if globalJSON {
		v.URL, v.FinalURL = redactURL(jsonRedactOn, v.URL), redactURL(jsonRedactOn, v.FinalURL)
		return emitObject(cmd, "", v)
	}
	saved := "not stored"
	if v.Saved {
		saved = "record " + v.RecordUUID
	}
	if v.Error != "" {
		fmt.Printf("%s %s %s → %s (%s)\n", terminal.ErrorSymbol(), v.Method, v.URL, v.Error, saved)
		return nil
	}
	fmt.Printf("%s %s %s → %d, %d bytes, %dms (%s)\n", terminal.InfoSymbol(), v.Method, v.URL, v.Status, v.Length, v.ResponseTime, saved)
	if v.FinalURL != v.URL {
		fmt.Printf("  final url: %s\n", v.FinalURL)
	}
	fmt.Println(v.Body)
	if v.BodyTruncated {
		fmt.Fprintf(os.Stderr, "%s body truncated at %d bytes; read the whole response with: vigolium traffic body %s\n", terminal.InfoSymbol(), replayOnceBodyCap, v.RecordUUID)
	}
	return nil
}

// validateFuzzSave checks --save's value.
func validateFuzzSave() error {
	switch fuzzSave {
	case "", fuzzSaveAnomalies, fuzzSaveAll:
		return nil
	}
	return usageErrorf("--save %q: want --save (the kept exchanges) or --save=all", fuzzSave)
}

// fuzzExchangeCollector buffers the exchanges a fuzz run stores, so the
// engine's serialized result path does no database I/O.
type fuzzExchangeCollector struct {
	all      bool
	items    []fuzzExchange
	overflow int
}

type fuzzExchange struct {
	raw  []byte
	resp *replay.Summary
}

// observe is the engine's OnExchange hook.
func (c *fuzzExchangeCollector) observe(matched bool, raw []byte, resp *replay.Summary) {
	if !c.all && !matched {
		return
	}
	if resp == nil || resp.Status <= 0 || resp.Error != "" {
		return
	}
	if len(c.items) >= fuzzSaveCap {
		c.overflow++
		return
	}
	c.items = append(c.items, fuzzExchange{raw: append([]byte(nil), raw...), resp: resp})
}

// store writes the buffered exchanges through one batched record writer
// (the scanner's: one duplicate lookup and one transaction per batch, an
// exchange identical to a stored one reusing its record) and returns their
// record UUIDs.
func (c *fuzzExchangeCollector) store(ctx context.Context, s *handSendSaver, origin string) []string {
	uuids := []string{}
	if c == nil || !s.active() {
		return uuids
	}
	exchanges := make([]*httpmsg.HttpRequestResponse, 0, len(c.items))
	for _, ex := range c.items {
		rr, err := handSentExchange(origin, ex.raw, ex.resp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s fuzz: could not store an exchange: %v\n", terminal.WarningSymbol(), err)
			continue
		}
		if rr != nil {
			exchanges = append(exchanges, rr)
		}
	}
	c.items = nil
	if len(exchanges) == 0 {
		return uuids
	}
	w := database.NewRecordWriter(s.repo, database.RecordWriterConfig{ScanUUID: s.scanUUID(ctx, origin)})
	saved, err := w.SaveRecordBatch(context.WithoutCancel(ctx), exchanges, s.source, s.projectUUID)
	w.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s fuzz: could not store every exchange: %v\n", terminal.WarningSymbol(), err)
	}
	for _, uuid := range saved {
		if uuid != "" {
			uuids = append(uuids, uuid)
		}
	}
	if c.overflow > 0 {
		fmt.Fprintf(os.Stderr, "%s fuzz --save: stored the first %d exchanges; %d more were not stored\n", terminal.WarningSymbol(), fuzzSaveCap, c.overflow)
	}
	return uuids
}

// replayDryRun is `replay --dry-run`: print the request that would be sent,
// send nothing and store nothing.
var replayDryRun bool

func init() {
	replayCmd.Flags().BoolVar(&replayDryRun, "dry-run", false, "Print the request that would be sent (after header overlays and --target), without sending or storing it")
}

// replayDryRunView is the `replay --dry-run -j` item.
type replayDryRunView struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Source string `json:"source"`
	// Request is the raw request that would be sent, before the header
	// overlay (OverlayHeaders names the headers it would set).
	Request        string   `json:"request"`
	OverlayHeaders []string `json:"overlay_headers"`
	RawOverride    bool     `json:"raw_override"`
	WouldSave      bool     `json:"would_save"`
}

func emitReplayDryRun(cmd *cobra.Command, src *replaySource, overlay map[string]string, rr *replayRun) error {
	raw, sentURL := sentRequest(src, rr.rawOverride)
	v := replayDryRunView{
		Method: requestMethodOf(raw), URL: sentURL, Source: src.OriginLabel,
		Request: string(raw), OverlayHeaders: sortedHeaderNames(overlay),
		RawOverride: len(rr.rawOverride) > 0, WouldSave: rr.saver.active(),
	}
	if v.OverlayHeaders == nil {
		v.OverlayHeaders = []string{}
	}
	if globalJSON {
		v.Request, v.URL = redactRaw(jsonRedactOn, v.Request), redactURL(jsonRedactOn, v.URL)
		return emitObject(cmd, "", v, withDryRun())
	}
	fmt.Printf("%s Dry run: would send %s %s (nothing sent, nothing stored)\n\n%s\n", terminal.InfoSymbol(), v.Method, v.URL, v.Request)
	return nil
}

// fuzzSavedUUIDs are the records this fuzz run stored (the -j summary's
// saved_record_uuids).
var fuzzSavedUUIDs []string

// armFuzzSave wires --save into job and returns the step that stores what
// the run collected (after the run, off the engine's serialized path). The
// store step returns nil when nothing is saved.
func armFuzzSave(job *fuzz.Job) func(ctx context.Context, origin string) []string {
	saver := newHandSendSaver(database.RecordSourceFuzz, fuzzSave != "")
	if !saver.active() {
		if fuzzSave != "" && saver.skip != "" {
			fmt.Fprintf(os.Stderr, "%s fuzz --save: not storing exchanges (%s)\n", terminal.InfoSymbol(), saver.skip)
		}
		return func(context.Context, string) []string { return nil }
	}
	c := &fuzzExchangeCollector{all: fuzzSave == fuzzSaveAll}
	job.OnExchange = func(r fuzz.Result, raw []byte, resp *replay.Summary) { c.observe(r.Matched, raw, resp) }
	return func(ctx context.Context, origin string) []string {
		uuids := c.store(ctx, saver, origin)
		if len(uuids) > 0 && !globalJSON {
			fmt.Fprintf(os.Stderr, "%s stored %d exchange(s) as source \"fuzz\" (vigolium traffic --source fuzz)\n", terminal.InfoSymbol(), len(uuids))
		}
		return uuids
	}
}
