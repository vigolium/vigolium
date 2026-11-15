package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
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
}

// newHandSendSaver opens the project store for writes unless saving is off
// or the invocation forbids writes.
func newHandSendSaver(source string, enabled bool) *handSendSaver {
	s := &handSendSaver{source: source}
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
	if !s.active() || len(rawRequest) == 0 || resp == nil || resp.Status <= 0 || resp.Error != "" {
		return "", nil
	}
	rr, err := httpmsg.ParseRawRequestWithURL(string(rawRequest), origin)
	if err != nil {
		return "", fmt.Errorf("parse the sent request: %w", err)
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponseWithDuration(rawSummaryResponse(resp), time.Duration(resp.ResponseTimeMs)*time.Millisecond))
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return s.repo.SaveRecord(saveCtx, rr, s.source, s.projectUUID)
}

// rawSummaryResponse rebuilds a raw HTTP/1.1 response from a summary.
func rawSummaryResponse(summary *replay.Summary) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", summary.Status, http.StatusText(summary.Status))
	for k, values := range summary.Headers {
		for _, value := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", k, value)
		}
	}
	b.WriteString("\r\n")
	return append([]byte(b.String()), summary.RawBody...)
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
	raw := src.BaselineRequest
	if out.Result != nil && len(out.Result.RawMutatedRequest) > 0 {
		raw = out.Result.RawMutatedRequest
	}
	v.Method = requestMethodOf(raw)
	v.URL = replaySourceURL(src)
	if rr, err := httpmsg.ParseRawRequestWithURL(string(raw), v.URL); err == nil {
		if u, uerr := rr.URL(); uerr == nil && u != nil {
			v.URL = u.String()
		}
	}
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

// store writes the buffered exchanges and returns their record UUIDs.
func (c *fuzzExchangeCollector) store(ctx context.Context, s *handSendSaver, origin string) []string {
	uuids := []string{}
	if c == nil || !s.active() {
		return uuids
	}
	for _, ex := range c.items {
		uuid, err := s.save(ctx, origin, ex.raw, ex.resp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s fuzz: could not store an exchange: %v\n", terminal.WarningSymbol(), err)
			continue
		}
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
	raw := src.BaselineRequest
	if len(rr.rawOverride) > 0 {
		raw = rr.rawOverride
	}
	v := replayDryRunView{
		Method: requestMethodOf(raw), URL: replaySourceURL(src), Source: src.OriginLabel,
		Request: string(raw), OverlayHeaders: sortedHeaderNames(overlay),
		RawOverride: len(rr.rawOverride) > 0, WouldSave: rr.saver.active(),
	}
	if v.OverlayHeaders == nil {
		v.OverlayHeaders = []string{}
	}
	if parsed, err := httpmsg.ParseRawRequestWithURL(string(raw), v.URL); err == nil {
		if u, uerr := parsed.URL(); uerr == nil && u != nil {
			v.URL = u.String()
		}
	}
	if globalJSON {
		env := newMachineEnvelope(cmd, kindRead, "", []replayDryRunView{v}, 1, 0, 1)
		env.objectResult = true
		env.DryRun = true
		return writeAgentJSON(env)
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
