package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/replay/jar"
	"github.com/vigolium/vigolium/pkg/requestinput"
	"github.com/vigolium/vigolium/pkg/requestscheme"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	// replayIgnoreScope is replay's --ignore-scope (traffic --replay maps its
	// own onto it).
	replayIgnoreScope    bool
	replayKeepHost       bool
	replayRecordUUID     string
	replayFindingID      int64
	replayInput          string
	replayInputFile      string
	replayRawRequest     string
	replayRawRequestFile string
	replayHeaders        []string
	replayAuthSession    string
	replaySessionID      string
	replayNoCookies      bool
	replayNoRedirects    bool
	replaySendBaseline   bool
	replayTargetURL      string
	replayTimeout        time.Duration
	replayOutputPath     string
	replayBurpBridgeURL  string
	replaySaveToBurp     bool
	replaySendViaBurp    bool
	replayHTTPMode       string
	replaySendTimeout    time.Duration
	replayToRepeater     bool
	replayRepeaterTab    string
	replayToOrganizer    bool
	replayNotes          string
	replayHighlight      string

	// Bulk-selection flags — when any is set (or a positional search term is
	// given), replay iterates the matching stored records instead of a single
	// source (mirrors `traffic --replay`, re-sending each record verbatim through
	// the diff engine). The filter surface tracks `vigolium traffic`. The
	// positional term is a local threaded through, not a flag global.
	replayAll               bool
	replayAllMatches        bool
	replayBulkHost          string
	replayBulkMethods       []string
	replayBulkStatus        []int
	replayBulkPath          string
	replayBulkSource        string
	replayBulkSearch        []string
	replayBulkHeaderSearch  string
	replayBulkBody          string
	replayBulkExclude       []string
	replayBulkExcludeHeader string
	replayBulkExcludeBody   string
	replayBulkFrom          string
	replayBulkTo            string
	replayBulkSort          string
	replayBulkAsc           bool
	replayBulkOffset        int
	replayBulkLimit         int
	replayConcurrency       int

	// replayInReplace overwrites each replayed record's stored response with the
	// replay response. Bound by both `replay --in-replace` and the
	// `traffic --replay --in-replace` shortcut — only one command runs per
	// process, so a single global backs both registrations.
	replayInReplace bool

	// replayWithBrowser loads each record's URL in a real browser routed through
	// --proxy instead of re-sending the stored bytes. Not a diff mode: a browser
	// navigation yields no status/body to compare (see replay_browser.go).
	replayWithBrowser bool
)

var replayCmd = &cobra.Command{
	Use:   "replay [search-term]",
	Short: "Re-send a stored or supplied HTTP request and diff baseline vs replay",
	Args:  cobra.MaximumNArgs(1),
	Long: `Re-send an HTTP request — stored record, finding evidence, curl command, raw HTTP, ` +
		`Burp XML, base64, or URL — optionally overriding the raw request bytes, and emit a ` +
		`baseline-vs-replay diff (status, length, content-hash, timing).

For payload / insertion-point fuzzing (wordlists, --class, matchers, calibration),
use 'vigolium fuzz' — replay is for re-sending and confirming, not fuzzing.

The same engine that powers the autopilot's in-process replay_request tool. Use this
to drive vigolium externally (Claude Code, Cursor, Pi, CI scripts). Output is a human
summary by default; -j gives one JSON envelope (the result in items[0]) and
--format jsonl one compact object per line, so an agent can confirm a finding
without parsing terminal output.

Cookies set by one replay persist to the next when --session-id is provided. Routes
through HTTP_PROXY / HTTPS_PROXY (or --proxy) for Burp-style inspection.

Burp bridge (needs --burp-bridge-url, the extension's loopback listener):
  --send-via-burp  send through Burp's own HTTP stack so exact bytes hit the wire —
                   the way to replay malformed/smuggling requests (pair with
                   --http-mode http1 so 'auto' doesn't negotiate HTTP/2 and reframe them)
  --to-repeater    also stage the request in a Burp Repeater tab for manual testing
  --to-organizer   also store the request + response in Burp's Organizer (--notes/--highlight)
  --save-to-burp  add the request + fresh response to Burp's Target Site map
None of these change the default send path — without them replay behaves exactly as before.

Bulk mode: pass a positional [search-term] (a broad fuzzy match, like
'vigolium traffic <term>'), --all, or any record filter to replay every matching
stored record instead of a single source. The selection surface mirrors
'vigolium traffic': --host/--method/--status/--path/--source, repeatable
--search (AND-combined), --header-search, --body, --from/--to date range,
--exclude-search/--exclude-header-search/--exclude-body, and
--sort/--asc/--offset. Each matched record is re-sent verbatim through the diff
engine. Results stream as JSONL (one object per record) by default for one more
release, with a notice on stderr; pass --format jsonl to keep the stream, -j for
one JSON document, or --format console for per-record tables. Throttle with
-c/--concurrency and read a standalone export with -S --db. 'vigolium traffic
--replay' is a shortcut for this mode.

Note --header-search filters which records are selected; -H/--header rewrites
headers on the request that gets sent. Combine them to re-send everything that
carried one header under a different session:
  vigolium replay --header-search 'X-Api-Key' -H 'Cookie: session=other'

--with-browser loads each matched URL in a real browser through --proxy instead
of re-sending the stored bytes. It is navigation-only — a browser gives no
status code or body to compare — so those runs report final URL, title, and any
JS dialogs, and carry no diff.`,
	// Example is set in usage.go (replayExamples) so it renders colored like the
	// other commands via FormatExamples.
	RunE: runReplay,
}

func init() {
	rootCmd.AddCommand(replayCmd)
	f := replayCmd.Flags()

	// Source flags — exactly one of these resolves the baseline.
	f.StringVarP(&replayRecordUUID, "record-uuid", "u", "", "Stored HTTP record UUID (or unique 8+ char prefix) to use as baseline")
	f.BoolVar(&replayIgnoreScope, "ignore-scope", false, "Send to hosts outside the configured host scope")
	f.Int64Var(&replayFindingID, "finding-id", 0, "Finding ID — replay the finding's linked record (or its stored evidence)")
	f.StringVarP(&replayInput, "input", "i", "", "Raw input: curl, raw HTTP, Burp XML, base64 or URL text, a path to a file holding one, or '-' for stdin")
	f.StringVar(&replayInputFile, "input-file", "", "Read --input value from a file")

	// Raw request override — send exact bytes verbatim (for payload/insertion-point
	// fuzzing use `vigolium fuzz` instead).
	f.StringVar(&replayRawRequest, "raw-request", "", "Full raw HTTP request override — send these exact bytes instead of the resolved baseline")
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
	f.BoolVar(&replaySendBaseline, "baseline", false,
		"Also send the un-mutated request first and diff the two. A supplied request (-i, --raw-request) is otherwise sent once with no diff; a stored record diffs against its stored response either way")
	f.StringVarP(&replayTargetURL, "target", "t", "", "Override scheme/host/port (e.g. https://staging.example.com); a Host header naming the old destination follows it unless --keep-host")
	f.BoolVar(&replayKeepHost, "keep-host", false, "With -t: send the request's Host header unchanged even when it names the old destination")
	f.DurationVar(&replayTimeout, "timeout", replay.DefaultTimeout, "Per-request timeout (e.g. 30s, 1m)")

	// Result handling.
	f.BoolVar(&replayInReplace, "in-replace", false,
		"When the source is a stored record, update its stored response with the replay")
	registerRowShapingFlags(f)
	f.StringVarP(&replayOutputPath, "output", "o", "", "Write the JSONL result stream (one object per record) to this file; stdout keeps the human summary, or the -j envelope")
	registerBridgeURLFlag(replayCmd, &replayBurpBridgeURL,
		"Loopback Burp/Caido bridge URL used by --save-to-burp / --send-via-burp / --to-repeater / --to-organizer")
	f.BoolVar(
		&replaySaveToBurp,
		"save-to-burp",
		false,
		"Add each replayed request and its fresh response to Burp's Target Site map")
	f.BoolVar(&replaySendViaBurp, "send-via-burp", false,
		"Send the request through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url")
	f.StringVar(&replayHTTPMode, "http-mode", "",
		"With --send-via-burp: wire protocol — auto|http1|http2|http2_ignore_alpn (default auto; use http1 for request smuggling/desync)")
	f.DurationVar(&replaySendTimeout, "send-timeout", 0,
		"With --send-via-burp: response timeout (<=2m; default uses the bridge's 30s)")
	f.BoolVar(&replayToRepeater, "to-repeater", false,
		"Stage the replayed request in a Burp Repeater tab for manual testing; requires --burp-bridge-url")
	f.StringVar(&replayRepeaterTab, "repeater-tab", "", "Repeater tab name for --to-repeater (default: vigolium)")
	f.BoolVar(&replayToOrganizer, "to-organizer", false,
		"Store the replayed request + response in Burp's Organizer for manual follow-up; requires --burp-bridge-url")
	f.StringVar(&replayNotes, "notes", "", fmt.Sprintf("Note attached to the --to-organizer item (longer than %d chars is truncated with an ellipsis, not rejected)", burpbridge.MaxOrganizerNote))
	f.StringVar(&replayHighlight, "highlight", "",
		"Highlight colour for the --to-organizer item: none|red|orange|yellow|green|cyan|blue|pink|magenta|gray")

	// Bulk selection — mirror the traffic filters. Setting any of these (or
	// --all, or a positional search term) switches replay into bulk mode over
	// the matching stored records.
	f.BoolVar(&replayAllMatches, "all-matches", false, "Bulk: replay every record the selection matches when it matches more than one (required then, so a broad term cannot fan out by accident)")
	f.BoolVarP(&replayAll, "all", "a", false, "Bulk: replay every matched stored record (lifts the -n/--limit cap); re-send all stored traffic")
	f.StringVar(&replayBulkHost, "host", "", "Bulk: filter records by hostname pattern (wildcard supported)")
	f.StringSliceVar(&replayBulkMethods, "method", nil, "Bulk: filter records by HTTP method (repeatable)")
	f.IntSliceVar(&replayBulkStatus, "status", nil, "Bulk: filter records by stored status code (repeatable)")
	f.StringVar(&replayBulkPath, "path", "", "Bulk: filter records by URL path pattern")
	f.StringVar(&replayBulkSource, "source", "", "Bulk: filter records by source (burp, caido, scanner, probe, ingest-cli, ingest-proxy, seed, ...)")
	f.StringArrayVar(&replayBulkSearch, "search", nil, "Bulk: search across URL, path, and the raw request/response (headers + body); repeatable, AND-combined")
	// Named --header-search, not --header: -H/--header is the override flag on
	// this command, so the traffic filter of the same name can't keep its spelling.
	f.StringVar(&replayBulkHeaderSearch, "header-search", "", "Bulk: filter records by text in HTTP header names/values (the search filter 'traffic --header' applies; -H/--header overrides headers instead)")
	f.StringVar(&replayBulkBody, "body", "", "Bulk: filter records whose request/response body contains this text")
	f.StringArrayVar(&replayBulkExclude, "exclude-search", nil, "Bulk: drop records where the term appears in the URL, path, or raw request/response (repeatable; dropped if ANY term matches — inverse of --search)")
	f.StringVar(&replayBulkExcludeHeader, "exclude-header-search", "", "Bulk: drop records whose HTTP header names/values contain the term (inverse of --header-search)")
	f.StringVar(&replayBulkExcludeBody, "exclude-body", "", "Bulk: drop records whose request/response body contains the term (inverse of --body)")
	f.StringVar(&replayBulkFrom, "from", "", fmt.Sprintf("Bulk: only records at or after this time — %s (alias: --since)", clicommon.TimeFilterSyntax))
	f.StringVar(&replayBulkTo, "to", "", fmt.Sprintf("Bulk: only records at or before this time — %s; %s (alias: --until)", clicommon.TimeFilterSyntax, clicommon.TimeFilterUpperBoundNote))
	addFlagAliases(replayCmd, timeFilterAliases)
	f.StringVar(&replayBulkSort, "sort", "created_at", "Bulk: sort matched records by: uuid, created_at, sent_at, method, status, time")
	f.BoolVar(&replayBulkAsc, "asc", false, "Bulk: sort ascending (default: descending)")
	f.IntVar(&replayBulkOffset, "offset", 0, "Bulk: skip this many matched records before replaying (pagination)")
	f.IntVarP(&replayBulkLimit, "limit", "n", 100, "Bulk: max records to replay (use --all to lift the cap)")
	f.IntVarP(&replayConcurrency, "concurrency", "c", 10, "Bulk: concurrent replays; keep low to avoid overwhelming an intercepting proxy like Burp")
	f.BoolVar(&replayWithBrowser, "with-browser", false,
		"Load each record's URL in a real browser routed via --proxy so an intercepting proxy captures browser-driven traffic; navigation-only, so no baseline-vs-replay diff is produced")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read records from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
}

func runReplay(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A positional argument is a broad fuzzy search term (like `traffic <term>`)
	// that selects records to replay in bulk. Kept as a local — not a flag
	// global — and threaded into the bulk path.
	var bulkFuzzy string
	if len(args) == 1 {
		bulkFuzzy = strings.TrimSpace(args[0])
		if urlShapedPositional(bulkFuzzy) {
			return clicommon.CLIError{
				Err:  fmt.Errorf("replay %q: a positional argument is a search over stored records, not a request to send", bulkFuzzy),
				Hint: "send that request with: vigolium replay -i 'curl " + bulkFuzzy + "' (or -i <raw request>); search stored records with --search " + bulkFuzzy,
			}
		}
	}
	if err := validateReplayFlags(); err != nil {
		return err
	}
	if err := replayShaping.validate(); err != nil {
		return err
	}
	// Decided before anything is sent: a contradictory output request is a
	// usage error, not a surprise after the traffic went out. A single source
	// prints the human summary by default; the bulk form keeps its JSONL
	// default for one more release (--format console or the old --pretty
	// select its tables; see streamOutputPlan).
	bulk := replayBulkRequested(bulkFuzzy)
	warnLegacyPretty(cmd, bulk)
	plan, err := resolveReplayOutputPlan(cmd, !bulk || (flagChanged(cmd, "pretty") && !globalJSON))
	if err != nil {
		return err
	}
	httpMode, err := burpbridge.ParseHTTPMode(replayHTTPMode)
	if err != nil {
		return usageErrorf("--http-mode: %w", err)
	}
	if replayHTTPMode != "" && !replaySendViaBurp {
		fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
	}
	var bridgeClient *burpbridge.Client
	if replayBurpBridgeURL != "" {
		validated, verr := burpbridge.ValidateURL(replayBurpBridgeURL)
		if verr != nil {
			return usageErrorf("--burp-bridge-url: %w", verr)
		}
		replayBurpBridgeURL = validated
		bridgeClient, verr = burpbridge.New(validated)
		if verr != nil {
			return verr
		}
	}
	// Preflight the listener for the explicit send flags so an unavailable bridge
	// is a clear up-front error rather than one failure per record mid-run.
	if bridgeClient != nil && (replaySendViaBurp || replayToRepeater || replayToOrganizer) {
		if _, herr := preflightBridge(ctx, bridgeClient, true); herr != nil {
			return herr
		}
	}

	rr, err := newReplayRun()
	if err != nil {
		return err
	}
	rr.burpClient = bridgeClient
	rr.sendOpts = burpbridge.SendOptions{Mode: httpMode, Timeout: replaySendTimeout}

	// Bulk mode: iterate every matching stored record through the same engine.
	if bulk {
		filters, ferr := buildReplayBulkFilters(bulkFuzzy)
		if ferr != nil {
			return ferr
		}
		return runReplayBulk(ctx, cmd, rr, filters, plan)
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
		if err := applyTargetOverride(src, replayTargetURL, replayKeepHost); err != nil {
			return err
		}
	}
	if err := newSendScopeGate(replayIgnoreScope).check(src.Hostname); err != nil {
		return err
	}

	out, err := rr.one(ctx, src, overlay)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}

	saveReplayJar(rr.pj)

	if err := emitReplayResult(cmd, plan, out); err != nil {
		return err
	}
	failed := 0
	if replayEntryFailed(out) {
		failed = 1
	}
	return sendOutcomeError("replay", 1, failed)
}

// replayEntryFailed reports whether one replay got no response: the record
// could not be replayed at all, or its send ended in a transport error.
func replayEntryFailed(out *replayOutput) bool {
	if out == nil {
		return false
	}
	if out.Error != "" {
		return true
	}
	return out.Result != nil && out.Result.Replay != nil && out.Result.Replay.Error != ""
}

// validateReplayFlags rejects flag combinations that can't be honored, so the
// operator gets one clear error up front instead of a per-record failure or a
// silently-ignored flag mid-run.
func validateReplayFlags() error {
	// Any Burp write target needs the loopback bridge URL.
	if replaySaveToBurp || replaySendViaBurp || replayToRepeater || replayToOrganizer {
		if strings.TrimSpace(replayBurpBridgeURL) == "" {
			return usageErrorf("--save-to-burp/--send-via-burp/--to-repeater/--to-organizer require --burp-bridge-url")
		}
	}

	// An over-long note is clipped, not rejected — but say so, so the operator is
	// not left wondering why Burp shows a shorter note than they typed.
	if n := len([]rune(strings.TrimSpace(replayNotes))); n > burpbridge.MaxOrganizerNote {
		fmt.Fprintf(os.Stderr, "%s --notes is %d chars; Burp's Organizer caps it at %d — it will be truncated with an ellipsis\n",
			terminal.WarnPrefix(), n, burpbridge.MaxOrganizerNote)
	}

	// --in-replace updates whichever store the records were read from, so under
	// --glob-db it would write into the throwaway merge DB and vanish. -S is
	// fine: the update lands in the standalone export being read.
	if replayInReplace && globalGlobDB != "" {
		return usageErrorf("--in-replace cannot be combined with --glob-db: the merged database is temporary, so the updated responses would be discarded")
	}

	// The browser path navigates a URL; it produces no response bytes and does
	// not send the stored request, so everything downstream of the send is
	// meaningless rather than merely unused.
	if replayWithBrowser {
		for _, conflict := range []struct {
			set  bool
			flag string
			why  string
		}{
			{replayInReplace, "--in-replace", "a navigation yields no response to store"},
			{replaySendViaBurp, "--send-via-burp", "the browser sends the request, not vigolium"},
			{replaySaveToBurp, "--save-to-burp", "there are no request/response bytes to save"},
			{replayToRepeater, "--to-repeater", "there are no request bytes to stage"},
			{replayToOrganizer, "--to-organizer", "there are no request/response bytes to store"},
			{replayRawRequest != "" || replayRawRequestFile != "", "--raw-request/--raw-request-file", "a navigation cannot send arbitrary request bytes"},
		} {
			if conflict.set {
				return usageErrorf("--with-browser cannot be combined with %s: %s", conflict.flag, conflict.why)
			}
		}
		if globalProxy == "" {
			fmt.Fprintf(os.Stderr, "%s --with-browser without --proxy: browser traffic isn't being routed to an intercepting proxy\n",
				terminal.WarningSymbol())
		}
	}
	return nil
}

// replayRun bundles the per-invocation replay settings that don't vary across
// records, so the single-source and bulk paths share one call shape instead of
// threading the same five values through every signature.
type replayRun struct {
	rawOverride []byte
	client      *http.Client
	pj          *jar.PersistentJar
	jarLoaded   int
	burpClient  *burpbridge.Client
	saveToBurp  bool
	sendViaBurp bool
	toRepeater  bool
	toOrganizer bool
	withBrowser bool
	sendOpts    burpbridge.SendOptions
}

// newReplayRun assembles the settings shared by every record in one run: the
// cookie jar, the HTTP client built over it, and the mode flags. Both entry
// points (runReplay and the traffic --replay shim) use it so they can't drift
// on how the jar is opened or which flags reach the send.
//
// The Burp bridge client and send options are set by the caller: only runReplay
// resolves and health-checks a bridge.
func newReplayRun() (*replayRun, error) {
	rawOverride, err := loadReplayRawOverride()
	if err != nil {
		return nil, err
	}
	installReplayTrafficDump()
	pj, jarLoaded, jarErr := openReplayJar()
	if jarErr != nil {
		fmt.Fprintf(os.Stderr, "%s replay: cookie jar disabled (%v)\n", terminal.WarningSymbol(), jarErr)
	}
	return &replayRun{
		rawOverride: rawOverride,
		client:      newReplayClient(pj, replayTimeout),
		pj:          pj,
		jarLoaded:   jarLoaded,
		saveToBurp:  replaySaveToBurp,
		sendViaBurp: replaySendViaBurp,
		toRepeater:  replayToRepeater,
		toOrganizer: replayToOrganizer,
		withBrowser: replayWithBrowser,
	}, nil
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
			replay.SetProxy(client, px)
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
	// The browser path shares record selection and the header overlay, but not
	// the send/diff engine — a navigation produces no status or body to compare.
	// Everything downstream of the send (--in-replace, the Burp targets,
	// --raw-request) is therefore skipped here; validateReplayFlags owns that
	// invariant by rejecting those combinations up front.
	if rr.withBrowser {
		summary, err := browserReplaySource(ctx, src, overlay)
		if err != nil {
			return nil, err
		}
		out := buildReplayOutput(src, nil, rr.jarLoaded, rr.pj)
		out.Browser = summary
		return out, nil
	}

	opts := replay.Options{
		BaselineRequest:      src.BaselineRequest,
		BaselineResponse:     src.BaselineResponse,
		BaselineStatus:       src.BaselineStatus,
		BaselineResponseTime: src.BaselineResponseTime,
		RawRequest:           rr.rawOverride,
		Scheme:               src.Scheme,
		Hostname:             src.Hostname,
		Port:                 src.Port,
		HeaderOverlay:        overlay,
		NoRedirects:          replayNoRedirects,
		Client:               rr.client,
		SendBaseline:         replaySendBaseline,
		BaselineIsEvidence:   src.FindingID != 0 && len(src.BaselineResponse) > 0,
	}
	// --send-via-burp routes the actual send through Burp's engine so the exact bytes
	// (deliberate Content-Length, smuggling, unusual methods) reach the wire; the
	// baseline and diff logic are unchanged.
	if rr.sendViaBurp {
		opts.Sender = burpbridge.BridgeSender(rr.burpClient, src.Scheme, src.Hostname, src.Port, rr.sendOpts, replay.DefaultExcerptCap)
	}

	result, err := replay.Do(ctx, opts)
	if err != nil {
		return nil, err
	}

	if replayInReplace {
		if err := persistReplayResponse(ctx, src, result); err != nil {
			fmt.Fprintf(os.Stderr, "%s replay: --in-replace failed: %v\n", terminal.WarningSymbol(), err)
		}
	}
	if rr.saveToBurp {
		if err := saveReplayResultToBurp(ctx, rr.burpClient, src, result); err != nil {
			return nil, fmt.Errorf("save replay to Burp: %w", err)
		}
	}
	if rr.toRepeater || rr.toOrganizer {
		if err := rr.stageReplayToBurp(ctx, src, result); err != nil {
			return nil, fmt.Errorf("stage replay to Burp: %w", err)
		}
	}

	out := buildReplayOutput(src, result, rr.jarLoaded, rr.pj)
	out.SavedToBurp = rr.saveToBurp
	out.SentViaBurp = rr.sendViaBurp
	out.StagedToRepeater = rr.toRepeater
	out.SavedToOrganizer = rr.toOrganizer
	return out, nil
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

	// URL is the absolute request URL. The send path reconstructs its
	// destination from Scheme/Hostname/Port and the raw request line, so this
	// is carried only for the paths that need a whole URL — --with-browser
	// navigation and record attribution.
	URL string

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
		return nil, usageErrorf("--record-uuid, --finding-id and --input/--input-file are mutually exclusive")
	}

	// openReadDB honors -S/--stateless: a standalone .sqlite/.jsonl export via
	// --db, project scoping off. Falls back to the project DB otherwise. Replay
	// re-sends the stored requests, so a --glob-db merge must keep the bodies.
	db, dbErr := openReadDB(globDBSkipSet{})
	var repo *database.Repository
	if dbErr == nil {
		repo = database.NewRepository(db)
	}

	switch {
	case replayRecordUUID != "":
		if repo == nil {
			//vigolium:not-usage database open failure
			return nil, fmt.Errorf("--record-uuid requires database access: %w", dbErr)
		}
		return sourceFromRecord(ctx, repo, replayRecordUUID)

	case replayFindingID > 0:
		if repo == nil {
			//vigolium:not-usage database open failure
			return nil, fmt.Errorf("--finding-id requires database access: %w", dbErr)
		}
		return sourceFromFinding(ctx, repo, replayFindingID)

	case replayInput != "" || replayInputFile != "":
		return sourceFromInput(ctx, repo, replayInput, replayInputFile, replayRawInputOptions())

	case replayRawRequest != "" || replayRawRequestFile != "":
		// The raw request is the whole request already, so with nothing else
		// named it is the source too: the baseline is those bytes re-sent, and
		// -t supplies the scheme and port a raw request cannot carry.
		raw, err := loadReplayRawOverride()
		if err != nil {
			return nil, err
		}
		return sourceFromInputString(ctx, repo, string(raw), replayRawRequestFile, replayRawInputOptions())

	default:
		data, ok, err := readStdinIfPiped()
		if err != nil {
			return nil, err
		}
		if ok {
			return sourceFromInputString(ctx, repo, data, "", replayRawInputOptions())
		}
		return nil, usageErrorf("no source specified: pass one of --record-uuid, --finding-id, --input/--input-file, --raw-request/--raw-request-file, or pipe a request on stdin")
	}
}

func sourceFromRecord(ctx context.Context, repo *database.Repository, ref string) (*replaySource, error) {
	rec, _, err := loadRecordRef(ctx, repo, ref)
	if err != nil {
		return nil, err
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

func sourceFromInput(ctx context.Context, repo *database.Repository, inline, file string, raw rawInputOptions) (*replaySource, error) {
	var data string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read --input-file %q: %w", file, err)
		}
		data = string(b)
	case inline == "-":
		b, err := readStdin()
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		data = string(b)
	case inlineNamesFile(inline):
		// -i takes the request itself, but `-i req.txt` is what every other
		// command's -i means. A value that parses as no request format and names
		// a regular file can only have meant the file, so read it rather than
		// fail on the file name.
		b, err := os.ReadFile(inline)
		if err != nil {
			return nil, fmt.Errorf("read -i %q: %w", inline, err)
		}
		if !globalSilent {
			fmt.Fprintf(os.Stderr, "%s -i %s read as a file path; --input-file is the explicit form\n",
				terminal.InfoSymbol(), inline)
		}
		data, file = string(b), inline
	default:
		data = inline
	}
	return sourceFromInputString(ctx, repo, data, file, raw)
}

// inlineNamesFile reports whether an -i value is a file path rather than a
// request: it matches no request format, and a regular file by that name
// exists. Text that does parse as a request is never re-read as a path.
func inlineNamesFile(inline string) bool {
	v := strings.TrimSpace(inline)
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return false
	}
	if input.DetectInputType(v) != agenttypes.InputTypeUnknown {
		return false
	}
	info, err := os.Stat(v)
	return err == nil && info.Mode().IsRegular()
}

// sourceFromInputString delegates to the agent input normalizer so a
// curl/raw/burp string from an external driver parses the same way it
// would in autopilot. Raw HTTP text goes through requestinput instead, the
// parser scan-request uses: a missing final blank line is repaired, and the
// scheme comes from the command's -t, the request's own signals or a
// probe of the target, not an https assumption.
func sourceFromInputString(ctx context.Context, repo *database.Repository, data, label string, raw rawInputOptions) (*replaySource, error) {
	if strings.TrimSpace(data) == "" {
		return nil, fmt.Errorf("input is empty")
	}
	if input.DetectInputType(data) == agenttypes.InputTypeRaw {
		if src, err := sourceFromRawText(ctx, data, label, raw); err == nil {
			return src, nil
		}
		// Not parseable as one raw request (a Burp pair, a capture with a
		// response): the general normalizer below decides.
	}
	records, err := input.NormalizeInput(ctx, data, "", repo)
	if errors.Is(err, input.ErrUnknownInputFormat) {
		return nil, codedErrorf(apicontract.CodeInputUnparsed,
			"%v.\n\nPass the request text to -i, a file path to --input-file, or pipe it on stdin", err)
	}
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
		URL:             u.URL.String(),
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

// rawInputOptions is what parsing raw request text needs from the command:
// its -t (pins the scheme) and its --ignore-scope (lets the scheme probe
// contact an out-of-scope host).
type rawInputOptions struct {
	pin         string
	ignoreScope bool
}

func replayRawInputOptions() rawInputOptions {
	return rawInputOptions{pin: replayTargetURL, ignoreScope: replayIgnoreScope}
}

// sourceFromRawText is a raw HTTP request typed or piped to -i, parsed by
// requestinput.Parse. The baseline bytes are the normalized text, header
// terminator included, so the send path parses what the operator pasted.
func sourceFromRawText(ctx context.Context, data, label string, raw rawInputOptions) (*replaySource, error) {
	opts := requestinput.Options{Target: raw.pin, Resolver: requestSchemeResolver, NoProbe: true}
	res, err := requestinput.Parse(ctx, data, opts)
	if err != nil {
		return nil, err
	}
	// The probe contacts the target, so it waits for the scope gate: an
	// out-of-scope host keeps the default and is refused before any send.
	if raw.pin == "" && res.SchemeSource == requestscheme.SourceDefault &&
		newSendScopeGate(raw.ignoreScope).check(res.Request.Target()) == nil {
		opts.NoProbe = false
		if res, err = requestinput.Parse(ctx, data, opts); err != nil {
			return nil, err
		}
	}
	u, err := res.Request.URL()
	if err != nil || u == nil || u.URL == nil {
		return nil, fmt.Errorf("could not extract URL from input")
	}
	src := &replaySource{
		BaselineRequest: []byte(res.Raw),
		Scheme:          u.Scheme,
		Hostname:        u.Hostname(),
		Port:            portFromURL(u.URL),
		URL:             u.URL.String(),
		InputType:       string(agenttypes.InputTypeRaw),
		OriginLabel:     fmt.Sprintf("input (%s)", agenttypes.InputTypeRaw),
	}
	if label != "" {
		src.OriginLabel = fmt.Sprintf("file %s", label)
	}
	if res.SchemeSource == requestscheme.SourceProbe && !globalSilent && !globalJSON {
		fmt.Fprintf(os.Stderr, "%s request line has no scheme — probed the target: %s\n",
			terminal.InfoSymbol(), terminal.Cyan(u.URL.Scheme+"://"+u.Host))
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
		URL:              urlStr,
	}, nil
}

// applyTargetOverride rewrites src's destination. A Host header that named the
// old destination follows it (keepHost off), so the request reaches the new
// environment's virtual host; any other Host (a deliberate vhost, a
// Host-header probe) is sent as written. replay.SendRaw sends the Host header
// as written and, through an HTTP proxy, still names the new destination's
// host:port in the request target.
func applyTargetOverride(src *replaySource, target string, keepHost bool) error {
	u, err := url.Parse(target)
	if err != nil || u == nil || u.Hostname() == "" {
		return usageErrorf("invalid --target %q: %w", target, err)
	}
	oldAuthority := strings.ToLower(replay.Authority(src.Scheme, src.Hostname, src.Port))
	src.Scheme = u.Scheme
	src.Hostname = u.Hostname()
	src.Port = portFromURL(u)
	if keepHost || len(src.BaselineRequest) == 0 {
		return nil
	}
	if host := rawHostHeader(src.BaselineRequest); host != "" && strings.EqualFold(host, oldAuthority) {
		if rewritten, err := httpmsg.AddOrReplaceHeader(src.BaselineRequest, "Host", replay.Authority(src.Scheme, src.Hostname, src.Port)); err == nil {
			src.BaselineRequest = rewritten
		}
	}
	return nil
}

// rawHostHeader is the Host header of a raw request ("" when it has none).
func rawHostHeader(raw []byte) string {
	head := raw
	if i := bytes.Index(head, []byte("\r\n\r\n")); i >= 0 {
		head = head[:i]
	} else if i := bytes.Index(head, []byte("\n\n")); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(string(head), "\n") {
		name, value, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			return strings.TrimSpace(value)
		}
	}
	return ""
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

func loadReplayRawOverride() ([]byte, error) {
	switch {
	case replayRawRequest != "" && replayRawRequestFile != "":
		return nil, usageErrorf("--raw-request and --raw-request-file are mutually exclusive")
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
		headers, err := resolveAuthSessionHeaders(ctx, replayAuthSession, src)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			overlay[k] = v
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

// resolveAuthSessionHeaders looks up a named auth session's stored headers for
// a hostname. Shared by `replay --auth-session` and `fuzz --auth-session` so
// the lookup, the project scoping, and the not-found message stay identical
// between them.
func resolveAuthSessionHeaders(ctx context.Context, sessionName string, src *replaySource) (map[string]string, error) {
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		//vigolium:not-usage database open failure
		return nil, fmt.Errorf("--auth-session requires database access: %w", err)
	}
	repo := database.NewRepository(db)
	pid, _ := effectiveProjectUUID()
	// The key auth load writes (host:port unless the port is the scheme's
	// default), then the bare host for sessions stored without a port.
	key := database.AuthHostKeyFor(src.Scheme, src.Hostname, strconv.Itoa(src.Port))
	for _, k := range database.AuthHostLookupKeys(key) {
		rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, pid, k)
		if err != nil {
			return nil, fmt.Errorf("lookup auth sessions: %w", err)
		}
		for _, row := range rows {
			if row.SessionName == sessionName {
				return row.Headers, nil
			}
		}
	}
	return nil, fmt.Errorf("auth session %q not found for %s", sessionName, key)
}

// parseReplayHeaderFlags parses the repeatable --header flags into an overlay
// map, erroring on the first malformed entry. Host-independent, so the bulk
// path parses it once and reuses it across records.
func parseReplayHeaderFlags() (map[string]string, error) {
	overlay := map[string]string{}
	for i, h := range replayHeaders {
		name, value, err := replay.ParseHeaderFlag(h)
		if err != nil {
			return nil, usageErrorf("--header[%d]: %w", i, err)
		}
		overlay[name] = value
	}
	return overlay, nil
}

func openReplayJar() (*jar.PersistentJar, int, error) {
	if replayNoCookies || replaySessionID == "" {
		return nil, 0, nil
	}
	return openSessionJar(replaySessionID)
}

// openSessionJar resolves a named session's cookie jar on disk. Shared by
// `replay --session-id` and `fuzz --session-id` so the VIGOLIUM_HOME fallback
// and the "couldn't resolve a path" message live in one place.
func openSessionJar(sessionID string) (*jar.PersistentJar, int, error) {
	path := jar.PathFor(sessionID)
	if path == "" {
		return nil, 0, fmt.Errorf("could not resolve jar path (set VIGOLIUM_HOME or HOME)")
	}
	return jar.Open(path)
}

func persistReplayResponse(ctx context.Context, src *replaySource, result *replay.Result) error {
	if src.RecordUUID == "" {
		//vigolium:not-usage reached after the replay was sent
		return fmt.Errorf("--in-replace requires a stored record (got %s)", src.OriginLabel)
	}
	// Records merged in from a live Burp bridge have no row to update: they
	// exist only in Burp's proxy history for the duration of the query.
	if burpbridge.IsBridgeUUID(src.RecordUUID) {
		//vigolium:not-usage reached after the replay was sent
		return fmt.Errorf("--in-replace skipped: live Burp records are read-only")
	}
	if result.Replay == nil || result.Replay.Error != "" {
		//vigolium:not-usage reached after the replay was sent
		return fmt.Errorf("--in-replace skipped: replay had no usable response")
	}
	body := result.Replay.RawBody
	if body == nil {
		// Defensive: the engine populates RawBody on every successful
		// send. If we ever stop doing that, refuse rather than write
		// the clipped excerpt back as the canonical body.
		//vigolium:not-usage reached after the replay was sent
		return fmt.Errorf("--in-replace skipped: engine did not return body bytes")
	}
	// Write back to the same store the record was read from — openReadDB, not
	// getDB. Under -S/--stateless that is the standalone export being replayed,
	// which is where the refreshed response belongs; routing to the project DB
	// instead would update rows whose UUIDs came from a different database.
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return err
	}
	repo := database.NewRepository(db)

	raw := rawReplayResponse(result.Replay)

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

func saveReplayResultToBurp(
	ctx context.Context,
	client *burpbridge.Client,
	src *replaySource,
	result *replay.Result,
) error {
	if client == nil {
		return fmt.Errorf("burp bridge client is not configured")
	}
	if result == nil || len(result.RawMutatedRequest) == 0 {
		return fmt.Errorf("replay did not return the complete sent request")
	}
	var rawResponse []byte
	if result.Replay != nil && result.Replay.Status > 0 && result.Replay.Error == "" {
		rawResponse = rawReplayResponse(result.Replay)
	}
	return client.AddToSiteMap(
		ctx,
		replaySourceURL(src),
		result.RawMutatedRequest,
		rawResponse,
		"vigolium-replay",
	)
}

// stageReplayToBurp pushes the just-sent request (and, where available, its
// response) into Burp's Repeater and/or Organizer for manual follow-up. The
// request was already issued (via Go or, under --send-via-burp, via Burp), so this
// only stages — it never re-sends.
func (rr *replayRun) stageReplayToBurp(ctx context.Context, src *replaySource, result *replay.Result) error {
	if rr.burpClient == nil {
		return fmt.Errorf("burp bridge client is not configured")
	}
	if result == nil || len(result.RawMutatedRequest) == 0 {
		return fmt.Errorf("replay did not return the complete sent request")
	}
	target := replaySourceURL(src)
	var rawResponse []byte
	if result.Replay != nil && result.Replay.Status > 0 && result.Replay.Error == "" {
		rawResponse = rawReplayResponse(result.Replay)
	}
	if rr.toRepeater {
		if _, err := rr.burpClient.SendToRepeater(ctx, target, "", result.RawMutatedRequest, burpbridge.RepeaterOptions{
			TabName: replayRepeaterTab,
		}); err != nil {
			return err
		}
	}
	if rr.toOrganizer {
		if _, err := rr.burpClient.SendToOrganizer(ctx, target, "", result.RawMutatedRequest, rawResponse, burpbridge.OrganizerOptions{
			Source:    "vigolium-replay",
			Notes:     replayNotes,
			Highlight: replayHighlight,
		}); err != nil {
			return err
		}
	}
	return nil
}

func replaySourceURL(src *replaySource) string {
	scheme := src.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := src.Hostname
	if src.Port > 0 {
		host = net.JoinHostPort(src.Hostname, strconv.Itoa(src.Port))
	}
	return (&url.URL{Scheme: scheme, Host: host}).String()
}

func rawReplayResponse(summary *replay.Summary) []byte {
	if summary == nil || summary.Status <= 0 {
		return nil
	}
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
	// Browser is set instead of Result for --with-browser runs, which navigate
	// rather than re-send and so produce no baseline-vs-replay diff.
	Browser          *browserReplaySummary `json:"browser,omitempty"`
	SavedToBurp      bool                  `json:"saved_to_burp,omitempty"`
	SentViaBurp      bool                  `json:"sent_via_burp,omitempty"`
	StagedToRepeater bool                  `json:"staged_to_repeater,omitempty"`
	SavedToOrganizer bool                  `json:"saved_to_organizer,omitempty"`
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

// emitReplayPretty renders one result to w, dispatching to the browser renderer
// for navigation runs (which have no diff table to print).
//
// It takes an io.Writer rather than printing directly so a bulk run can render
// into a buffer off-lock and emit each record's block in one write — building
// the table under the shared output mutex would serialize every worker's
// formatting behind one tty write.
func emitReplayPretty(w io.Writer, out *replayOutput) error {
	emitReplayOutputHeader(w, out)

	if out.Browser != nil {
		return emitBrowserReplayPretty(w, out)
	}
	if out.Result == nil || out.Result.Replay == nil {
		return fmt.Errorf("no result")
	}
	if out.Result.Baseline == nil || out.Result.Diff == nil {
		return emitReplaySinglePretty(w, out)
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
	_, _ = fmt.Fprint(w, tbl.Render())
	if r.Error != "" {
		_, _ = fmt.Fprintf(w, "  %s replay error: %s\n", terminal.ErrorPrefix(), r.Error)
	}
	if d.Interpretation != "" {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.InfoSymbol(), d.Interpretation)
	}
	if len(d.ReflectsPayload) > 0 {
		_, _ = fmt.Fprintf(w, "  %s reflected payloads: %s\n", terminal.WarnPrefix(), strings.Join(d.ReflectsPayload, ", "))
	}
	if len(out.Result.Unmatched) > 0 {
		_, _ = fmt.Fprintf(w, "  %s unmatched insertion points: %s\n",
			terminal.WarnPrefix(), strings.Join(out.Result.Unmatched, ", "))
	}
	if out.Result.AdditionalGroups > 0 {
		_, _ = fmt.Fprintf(w, "  %s %d additional payload group(s) not sent — re-run to fire them\n",
			terminal.InfoSymbol(), out.Result.AdditionalGroups)
	}
	return nil
}

// emitReplaySinglePretty renders a replay that was sent once, with no
// baseline to compare against.
func emitReplaySinglePretty(w io.Writer, out *replayOutput) error {
	r := out.Result.Replay
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "RESPONSE")
	tbl.AddRow("Status", colorStatus(fmt.Sprintf("%d", r.Status), r.Status))
	tbl.AddRow("Length", fmt.Sprintf("%d", r.ResponseLen))
	tbl.AddRow("Hash", clicommon.Truncate(r.ContentHash, 16))
	tbl.AddRow("Time (ms)", fmt.Sprintf("%d", r.ResponseTimeMs))
	_, _ = fmt.Fprint(w, tbl.Render())
	if r.Error != "" {
		_, _ = fmt.Fprintf(w, "  %s replay error: %s\n", terminal.ErrorPrefix(), r.Error)
	}
	_, _ = fmt.Fprintf(w, "  %s sent once; pass --baseline to also send a baseline and diff\n", terminal.InfoSymbol())
	return nil
}

// emitReplayOutputHeader writes the source/target/session preamble shared by
// the diff and browser renderers — it describes the replayOutput envelope, not
// the send, so both modes report it identically.
func emitReplayOutputHeader(w io.Writer, out *replayOutput) {
	_, _ = fmt.Fprintf(w, "%s %s\n", terminal.Cyan("→"), out.Source)
	_, _ = fmt.Fprintf(w, "  target: %s\n", out.Target)
	if out.SessionID != "" {
		_, _ = fmt.Fprintf(w, "  session: %s (preloaded %d cookies, jar: %s)\n",
			out.SessionID, out.CookiesPreloaded, out.JarPath)
	}
	if out.SentViaBurp {
		_, _ = fmt.Fprintf(w, "  sent via Burp's HTTP engine\n")
	}
	if out.SavedToBurp {
		_, _ = fmt.Fprintf(w, "  saved to Burp Target Site map\n")
	}
	if out.StagedToRepeater {
		_, _ = fmt.Fprintf(w, "  staged in Burp Repeater\n")
	}
	if out.SavedToOrganizer {
		_, _ = fmt.Fprintf(w, "  saved to Burp Organizer\n")
	}
}

// urlShapedPositional reports whether a replay positional looks like a
// request target (a URL, an absolute path, a path with a query) rather than
// a search term: those are refused, since the bulk search they would run is
// almost never what was meant.
func urlShapedPositional(v string) bool {
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"), strings.HasPrefix(v, "/"):
		return true
	case strings.Contains(v, "?") && strings.Contains(v, "="):
		return !strings.ContainsAny(v, " \t")
	}
	return false
}

// installReplayTrafficDump routes replay's sends through --dump-traffic.
func installReplayTrafficDump() {
	if globalDumpTraffic {
		replay.TrafficDump = vighttp.DumpExchange
	} else {
		replay.TrafficDump = nil
	}
}
