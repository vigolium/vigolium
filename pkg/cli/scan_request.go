package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/requestinput"
)

// scan-request flags
var (
	scanReqInput  string
	scanReqTarget string
)

var scanRequestCmd = &cobra.Command{
	Use:   "scan-request",
	Short: "Scan a raw HTTP request for vulnerabilities",
	Long: `Read a raw HTTP request from file or stdin and run scanner modules against it.
Designed for pipeline integration and AI agent workflows.
Accepts raw HTTP requests, curl commands, and supports format auto-detection.`,
	Args: cobra.NoArgs,
	RunE: runScanRequestCmd,
}

func init() {
	rootCmd.AddCommand(scanRequestCmd)
	flags := scanRequestCmd.Flags()

	flags.StringVarP(&scanReqInput, "input", "i", "-", "Input file or - for stdin")
	flags.StringVarP(&scanReqTarget, "target", "t", "", "Override target URL (scheme://host)")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	flags.BoolVar(&scanIgnoreScope, "ignore-scope", false, ignoreScopeFlagUsage)
	flags.BoolVar(&scanReqNoSchemeProbe, "no-scheme-probe", false, "Do not probe the target (TCP connect / TLS handshake) when the request carries no scheme signal; keep the https default")
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerHTTPClientFlags(flags)
	flags.StringArrayVarP(&scanURLHeaders, "header", "H", nil, "Set a header on the captured request (repeatable, e.g. -H 'Cookie: a=1'): replaces every same-named captured header, else appends. Commas are literal — repeat -H for multiple headers.")
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
	registerIncludeStoredFlag(scanRequestCmd)
	registerLightweightScanTuningFlags(flags)
}

func runScanRequestCmd(cmd *cobra.Command, _ []string) error {
	defer syncLogger()

	if err := resetFailOnGate(); err != nil {
		return err
	}
	if err := validateModuleSelectionFlags(scanURLNoPassive); err != nil {
		return err
	}
	if err := resolveScanOutputs(cmd); err != nil {
		return err
	}
	// Validate --format before any network activity so an unknown format (or
	// fs/sqlite) fails fast instead of being silently ignored on the direct path.
	if err := validateGlobalFormats(); err != nil {
		return err
	}
	if err := validateEventsFlag(scanOpts.Events); err != nil {
		return asUsageError(err)
	}
	if err := validateNoAuth(); err != nil {
		return err
	}
	// Validated here, not only in runRunnerScan: without -S/-o this command takes
	// the direct in-memory path, which never reaches the Runner — so a check
	// there alone let `scan-url --keep-db-on-error` exit 0 having done nothing
	// with the flag, which is the shape of control this plan exists to remove.
	if err := validateKeepDBOnError(globalStateless); err != nil {
		return err
	}
	if err := validateLightweightScanTuning(); err != nil {
		return err
	}

	// Read raw HTTP request
	var raw []byte
	var err error

	if scanReqInput == "-" {
		raw, err = readScanRequestStdin(cmd.Flags().Changed("input"))
		if err != nil {
			return err
		}
	} else {
		// Bounded like the stdin branch rather than an unbounded os.ReadFile:
		// -i accepts a FIFO or /dev/stdin just as readily as a regular file, and
		// those have neither a size nor an end a plain ReadFile can rely on.
		// No deadline — a named file is not a producer that can stall, and
		// --input-read-timeout is documented as the stdin dial.
		var f *os.File
		if f, err = os.Open(scanReqInput); err == nil {
			defer func() { _ = f.Close() }()
			raw, err = clicommon.ReadBounded(f, scanReqInput, clicommon.DefaultStdinLimit, 0)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	rawStr := string(raw)
	if strings.TrimSpace(rawStr) == "" {
		return usageErrorf("empty request input")
	}

	// Detect format and parse request. Detection runs on the fully trimmed text
	// — surrounding whitespace says nothing about whether this is curl or raw
	// HTTP — but the raw parser gets the byte-preserving normalization instead,
	// because for a request with a body those bytes ARE the request.
	var rr *httpmsg.HttpRequestResponse
	// normalized is the raw request as parsed; empty for curl input, whose URL
	// carries its scheme.
	var normalized string
	trimmed := strings.TrimSpace(rawStr)
	detected := detect.DetectStdinFormat(trimmed)
	if detected == detect.FormatCurl {
		// Curl command detected — parse via curl parser
		items, parseErr := detect.ParseStdinContent(trimmed, detect.FormatCurl)
		if parseErr != nil {
			return fmt.Errorf("failed to parse curl command: %w", parseErr)
		}
		rr = items[0]
	} else {
		// Raw HTTP (or fallback) — use existing raw HTTP parser
		normalized = normalizeRawRequestInput(rawStr)
		if scanReqTarget != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(normalized, scanReqTarget)
		} else {
			rr, err = httpmsg.ParseRawRequest(normalized)
		}
		if err != nil {
			return fmt.Errorf("failed to parse raw request: %w", err)
		}
	}

	// -H overrides the captured request (replace a same-named header, else
	// append), before admission so a Host override is admitted as sent.
	if rr, err = applyRequestHeaderOverrides(rr, scanURLHeaders); err != nil {
		return err
	}

	// Extract method and target for output
	method := rr.Request().Method()
	target := rr.Target()

	// Scope admission, before any network activity: a refused request is
	// reported (exit 1, no_targets_in_scope) without being sent.
	inputs := []scanInput{{rr: rr, target: target, method: method}}
	scopeEscapeHint = "or pass --ignore-scope to scan it anyway"
	cfg := &directSettings{}
	admission, err := admitDirectInputs(cfg, inputs)
	if err != nil {
		return err
	}
	if err := admission.refuse(); err != nil {
		return err
	}

	// One cancellation context for the invocation — scan-request scans exactly one
	// request, but the handler lives in the direct path shared with scan-url, and
	// installing the signal trap per request is what leaked a goroutine there.
	ctx, stop := lightweightScanContext()
	defer stop()

	// No -t override and no scheme on the request line: settle the scheme from
	// the request's own signals, else probe the target (after admission, so a
	// refused target is never contacted). A probe that changed the target is
	// admitted again over the URL that will actually be sent.
	_, refused := admission.verdict(target)
	// A dry run sends nothing, so the scheme is not probed.
	resolved, schemeSource := settleRequestScheme(ctx, normalized, rr, scanReqTarget != "", scanReqNoSchemeProbe || refused || scanDryRun)
	if resolved != rr {
		// A probe rebuilds the request from the captured text, so the -H
		// overrides are applied again.
		if resolved, err = applyRequestHeaderOverrides(resolved, scanURLHeaders); err != nil {
			return err
		}
		rr, target = resolved, resolved.Target()
		inputs = []scanInput{{rr: rr, target: target, method: method}}
		if admission, err = admitDirectInputs(cfg, inputs); err != nil {
			return err
		}
		if err := admission.refuse(); err != nil {
			return err
		}
	}

	if scanDryRun {
		return runLightweightDryRun(cmd, inputs)
	}

	sess := newDirectScanSession(database.ScanNameScanRequest, inputs)
	sess.admission = admission
	sess.cfg = cfg
	sess.schemeSource = schemeSource
	defer sess.close()

	// Route through the Runner when output/persistence/phase flags are in play;
	// otherwise take the fast in-memory direct path. An input that got no answer
	// fails the command (no_targets_reachable) after its result was written.
	// Under -j either path is folded into the one scan document.
	if globalJSON {
		return withFailOnGate(admission.settle(sess.reach.settle(runScanDocumentBatch(ctx, cmd, sess, inputs))))
	}
	return withFailOnGate(admission.settle(sess.reach.settle(dispatchSingleScan(ctx, sess, rr, target, method))))
}

// applyRequestHeaderOverrides applies scan-request's -H values to the captured
// request: each replaces every captured header of the same name
// (case-insensitive), or is appended when the capture has none. So -H
// overrides the capture: `-H 'Cookie: session=fresh'` swaps a stale captured
// Cookie instead of sending two. Two -H with one name: the last wins, as on the
// Runner path, where the requester sets each -H on every request.
func applyRequestHeaderOverrides(rr *httpmsg.HttpRequestResponse, headers []string) (*httpmsg.HttpRequestResponse, error) {
	if len(headers) == 0 || rr == nil || rr.Request() == nil {
		return rr, nil
	}
	req := rr.Request()
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, usageErrorf("invalid -H %q: want 'Name: value'", h)
		}
		req = req.WithHeader(name, strings.TrimSpace(value))
	}
	return httpmsg.NewHttpRequestResponse(req, rr.Response()), nil
}

// normalizeRawRequestInput prepares a raw HTTP request for the parser while
// preserving the bytes that are part of the message.
//
// Leading whitespace is always stripped: a blank first line would be read as
// the request line, and nothing legitimate precedes the method. Trailing
// whitespace is a different matter. `scan-request` used to hand the parser
// strings.TrimSpace(input), which silently rewrote the body of every request
// whose payload ends in whitespace — a trailing newline in a JSON body, the
// CRLF a chunked encoder emits, a form field whose value ends with a space. The
// request that then went on the wire was not the request the operator pasted,
// and with Content-Length still declaring the original length the server saw a
// truncated body.
//
// So trailing whitespace is only trimmed when the headers say there is no body
// to damage: no Content-Length and no Transfer-Encoding. That keeps the old
// forgiving behavior for the common bodyless GET pasted out of a terminal, and
// stops guessing the moment the request declares a body.
func normalizeRawRequestInput(raw string) string {
	parsed, _ := requestinput.Normalize(raw)
	return parsed
}

// scanRequestNoInput is the usage message for scan-request with nothing to read.
const scanRequestNoInput = "no request: scan-request reads a raw HTTP request or curl command from -i <file> or stdin"

// readScanRequestStdin reads the request from stdin. -i defaults to "-", so an
// untyped -i is the implicit case: a terminal stdin fails fast (it used to block
// on the keyboard) and a pipe gets the first-byte window. A typed `-i -` is an
// explicit request for stdin and waits the full --input-read-timeout.
func readScanRequestStdin(inputTyped bool) ([]byte, error) {
	if inputTyped {
		raw, err := readStdin()
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		return raw, nil
	}
	if !fileutil.HasStdin() {
		return nil, usageErrorf("%s (stdin is a terminal)", scanRequestNoInput)
	}
	raw, err := readImplicitStdin()
	if err != nil {
		if errors.Is(err, clicommon.ErrStdinNoData) {
			return nil, usageErrorf("%s (nothing arrived on stdin within %s; use -i - to wait for a slow producer)",
				scanRequestNoInput, implicitStdinWait)
		}
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	return raw, nil
}
