package cli

import (
	"context"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// Who owns stdout.
//
// A scan command can be asked to write up to three different things there, and
// two of them are streams with no framing of their own:
//
//   - `--events ndjson`, one event object per line, for the whole run;
//   - `--format jsonl` with no -o, the bulk export streamed to stdout;
//   - `--print-finding` / `--print-traffic` / `--print-traffic-tree`, Markdown.
//
// Any two of those interleave into a stream that is not what either contract
// describes: a consumer reading NDJSON events hits a Markdown heading, or two
// different object shapes on alternate lines with no `type` to tell them apart.
// Nothing detected the combination, so the corruption was silent and the exit
// code was 0.
//
// --events is the one that owns the stream, because it is the only one that
// writes DURING the run and therefore cannot be relocated after the fact: the
// others all have an -o or a file destination. So the rule is one-way: asking
// for --events alongside another stdout writer is a usage error (exit 2) naming
// the conflict and the fix, rather than a corrupt stream.

//
// -j is the other owner. On the scan commands it prints ONE scan document once
// the run is over (scan_document.go), and every other stdout writer — the
// event stream included — would put a second protocol in front of it. So -j
// with any of them is a usage error too; their file forms (-o for --format
// jsonl) stay available.

// validateStdoutProtocol rejects a flag set in which -j's scan document or
// --events would share stdout with another writer. It is a no-op when neither
// was asked for.
func validateStdoutProtocol(opts *types.Options) error {
	if opts == nil {
		return nil
	}
	if err := validateScanDocumentProtocol(opts); err != nil {
		return err
	}
	if strings.TrimSpace(opts.Events) == "" {
		return nil
	}
	const fix = "Add -o <file> or drop --events"
	switch {
	// jsonl WITH -o goes to the file, so only the stdout case conflicts.
	case opts.HasFormat("jsonl") && strings.TrimSpace(opts.Output) == "":
		return usageErrorf("--events owns stdout; --format jsonl without -o would also write there. %s", fix)
	case scanPrintFinding:
		return usageErrorf("--events owns stdout; --print-finding writes Markdown there too. %s", fix)
	case scanPrintTraffic:
		return usageErrorf("--events owns stdout; --print-traffic writes Markdown there too. %s", fix)
	case scanPrintTrafficTree:
		return usageErrorf("--events owns stdout; --print-traffic-tree writes a tree there too. %s", fix)
	}
	return nil
}

// validateScanDocumentProtocol rejects -j together with another stdout writer
// on a scan command. -j alone is the scan document; with --format jsonl the
// stream goes to the -o file and the document to stdout.
func validateScanDocumentProtocol(opts *types.Options) error {
	if !globalJSON {
		return nil
	}
	const owns = "-j prints one scan document on stdout when the scan ends"
	switch {
	case strings.TrimSpace(opts.Events) != "":
		// Decision D11: no final scan.result event; the two stay separate until
		// --events can write to a file.
		return usageErrorf("%s; --events streams NDJSON there while it runs. Drop one of them (read the result afterwards with `vigolium finding --scan-uuid <uuid> -j`)", owns)
	case opts.HasFormat("jsonl") && strings.TrimSpace(opts.Output) == "":
		return usageErrorf("%s; --format jsonl without -o would stream the export there too. Add -o <file> for the jsonl stream, or drop --format jsonl", owns)
	case scanPrintFinding:
		return usageErrorf("%s; --print-finding writes Markdown there too. Drop one of them", owns)
	case scanPrintTraffic:
		return usageErrorf("%s; --print-traffic writes Markdown there too. Drop one of them", owns)
	case scanPrintTrafficTree:
		return usageErrorf("%s; --print-traffic-tree writes a tree there too. Drop one of them", owns)
	}
	return nil
}

// rejectFanOutJSON refuses -j on a fan-out that scans its targets as child
// processes (-P/--parallel over -T, -S -T --split-by-host): the parent has no
// scan of its own to describe, and each child's stdout is its console log, so
// -j printed nothing at all. Aggregating the children's documents into one is
// a follow-up; until then the combination is a usage error, never an empty
// stdout.
func rejectFanOutJSON() error {
	if !globalJSON {
		return nil
	}
	return usageErrorf("-j is not supported with a per-target fan-out (-P/--parallel over -T, or -S -T --split-by-host): each target scans in its own process and no single scan document reaches your stdout.\n" +
		"Scan without the fan-out (drop -P/--split-by-host), or drop -j and read each scan afterwards with `vigolium finding --scan-uuid <uuid> -j`")
}

// rejectCIOutputFlag refuses the removed --ci-output-format. It printed no
// findings for `scan`, and what it promised is -j (one scan document) or
// --format jsonl (the findings stream).
func rejectCIOutputFlag() error {
	if !globalCIOutput {
		return nil
	}
	// Report the refusal in the caller's own mode: the flag no longer makes
	// this a machine-output run.
	globalCIOutput = false
	return clicommon.CLIError{
		Err:  usageErrorf("--ci-output-format was removed"),
		Hint: "use -j for one scan document on stdout, or --format jsonl -o <file> (or --format jsonl alone, to stdout) for the findings stream",
	}
}

// scanInput is one parsed request the lightweight commands were asked to scan,
// carried with the target and method its result reports. Built up front so the
// aggregation below can count what it did not get to.
type scanInput struct {
	rr     *httpmsg.HttpRequestResponse
	target string
	method string
}

// scanInputs runs fn over each input, stopping as soon as ctx is cancelled.
//
// It returns the results it collected, the targets it never dispatched, and the
// last error. The not-scanned list is the point: a Ctrl-C partway through
// `scan-url -t a -t b -t c` used to leave the caller with results for `a` and
// no statement at all about `b` and `c`, which reads identically to a run that
// scanned all three and found nothing on two of them.
//
// fn is a parameter so the cancellation behaviour is testable without a network.
func scanInputs(
	ctx context.Context,
	inputs []scanInput,
	fn func(context.Context, scanInput) (*scanResult, error),
) (results []*scanResult, notScanned []string, err error) {
	for i, in := range inputs {
		if ctx.Err() != nil {
			for _, rest := range inputs[i:] {
				notScanned = append(notScanned, rest.target)
			}
			return results, notScanned, err
		}
		res, scanErr := fn(ctx, in)
		if scanErr != nil {
			err = scanErr
		}
		if res != nil {
			results = append(results, res)
		}
	}
	return results, notScanned, err
}
