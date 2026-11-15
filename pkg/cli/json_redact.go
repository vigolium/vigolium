package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/replay"
)

// A -j document is read into a coding agent's transcript, which is logged,
// summarised and sent to a model provider. A stored session cookie or bearer
// token in a raw header view goes everywhere the transcript goes. So when a
// coding agent is detected (codingAgentEnvVars: a separate list from CI, where
// the output lands in a job log the operator controls), -j documents mask
// credential header values, cookie values and sensitive query parameters, and
// say so in `redacted`. --redact forces it on, --no-redact off.
//
// Only views are redacted. The database, exports (`export`, `--format jsonl`,
// `db export`), the per-payload streams and human output stay raw: re-sending a
// record by UUID reads the stored bytes, so nothing an agent does next needs
// the secret in its context. Bodies are evidence and are kept.

var (
	globalRedact   bool
	globalNoRedact bool
)

// jsonRedactOn is the resolved mode for this invocation (set in the root
// pre-run, before any command writes).
var jsonRedactOn bool

func registerRedactFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.BoolVar(&globalRedact, "redact", false,
		"With -j: mask credential header values, cookie values and sensitive query parameters in raw request/response views (on by default when a coding-agent variable such as CLAUDECODE is set; exports and the database stay raw)")
	pf.BoolVar(&globalNoRedact, "no-redact", false,
		"With -j: print credentials in raw request/response views even when a coding agent is detected")
}

// applyRedactionMode resolves --redact/--no-redact and the environment.
func applyRedactionMode() error {
	if globalRedact && globalNoRedact {
		return usageErrorf("--redact and --no-redact are mutually exclusive")
	}
	jsonRedactOn = resolveJSONRedaction(globalJSON, globalRedact, globalNoRedact, os.Getenv)
	return nil
}

// resolveJSONRedaction: only -j documents are redacted; an explicit flag wins;
// otherwise a detected coding agent turns it on.
func resolveJSONRedaction(jsonMode, on, off bool, getenv func(string) string) bool {
	switch {
	case !jsonMode, off:
		return false
	case on:
		return true
	}
	name, _ := detectCodingAgent(getenv)
	return name != ""
}

// redactRaw masks a raw HTTP message when redaction is on.
func redactRaw(on bool, raw string) string {
	if !on {
		return raw
	}
	return redact.HTTPMessage(raw, nil)
}

// redactURL masks sensitive query parameters of a URL when redaction is on.
func redactURL(on bool, u string) string {
	if !on || u == "" {
		return u
	}
	return redact.URL(u)
}

// redactReplayOutputs returns copies of outs with the exchange's request,
// URLs and response headers masked; outs are not modified (the stream written
// beside the document keeps the raw bytes).
func redactReplayOutputs(outs []*replayOutput) []*replayOutput {
	red := make([]*replayOutput, len(outs))
	for i, o := range outs {
		if o == nil || o.Result == nil {
			red[i] = o
			continue
		}
		c := *o
		c.Target = redactURL(true, o.Target)
		r := *o.Result
		r.MutatedRequest = redactRaw(true, r.MutatedRequest)
		r.Baseline = redactReplaySummary(r.Baseline)
		r.Replay = redactReplaySummary(r.Replay)
		c.Result = &r
		red[i] = &c
	}
	return red
}

func redactReplaySummary(s *replay.Summary) *replay.Summary {
	if s == nil {
		return nil
	}
	c := *s
	c.Headers = redact.Header(s.Headers, nil)
	c.FinalURL = redactURL(true, s.FinalURL)
	return &c
}

// redactHeaderEntries masks the values of credential headers in a parsed
// header block when redaction is on; entries are not modified.
func redactHeaderEntries(on bool, entries []headerEntry) []headerEntry {
	if !on {
		return entries
	}
	out := make([]headerEntry, len(entries))
	for i, e := range entries {
		out[i] = headerEntry{Name: e.Name, Value: redact.HeaderValue(e.Name, e.Value, nil)}
	}
	return out
}

// redactStartLine masks sensitive query parameters on a request line when
// redaction is on.
func redactStartLine(on bool, line string) string {
	if !on {
		return line
	}
	return redact.StartLine(line)
}

// redactFuzzDryRun masks the baseline request and the rendered examples of a
// fuzz dry run when redaction is on.
func redactFuzzDryRun(r fuzzDryRunReport) fuzzDryRunReport {
	if !jsonRedactOn {
		return r
	}
	r.Target = redactURL(true, r.Target)
	r.Request = redactRaw(true, r.Request)
	r.ExampleCase = redactRaw(true, r.ExampleCase)
	pos := make([]fuzzDryRunPos, len(r.Positions))
	for i, p := range r.Positions {
		p.Example = redactRaw(true, p.Example)
		pos[i] = p
	}
	r.Positions = pos
	return r
}
