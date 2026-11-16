package cli

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/replay"
)

// A -j document is read into a coding agent's transcript, which is logged,
// summarised and sent to a model provider. A stored session cookie or bearer
// token in a raw header view goes everywhere the transcript goes. So when a
// coding agent is detected (codingAgentEnvVars: a separate list from CI, where
// the output lands in a job log the operator controls), -j documents mask
// credential header values, cookie values and sensitive query parameters.
//
// The mode resolves in this order: --redact / --no-redact, then
// $VIGOLIUM_REDACT (1/true on, 0/false off), then coding-agent detection. The
// variable exists for a driver whose deterministic reads need the raw bytes
// while its own process tree carries an agent marker it cannot unset for the
// model it hosts: an env override reaches every subprocess, a flag only the
// invocations that remember it.
//
// Only views are redacted. The database, exports (`export`, `--format jsonl`,
// `db export`), the per-payload streams and human output stay raw: re-sending a
// record by UUID reads the stored bytes, so nothing an agent does next needs
// the secret in its context. Bodies are evidence and are kept.
//
// The envelope's `redacted` reports what happened to THIS document: true when
// a credential-bearing view in it was produced in masked form (markRedacted),
// false when the document has no such view — a `version -j` under a coding
// agent says false, because there was nothing to mask.

var (
	globalRedact   bool
	globalNoRedact bool
)

// jsonRedactOn is the resolved mode for this invocation (set in the root
// pre-run, before any command writes).
var jsonRedactOn bool

// redactRequested is the same resolution as if -j were on: jsonRedactOn is
// redactRequested under -j. A command that can write the same values outside
// the envelope (kit cookies --stdout) honours it without -j.
var redactRequested bool

// redactEnvVar overrides coding-agent detection; the flags still win.
const redactEnvVar = "VIGOLIUM_REDACT"

// viewsRedacted records that a view in this invocation's document was masked.
// Atomic because the scan document is assembled from goroutines.
var viewsRedacted atomic.Bool

// markRedacted records that a credential-bearing view was produced masked, so
// the envelope's `redacted` says so.
func markRedacted() { viewsRedacted.Store(true) }

func registerRedactFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.BoolVar(&globalRedact, "redact", false,
		"With -j: mask credential header values, cookie values and sensitive query parameters in raw request/response views (on by default when a coding-agent variable such as CLAUDECODE is set, or with VIGOLIUM_REDACT=1; exports and the database stay raw)")
	pf.BoolVar(&globalNoRedact, "no-redact", false,
		"With -j: print credentials in raw request/response views even when a coding agent is detected (VIGOLIUM_REDACT=0 does the same for every subprocess)")
}

// applyRedactionMode resolves --redact/--no-redact and the environment.
func applyRedactionMode() error {
	if globalRedact && globalNoRedact {
		return usageErrorf("--redact and --no-redact are mutually exclusive")
	}
	viewsRedacted.Store(false)
	on, err := resolveJSONRedaction(true, globalRedact, globalNoRedact, os.Getenv)
	if err != nil {
		return err
	}
	redactRequested = on
	jsonRedactOn = globalJSON && on
	return nil
}

// resolveJSONRedaction: only -j documents are redacted; an explicit flag wins;
// then $VIGOLIUM_REDACT; otherwise a detected coding agent turns it on.
//
// The variable is parsed strictly. An unrecognised value is a usage error
// rather than a guess: read as "off" it would print credentials into the
// transcript the caller was trying to protect, and read as "on" it would
// silently defeat a driver that meant 0.
func resolveJSONRedaction(jsonMode, on, off bool, getenv func(string) string) (bool, error) {
	env, envSet, err := strictEnvBool(getenv, redactEnvVar)
	if err != nil {
		return false, err
	}
	switch {
	case !jsonMode, off:
		return false, nil
	case on:
		return true, nil
	case envSet:
		return env, nil
	}
	name, _ := detectCodingAgent(getenv)
	return name != "", nil
}

// strictEnvBool reads a boolean switch variable the strict way
// ($VIGOLIUM_REDACT, $VIGOLIUM_REQUIRE_SCOPE): unset or blank is "not set",
// strconv.ParseBool's forms are the value, and anything else is a usage error
// (exit 2) — a misspelled safety switch must not silently read as either
// state. A consent variable that only needs "is it on" uses utils.Truthy.
func strictEnvBool(getenv func(string) string, name string) (value, set bool, err error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return false, false, nil
	}
	v, perr := strconv.ParseBool(raw)
	if perr != nil {
		return false, false, usageErrorf("%s=%q: want 1/true or 0/false", name, raw)
	}
	return v, true, nil
}

// redactRaw masks a raw HTTP message when redaction is on.
func redactRaw(on bool, raw string) string {
	if !on || raw == "" {
		return raw
	}
	markRedacted()
	return redact.HTTPMessage(raw, nil)
}

// redactValue masks one credential value with mask when redaction is on, and
// marks the document redacted (markRedacted) when there was a value to mask.
// A view with its own masking form (browsercookie.Redact keeps a cookie's
// shape) goes through here, so it marks the envelope the same way the raw
// message, URL and header views do.
func redactValue(on bool, v string, mask func(string) string) string {
	if !on || v == "" {
		return v
	}
	markRedacted()
	return mask(v)
}

// redactURL masks sensitive query parameters of a URL when redaction is on.
func redactURL(on bool, u string) string {
	if !on || u == "" {
		return u
	}
	markRedacted()
	return redact.URL(u)
}

// redactReplayOutputs returns copies of outs with the exchange's request,
// URLs and response headers masked; outs are not modified (the stream written
// beside the document keeps the raw bytes).
func redactReplayOutputs(outs []*replayOutput) []*replayOutput {
	if len(outs) > 0 {
		markRedacted()
	}
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
	if len(entries) > 0 {
		markRedacted()
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
	if !on || line == "" {
		return line
	}
	markRedacted()
	return redact.StartLine(line)
}

// redactFuzzDryRun masks the baseline request and the rendered examples of a
// fuzz dry run when redaction is on.
func redactFuzzDryRun(r fuzzDryRunReport) fuzzDryRunReport {
	if !jsonRedactOn {
		return r
	}
	markRedacted()
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
