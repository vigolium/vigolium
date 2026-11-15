package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// streamOutputPlan says where the results of a command with a per-item stream
// (replay, fuzz) go. It is decided once, from the flags alone, before anything
// is sent — a contradictory command line is a usage error, not a surprise after
// the traffic went out.
//
// The polarity used to be reversed: bare `replay` printed raw JSON (ignoring
// -j, which it never read), bare `fuzz` printed its JSONL stream, and a local
// --pretty asked for the human view. Now:
//
//   - default: the human view on stdout;
//   - -j: one envelope on stdout;
//   - --format jsonl: the per-item stream on stdout;
//   - -o <path>: the per-item stream goes to that file, and stdout keeps
//     whichever of the above it would otherwise carry.
//
// -j together with a stream on stdout is two protocols on one pipe, so it
// needs -o. Bulk replay keeps its JSONL default for one release, with a stderr
// notice (legacyBulkDefault).
type streamOutputPlan struct {
	human    bool // the human view on stdout
	envelope bool // one -j document on stdout
	stream   bool // the per-item JSONL stream
	// streamPath is the stream's file; "" is stdout.
	streamPath string
	// legacyBulkDefault: the JSONL stream is on stdout only because bulk replay
	// has not flipped its default yet.
	legacyBulkDefault bool
}

// streamOnStdout reports whether the per-item stream owns stdout.
func (p streamOutputPlan) streamOnStdout() bool { return p.stream && p.streamPath == "" }

// resolveStreamOutputPlan builds the plan. outPath is the command's -o.
// humanDefault is what a run with no output flags prints: true everywhere
// except the bulk form of `replay`, until its default flips. A typed
// --format console always selects the human view.
func resolveStreamOutputPlan(cmd *cobra.Command, outPath string, humanDefault bool) (streamOutputPlan, error) {
	format, err := requestedStreamFormat(cmd)
	if err != nil {
		return streamOutputPlan{}, err
	}
	jsonl := format == "jsonl"
	out := strings.TrimSpace(outPath)
	p := streamOutputPlan{
		envelope:   globalJSON,
		stream:     jsonl || out != "",
		streamPath: out,
	}
	if p.envelope && p.streamOnStdout() {
		return streamOutputPlan{}, usageErrorf("-j and --format jsonl would both write to stdout; send the stream to a file with -o <path>, or drop one of them")
	}
	if !humanDefault && !globalJSON && format == "" {
		p.stream = true
		p.legacyBulkDefault = out == ""
	}
	p.human = !p.envelope && !p.streamOnStdout()
	return p, nil
}

// resolveReplayOutputPlan is resolveStreamOutputPlan with replay's -o.
func resolveReplayOutputPlan(cmd *cobra.Command, humanDefault bool) (streamOutputPlan, error) {
	return resolveStreamOutputPlan(cmd, replayOutputPath, humanDefault)
}

var replayBulkDefaultOnce sync.Once

// noteLegacyBulkDefault tells the operator that the bulk JSONL default is on its
// way out, once per process.
func noteLegacyBulkDefault(p streamOutputPlan) {
	if !p.legacyBulkDefault {
		return
	}
	replayBulkDefaultOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "%s bulk replay streams JSONL to stdout by default for one more release; the default becomes the human summary next. "+
			"Pass --format jsonl to keep the stream, --format console for the tables, or -j for one JSON document\n", terminal.WarningSymbol())
	})
}

// openStreamEncoder opens the plan's stream: the -o file, or stdout. The close
// func is a no-op for stdout.
func openStreamEncoder(p streamOutputPlan) (*json.Encoder, func(), error) {
	if p.streamPath == "" {
		return json.NewEncoder(os.Stdout), func() {}, nil
	}
	f, err := os.Create(p.streamPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create --output %q: %w", p.streamPath, err)
	}
	return json.NewEncoder(f), func() { _ = f.Close() }, nil
}

// emitReplayResult writes a single-source result according to the plan.
func emitReplayResult(cmd *cobra.Command, p streamOutputPlan, out *replayOutput) error {
	if p.stream {
		enc, closeOut, err := openStreamEncoder(p)
		if err != nil {
			return err
		}
		err = enc.Encode(out)
		closeOut()
		if err != nil {
			return err
		}
	}
	if p.human {
		if err := emitReplayPretty(os.Stdout, out); err != nil {
			return err
		}
	}
	if p.envelope {
		rows, err := shapeReplayRows(cmd, []*replayOutput{out})
		if err != nil {
			return err
		}
		return emitObject(cmd, ".", rows[0])
	}
	return nil
}

// replayShaping is replay -j's --fields vocabulary (one replay row's keys).
// --compact is applied to the nested exchange by compactReplayOutput instead,
// since what makes a replay row large lives below its top level.
var replayShaping = rowShaping{path: "replay"}

// shapeReplayRows applies --compact and --fields to replay rows. Only `replay`
// itself registers those flags; the `traffic --replay` shim reaches the same
// emitters with traffic's own --fields, which describe traffic rows, so it is
// passed through untouched.
func shapeReplayRows(cmd *cobra.Command, outs []*replayOutput) ([]any, error) {
	if jsonRedactOn {
		outs = redactReplayOutputs(outs)
	}
	if commandPathWithoutRoot(cmd) != "replay" {
		rows := make([]any, len(outs))
		for i, o := range outs {
			rows[i] = o
		}
		return rows, nil
	}
	if jsonCompact {
		compacted := make([]*replayOutput, len(outs))
		for i, o := range outs {
			compacted[i] = compactReplayOutput(o)
		}
		outs = compacted
	}
	shaped, err := replayShaping.applyRows(outs)
	if err != nil {
		return nil, err
	}
	rows := make([]any, len(shaped))
	for i, r := range shaped {
		rows[i] = r
	}
	return rows, nil
}

// compactReplayOutput is a copy of o with the bulky parts of the exchange
// removed: response headers and excerpts, and the mutated request preview.
// Status, length, content hash, timing and the diff stay.
func compactReplayOutput(o *replayOutput) *replayOutput {
	if o == nil || o.Result == nil {
		return o
	}
	c := *o
	r := *o.Result
	r.MutatedRequest = ""
	r.MutatedRequestTrunc = false
	r.Baseline = compactReplaySummary(r.Baseline)
	r.Replay = compactReplaySummary(r.Replay)
	c.Result = &r
	return &c
}

func compactReplaySummary(s *replay.Summary) *replay.Summary {
	if s == nil {
		return nil
	}
	c := *s
	c.Headers = nil
	c.Excerpt = ""
	c.Truncated = false
	return &c
}

// emitReplayBulkEnvelope writes a bulk run's -j document: every replayed record
// as a row, with the per-record failures counted (each failed row carries its
// own `error`).
func emitReplayBulkEnvelope(cmd *cobra.Command, outs []*replayOutput) error {
	failed := 0
	for _, o := range outs {
		if o.Error != "" {
			failed++
		}
	}
	if outs == nil {
		outs = []*replayOutput{}
	}
	items, err := shapeReplayRows(cmd, outs)
	if err != nil {
		return err
	}
	return emitRead(cmd, "", items, int64(len(outs)), 0, len(outs), withExtra("failed", failed))
}
