package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/spf13/cobra"
)

// -o/--output for the -j read commands.
//
// `traffic -j` and `finding -j` could only ever write to stdout, so a result
// large enough to matter had to travel through whatever was driving the CLI —
// a shell capture, a tool transcript, an agent's context — even when the caller
// only wanted it on disk to grep later. `db export` and `export` have had -o for
// exactly this reason; the browse commands did not, and the gap was the whole
// difference between "save this" and "print this and hope".
//
// Scoped to --json on purpose. A table rendered to a file is `export`'s job and
// already has formats, filters and a summary; adding a second, quieter spelling
// of it here would be a parallel export path to keep in sync.

// jsonOutputPath backs -o/--output on the read commands that emit an envelope.
var jsonOutputPath string

// registerJSONOutputFlag adds -o/--output to a command whose -j output is a
// single result document.
//
// Callers must not already own -o: `db export` and `export` do, with their own
// (documented, different) meaning, and silently reinterpreting those would break
// every script that uses them.
func registerJSONOutputFlag(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&jsonOutputPath, "output", "o", "",
		"With --json: write the result document to this file and print a receipt instead; '-' forces stdout")
}

// validateJSONOutputFlag rejects the combinations that cannot mean anything,
// before a query runs.
func validateJSONOutputFlag(cmd *cobra.Command) error {
	dest := strings.TrimSpace(jsonOutputPath)
	if dest == "" {
		return nil
	}
	if !globalJSON {
		return usageErrorf(
			"-o/--output on %s writes the --json result document, so it needs --json/-j.\n\n"+
				"For a rendered report or a bulk dump, use: vigolium export -o <path> --format <fmt>",
			commandPathWithoutRoot(cmd))
	}
	// --watch turns -j into a stream of documents, one per tick. There is no
	// single "the result" to save, and appending them would produce a file that
	// is neither one JSON document nor a stable NDJSON log.
	if strings.TrimSpace(globalWatchRaw) != "" && dest != "-" {
		return usageErrorf("-o/--output cannot be combined with --watch: a repeated read has no single result document to write")
	}
	return nil
}

// jsonOutputDestination returns the file the result document should go to, or ""
// for stdout.
func jsonOutputDestination() string {
	dest := strings.TrimSpace(jsonOutputPath)
	if dest == "-" {
		return ""
	}
	return dest
}

// writeJSONResultToFile saves an already-encoded result document and prints the
// receipt that replaces it on stdout.
//
// The receipt never contains the document. Echoing it back would reinstate the
// transcript cost the flag exists to remove, and a caller that wanted both can
// ask twice.
func writeJSONResultToFile(dest string, doc []byte, src any) error {
	return writeJSONResultToFileNow(dest, doc, src, nil)
}

// writeJSONResultToFileNow writes the file and its receipt to stdout directly,
// bypassing the held-result path: Execute calls it when publishing a held -o
// result. src is the document's value (its command, kind and total are
// repeated); outcomeErr is the error the document carries (nil when ok), which
// the receipt repeats, so the receipt alone answers whether the command worked.
func writeJSONResultToFileNow(dest string, doc []byte, src any, outcomeErr *agentError) error {
	if err := writeRequestedFile(dest, doc); err != nil {
		return err
	}
	receipt := jsonResultReceipt(src, dest, doc, outcomeErr)
	out, err := encodeAgentJSON(receipt)
	if err != nil {
		return err
	}
	return writeAgentJSONDoc(out)
}

// jsonResultReceipt is the -o receipt: an envelope with the source document's
// spine (command, kind, ok, total) and no rows, plus where the document went.
func jsonResultReceipt(src any, dest string, doc []byte, outcomeErr *agentError) *agentEnvelope {
	paged := resultIsPaged(src)
	sum := sha256.Sum256(doc)
	r := newAgentEnvelope("", "", nil, 0, 0, 0)
	if env, ok := src.(*agentEnvelope); ok && env != nil {
		r.Command, r.Kind, r.Total = env.Command, env.Kind, env.Total
		r.Changed, r.Action, r.DryRun = env.Changed, env.Action, env.DryRun
		r.ProjectUUID, r.DBPath = env.ProjectUUID, env.DBPath
		for _, k := range []string{"project_source", "project_scoped", "sends_traffic"} {
			if v, ok := env.extra[k]; ok {
				r.extra[k] = v
			}
		}
	}
	r.OK = outcomeErr == nil
	r.Error = outcomeErr
	if outcomeErr != nil {
		r.SoftFail = globalSoftFail
	}
	r.With("artifact", "json_result").
		With("output", dest).
		With("bytes", len(doc)).
		With("sha256", hex.EncodeToString(sum[:])).
		// A saved page is still a page. Saying so keeps a file named like a
		// full export from being read as one when -n/--limit was still in force.
		With("complete", !paged).
		With("artifacts", []scanArtifact{{Format: "json", Path: dest, Bytes: int64(len(doc))}})
	if paged {
		r.With("hint", "this file holds one page; pass -a/--all or raise -n/--limit for the whole result set")
	}
	return r
}

// resultIsPaged reports whether an envelope carries fewer rows than it matched,
// so the receipt can describe the file as a window rather than the whole result.
//
// Anything that is not a row-list envelope (db stats emits an object) is
// complete by definition: there is no page to be a fraction of.
func resultIsPaged(v any) bool {
	env, items, ok := envelopeItemSlice(v)
	if !ok {
		return false
	}
	return env.Total > int64(items.Len())
}
