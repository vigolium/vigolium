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
func writeJSONResultToFile(dest string, doc []byte, paged bool) error {
	return writeJSONResultToFileNow(dest, doc, paged, nil)
}

// writeJSONResultToFileNow writes the file and its receipt to stdout directly,
// bypassing the held-result path: Execute calls it when publishing a held -o
// result. outcomeErr is the error the document carries (nil when ok); the
// receipt repeats it, so the receipt alone answers whether the command worked.
func writeJSONResultToFileNow(dest string, doc []byte, paged bool, outcomeErr *agentError) error {
	if err := writeRequestedFile(dest, doc); err != nil {
		return err
	}
	sum := sha256.Sum256(doc)
	receipt := map[string]any{
		"ok":             outcomeErr == nil,
		"artifact":       "json_result",
		"output":         dest,
		"bytes":          len(doc),
		"sha256":         hex.EncodeToString(sum[:]),
		"schema_version": AgentSchemaVersion,
		// A saved page is still a page. Saying so keeps a file named like a full
		// export from being read as one when -n/--limit was still in force.
		"complete": !paged,
	}
	if paged {
		receipt["hint"] = "this file holds one page; pass -a/--all or raise -n/--limit for the whole result set"
	}
	if outcomeErr != nil {
		receipt["error"] = outcomeErr
		if globalSoftFail {
			receipt["soft_fail"] = true
		}
	}
	doc, err := encodeAgentJSON(receipt)
	if err != nil {
		return err
	}
	return writeAgentJSONDoc(doc)
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
