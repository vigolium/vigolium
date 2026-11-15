package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `traffic body` and `traffic headers` extract ONE part of ONE stored exchange.
//
// Everything they do was previously reachable, and that was the problem: getting
// a single response body onto disk meant `db export --format fs`, which writes a
// whole tree (and whose -o names a directory PREFIX, so `-o ./out` produces
// ./out-traffic/…), then finding the file inside it. The listing's own
// decoder_hint said to do exactly that. Meanwhile reading just the response
// headers had no spelling at all: --fields response carries the body with them.
//
// So the gap is narrow and so are these: one record, one side, bytes out. The
// decoding, capping, hashing and completeness rules are NOT reimplemented here —
// they are the same gunzipBounded/splitHeadersBody the JSON views use, which is
// the point. A body extracted here and a body previewed by `traffic -j` are the
// same bytes by construction.

// Extraction flags. Separate vars from the listing's: these subcommands share
// trafficCmd's persistent filter flags but own their selection.
var (
	extractUUID            string
	extractRequestSide     bool
	extractOutput          string
	extractRepresentation  string
	extractAllowIncomplete bool // --allow-incomplete
	extractHeaderName      string
)

// Representations a body can be extracted in. `text` from the design sketch is
// deliberately absent: it would mean charset transcoding to UTF-8, which nothing
// in this codebase does today, and offering a name that silently behaves like
// `decoded` is worse than not offering it.
const (
	reprStored  = "stored"
	reprDecoded = "decoded"
)

var trafficBodyCmd = &cobra.Command{
	Use:   "body [uuid]",
	Short: "Extract one stored request or response body",
	Long: "Write the body of a single stored HTTP message to stdout or to a file.\n\n" +
		"Selects exactly one record — by positional UUID or --uuid, either one a full UUID or a unique prefix of at least 8 characters — " +
		"and one side (--response, the default, or --request). " +
		"Never re-sends the exchange — use `vigolium replay` for that; pass --read-only to open the source without modifying it.",
	Args: cobra.MaximumNArgs(1),
	RunE: runTrafficBody,
	Example: `  # Save a response body to a file (a uuid_short prefix works too)
  vigolium traffic body <record-id> -o response.json
  vigolium traffic body --uuid <record-id> -o response.json
  # The request side instead
  vigolium traffic body --uuid <record-id> --request -o request.txt
  # Pipe it
  vigolium traffic body --uuid <record-id> | jq .
  # Metadata receipt (size, sha256, completeness) without the bytes
  vigolium traffic body --uuid <record-id> --json
  # Exactly as stored, without removing content/transfer encodings
  vigolium traffic body --uuid <record-id> --representation stored -o body.gz`,
}

var trafficHeadersCmd = &cobra.Command{
	Use:   "headers [uuid]",
	Short: "Read one stored message's headers without its body",
	Long: "Print the header block of a single stored HTTP message.\n\n" +
		"Under --json the headers are an ordered array of {name, value} entries, so repeated headers " +
		"(Set-Cookie above all) survive — a map would silently keep only the last one. " +
		"The record is named by positional UUID or --uuid (a unique prefix of at least 8 characters works).",
	Args: cobra.MaximumNArgs(1),
	RunE: runTrafficHeaders,
	Example: `  # Response headers as an ordered array
  vigolium traffic headers <record-id> --json
  vigolium traffic headers --uuid <record-id> --json
  # Request headers
  vigolium traffic headers --uuid <record-id> --request --json
  # Every value of one header, case-insensitively
  vigolium traffic headers --uuid <record-id> --name set-cookie --json`,
}

func init() {
	trafficCmd.AddCommand(trafficBodyCmd, trafficHeadersCmd)

	for _, cmd := range []*cobra.Command{trafficBodyCmd, trafficHeadersCmd} {
		f := cmd.Flags()
		f.StringVar(&extractUUID, "uuid", "", "UUID (or unique prefix, 8+ chars) of the stored record to read; the positional argument is the same")
		f.BoolVar(&extractRequestSide, "request", false, "Read the request side")
		f.Bool("response", false, "Read the response side (default)")
		f.StringVarP(&extractOutput, "output", "o", "", "Write to this file instead of stdout; '-' forces stdout")
		f.BoolVarP(&globalStateless, "stateless", "S", false,
			"Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB")
		cmd.MarkFlagsMutuallyExclusive("request", "response")
	}

	bf := trafficBodyCmd.Flags()
	bf.StringVar(&extractRepresentation, "representation", reprDecoded,
		"Body representation: 'decoded' removes supported content encodings (gzip); 'stored' returns the bytes exactly as captured")
	bf.BoolVar(&extractAllowIncomplete, "allow-incomplete", false,
		"Write the body even when the capture is known to be incomplete (the receipt still reports complete: false)")

	trafficHeadersCmd.Flags().StringVar(&extractHeaderName, "name", "",
		"Return only entries with this header name (case-insensitive); every matching entry is returned, not just the first")
}

// extractSide names the half of an exchange a call selected.
type extractSide string

const (
	sideRequest  extractSide = "request"
	sideResponse extractSide = "response"
)

// selectedSide resolves the --request/--response pair. The two are mutually
// exclusive at the cobra level, so this only has to pick the default.
//
// Response is the default because it is what a caller reading stored evidence
// almost always wants, and because the alternative — requiring a side on every
// invocation — buys no safety: the side actually used is named in the receipt
// and in every error, so the choice is never silent.
func selectedSide() extractSide {
	if extractRequestSide {
		return sideRequest
	}
	return sideResponse
}

// extractedMessage is one side of a stored exchange, located and classified.
type extractedMessage struct {
	Record  *database.HTTPRecord
	Side    extractSide
	Headers string
	Body    []byte

	// ProjectScope is the project filter the lookup actually applied, empty when
	// none was. It is carried on the message rather than re-derived at envelope
	// time so the receipt reports the scope the record was found under, not a
	// second resolution that could differ.
	ProjectScope string
}

// takePositionalUUID folds `traffic body <uuid>` into --uuid. Both naming the
// same record is fine; naming two different ones is a usage error rather than
// a silent pick.
func takePositionalUUID(args []string) error {
	if len(args) == 0 {
		return nil
	}
	pos := strings.TrimSpace(args[0])
	if flag := strings.TrimSpace(extractUUID); flag != "" && flag != pos {
		return usageErrorf("the positional UUID %q and --uuid %q name different records; pass one", pos, flag)
	}
	extractUUID = pos
	return nil
}

// loadExtractTarget resolves --uuid to one record and isolates the selected
// side, distinguishing "no such record" from "that side was never captured".
// Collapsing those two into an empty result is what made a mistyped UUID look
// like a bodiless response.
//
// Selection by UUID is still project-scoped. GetRecordByUUID is a bare primary
// key read, so this command was the one way to pull a body out of a project the
// invocation had not selected — the project boundary every listing and query
// path enforces, bypassed by naming a row directly.
func loadExtractTarget(ctx context.Context) (*extractedMessage, error) {
	uuid := strings.TrimSpace(extractUUID)
	if uuid == "" {
		return nil, usageErrorf("name exactly one stored record to read: `traffic body <uuid>` or --uuid <uuid> (a unique 8+ character prefix works).\n\n" +
			"Find one with: vigolium traffic --compact --fields uuid_short,url -j")
	}

	// The body/header columns are the entire point of this command, so nothing is
	// skipped; findings and the file map are never consulted.
	db, err := openReadDB(globDBSkipSet{Findings: true, RecordFileMap: true})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Resolved within the project the read is scoped to: a prefix never matches
	// (or names, in an ambiguity) another project's record, and another
	// project's record reads the same as a missing one — "it belongs elsewhere"
	// would confirm it exists. GetRecordByUUID alone is a bare primary-key read.
	record, scope, err := loadRecordRef(ctx, database.NewRepository(db), uuid)
	if err != nil {
		return nil, err
	}
	uuid = record.UUID

	side := selectedSide()
	raw := record.RawRequest
	if side == sideResponse {
		if !record.HasResponse {
			return nil, codedErrorf(apicontract.CodeBodyUnavailable,
				"record %q has no response captured: the request was stored without one", uuid)
		}
		raw = record.RawResponse
	}
	if len(raw) == 0 {
		return nil, codedErrorf(apicontract.CodeBodyUnavailable, "record %q has no %s bytes stored", uuid, side)
	}

	headers, body := splitHeadersBody(raw)
	return &extractedMessage{
		Record:       record,
		Side:         side,
		Headers:      headers,
		Body:         body,
		ProjectScope: scope,
	}, nil
}

func runTrafficBody(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	switch extractRepresentation {
	case reprStored, reprDecoded:
	default:
		return usageErrorf("unknown --representation %q\n\nsupported: %s, %s",
			extractRepresentation, reprDecoded, reprStored)
	}

	if err := takePositionalUUID(args); err != nil {
		return err
	}
	msg, err := loadExtractTarget(context.Background())
	if err != nil {
		return err
	}

	out := msg.Body
	complete := true
	transformations := []string{}

	if extractRepresentation == reprDecoded {
		// measure=false: this caller reads only Bytes and Capped. Asking to
		// measure would drain up to agentMeasureCap of attacker-controlled data
		// through SHA-256 to produce a size and digest nobody reads — and it would
		// do it on the path that is about to return body_incomplete.
		dec := gunzipBounded(msg.Body, false)
		if looksGzip(msg.Body) {
			if bytes.Equal(dec.Bytes, msg.Body) {
				// gunzipBounded falls back to the stored bytes on any decode error,
				// which is right for a preview and wrong here: a caller who asked for
				// `decoded` and silently received compressed bytes would write a
				// broken artifact and never know.
				return codedErrorf(apicontract.CodeBodyDecodeFailed,
					"record %q: the %s body is gzip-encoded but could not be decoded.\n"+
						"Use --representation stored to extract the compressed bytes as captured",
					msg.Record.UUID, msg.Side)
			}
			transformations = append(transformations, "gunzip")
		}
		out = dec.Bytes
		// Capped means the decoder stopped at its ceiling, so these bytes are a
		// prefix of a body that is larger. Writing that to a file named like the
		// whole thing is how a partial artifact enters an evidence trail.
		if dec.Capped {
			complete = false
			if !extractAllowIncomplete {
				return codedErrorf(apicontract.CodeBodyIncomplete,
					"record %q: the decoded %s body exceeds the %d-byte decoder limit, so only a prefix is available.\n"+
						"Pass --allow-incomplete to write the prefix anyway, or --representation stored for the complete compressed bytes",
					msg.Record.UUID, msg.Side, agentGunzipCap)
			}
		}
	}

	return deliverBody(cmd, msg, out, complete, transformations)
}

// looksGzip reports the gzip magic number, matching gunzipBounded's own test so
// the two always agree on what "is compressed" means.
func looksGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// deliverBody writes the extracted bytes wherever the flags asked, and reports
// what it did.
//
// The three destinations are deliberately non-overlapping: bytes to stdout,
// bytes to a file with a receipt on stdout, or a receipt alone. What never
// happens is a second copy of the body inside the receipt — that would reinstate
// the transcript cost this command exists to remove.
func deliverBody(cmd *cobra.Command, msg *extractedMessage, out []byte, complete bool, transformations []string) error {
	// Built lazily: the default path writes bytes to stdout and reports nothing,
	// so hashing the whole body there would be a full extra pass over it — 20ms
	// on a 20 MB response — to fill a map that is immediately discarded.
	receipt := func(output string) map[string]any {
		sum := sha256.Sum256(out)
		m := map[string]any{
			"uuid":            msg.Record.UUID,
			"url":             msg.Record.URL,
			"side":            string(msg.Side),
			"representation":  extractRepresentation,
			"bytes":           len(out),
			"sha256":          hex.EncodeToString(sum[:]),
			"complete":        complete,
			"transformations": transformations,
			// An empty body is a real, common answer (204, HEAD, a bare redirect)
			// and is NOT the same as a body that was never captured — that one
			// failed earlier with body_unavailable. Stating it keeps the two apart
			// for a caller looking at a zero-byte file.
			"empty": len(out) == 0,
		}
		if output != "" {
			m["output"] = output
		}
		return m
	}

	dest := strings.TrimSpace(extractOutput)
	if dest == "" || dest == "-" {
		// Bytes are the product here, so a binary body still goes to stdout when
		// that is where it was pointed — but not when stdout is a terminal, where
		// it would corrupt the session for no benefit.
		if dest == "" && looksBinaryBytes(out) && terminal.IsTerminal() && !globalForce {
			return usageErrorf(
				"the %s body of %q looks binary and stdout is a terminal.\n\n"+
					"Write it to a file with -o <path>, pipe it, or pass --force to print it anyway",
				msg.Side, msg.Record.UUID)
		}
		if globalJSON {
			return writeReceiptFrame(newExtractEnvelope(cmd, msg, receipt("")))
		}
		_, err := os.Stdout.Write(out)
		return err
	}

	if err := writeRequestedFile(dest, out); err != nil {
		return err
	}

	if globalJSON {
		return writeReceiptFrame(newExtractEnvelope(cmd, msg, receipt(dest)))
	}
	// Human receipt on stderr: stdout stayed empty, so a caller who redirected it
	// expecting bytes gets an empty file rather than a surprise line of prose.
	fmt.Fprintf(os.Stderr, "%s Wrote %s %s body to %s (%s)\n",
		terminal.InfoSymbol(), terminal.Cyan(msg.Record.UUID), msg.Side,
		terminal.BoldCyan(dest), terminal.HumanBytes(int64(len(out))))
	if !complete {
		fmt.Fprintf(os.Stderr, "%s The capture is incomplete; this file holds a prefix, not the whole body\n",
			terminal.WarningSymbol())
	}
	return nil
}

// newExtractEnvelope wraps a receipt in the shared -j envelope so one parser
// reads these commands and the listings alike. total/offset/limit describe the
// one message that was addressed.
func newExtractEnvelope(cmd *cobra.Command, msg *extractedMessage, receipt map[string]any) *agentEnvelope {
	env := newMachineEnvelope(cmd, kindRead, "", receipt, 1, 0, 1)
	env.DBPath = resolvedReadDBPath()
	env.WithProjectScope(msg.ProjectScope)
	return env.WithQuery("traffic", "--uuid", msg.Record.UUID, "--json", "--full-body")
}

func runTrafficHeaders(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	if err := takePositionalUUID(args); err != nil {
		return err
	}
	msg, err := loadExtractTarget(context.Background())
	if err != nil {
		return err
	}

	entries := parseHeaderEntries(msg.Headers)
	if name := strings.TrimSpace(extractHeaderName); name != "" {
		entries = filterHeaderEntries(entries, name)
	}

	if globalJSON {
		receipt := map[string]any{
			"uuid":    msg.Record.UUID,
			"url":     redactURL(jsonRedactOn, msg.Record.URL),
			"side":    string(msg.Side),
			"headers": redactHeaderEntries(jsonRedactOn, entries),
			"count":   len(entries),
		}
		if line := headerStartLine(msg.Headers); line != "" {
			receipt["start_line"] = redactStartLine(jsonRedactOn, line)
		}
		if name := strings.TrimSpace(extractHeaderName); name != "" {
			receipt["name"] = name
			// "the header is absent" and "the message was unavailable" are
			// different answers; the second failed earlier, so this one is stated.
			receipt["present"] = len(entries) > 0
		}
		return writeAgentJSON(newExtractEnvelope(cmd, msg, receipt))
	}

	var sb strings.Builder
	if name := strings.TrimSpace(extractHeaderName); name != "" {
		for _, e := range entries {
			fmt.Fprintf(&sb, "%s: %s\n", e.Name, e.Value)
		}
	} else {
		sb.WriteString(msg.Headers)
		sb.WriteString("\n")
	}

	if dest := strings.TrimSpace(extractOutput); dest != "" && dest != "-" {
		if err := writeRequestedFile(dest, []byte(sb.String())); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s Wrote %s %s headers to %s\n",
			terminal.InfoSymbol(), terminal.Cyan(msg.Record.UUID), msg.Side, terminal.BoldCyan(dest))
		return nil
	}
	_, err = os.Stdout.WriteString(sb.String())
	return err
}

// headerEntry is one header, in the order it appeared.
//
// An ordered ARRAY, not a map. A map loses two things a security reader needs:
// the order (which distinguishes the header a proxy prepended from the one the
// origin sent) and the duplicates — a response with three Set-Cookie headers
// becomes one Set-Cookie in a map, and the two that vanish are as likely to be
// the interesting ones.
type headerEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// parseHeaderEntries splits a header block into ordered entries, skipping the
// request/status line. Values keep their original spelling and spacing after the
// single separating space; a continuation line (obs-fold) is appended to the
// entry it continues rather than dropped.
func parseHeaderEntries(block string) []headerEntry {
	lines := strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	entries := make([]headerEntry, 0, len(lines))
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // the request/status line carries no name: value
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Obs-fold: a continuation belongs to the entry above it. Dropping it
			// would silently truncate the value rather than omit it.
			if len(entries) > 0 {
				entries[len(entries)-1].Value += " " + strings.TrimSpace(line)
			}
			continue
		}
		// httpmsg owns what a header line IS, so this view and olium's record
		// inspector cannot disagree about where the name ends. A line with no
		// colon yields a blank name and is skipped.
		h := httpmsg.ParseHttpHeader(line)
		if h.Name == "" {
			continue
		}
		entries = append(entries, headerEntry{Name: h.Name, Value: h.Value})
	}
	return entries
}

// headerStartLine returns the request or status line, which is not a header but
// is the one piece of the block that is not one and still matters.
func headerStartLine(block string) string {
	line, _, _ := strings.Cut(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	return strings.TrimSpace(line)
}

// filterHeaderEntries returns EVERY entry whose name matches, case-insensitively
// — never just the first. Returning one Set-Cookie out of three is the same
// information loss a map would cause.
func filterHeaderEntries(entries []headerEntry, name string) []headerEntry {
	out := make([]headerEntry, 0, 2)
	for _, e := range entries {
		if strings.EqualFold(e.Name, name) {
			out = append(out, e)
		}
	}
	return out
}
