package cli

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// `traffic request` reads ONE stored request whole: method, URL, ordered
// headers and body, in one document. A caller that re-derives what the real
// client sent - a declared request transform reproducing a recorded signature
// byte for byte - needs all four together; `traffic headers --request` plus
// `traffic body --request` is two reads and leaves the method in a start line.
//
// The -j view masks credential values only under the same rule every view
// follows (json_redact.go); a deterministic reader passes --no-redact.

var trafficRequestCmd = &cobra.Command{
	Use:   "request [uuid]",
	Short: "Read one stored request whole: method, URL, headers and body",
	Long: "Print a single stored HTTP request.\n\n" +
		"Without -j the raw request is written as stored. With -j the one item is " +
		"{uuid, method, url, target, headers: [{name, value}], body, body_encoding, complete}: headers keep their order and " +
		"duplicates, the body is decoded from gzip like `traffic body`, and body_encoding is base64 when the body is not UTF-8. " +
		"The record is named by positional UUID or --uuid (a unique prefix of at least 8 characters works).",
	Args: cobra.MaximumNArgs(1),
	RunE: runTrafficRequest,
	Example: `  # The whole request as JSON, credentials unmasked for a deterministic reader
  vigolium traffic request <record-id> -j --no-redact
  # The raw request
  vigolium traffic request --uuid <record-id>`,
}

func init() {
	trafficCmd.AddCommand(trafficRequestCmd)
	f := trafficRequestCmd.Flags()
	f.StringVar(&extractUUID, "uuid", "", "UUID (or unique prefix, 8+ chars) of the stored record to read; the positional argument is the same")
	f.BoolVarP(&globalStateless, "stateless", "S", false,
		"Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB")
}

// storedRequest is the -j item `traffic request` answers.
type storedRequest struct {
	UUID   string `json:"uuid"`
	Method string `json:"method"`
	URL    string `json:"url"`
	// Target is the request-target exactly as the stored request line
	// carries it - the bytes a client's signature covers, which URL may hold
	// normalised.
	Target       string        `json:"target"`
	Headers      []headerEntry `json:"headers"`
	Body         string        `json:"body"`
	BodyEncoding string        `json:"body_encoding"`
	Complete     bool          `json:"complete"`
}

// requestView builds the item from one stored request's header block and body.
func requestView(uuid, url, headers string, body []byte, redact bool) storedRequest {
	line := headerStartLine(headers)
	if redact {
		line = redactStartLine(redact, line)
	}
	method, target := requestLineParts(line)
	dec := gunzipBounded(body, false)
	out := storedRequest{
		UUID:     uuid,
		Method:   strings.ToUpper(method),
		URL:      redactURL(redact, url),
		Target:   target,
		Headers:  redactHeaderEntries(redact, parseHeaderEntries(headers)),
		Complete: !dec.Capped,
	}
	if out.Headers == nil {
		out.Headers = []headerEntry{}
	}
	if utf8.Valid(dec.Bytes) {
		out.Body, out.BodyEncoding = string(dec.Bytes), "utf8"
	} else {
		out.Body, out.BodyEncoding = base64.StdEncoding.EncodeToString(dec.Bytes), "base64"
	}
	return out
}

// requestLineParts splits "METHOD target HTTP/x" into the method and the
// request-target, keeping the target's bytes as written.
func requestLineParts(line string) (string, string) {
	method, rest, _ := strings.Cut(line, " ")
	if i := strings.LastIndex(rest, " HTTP/"); i >= 0 {
		rest = rest[:i]
	}
	return method, rest
}

func runTrafficRequest(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	if err := takePositionalUUID(args); err != nil {
		return err
	}
	extractRequestSide = true
	msg, err := loadExtractTarget(context.Background())
	if err != nil {
		return err
	}
	if globalJSON {
		item := requestView(msg.Record.UUID, msg.Record.URL, msg.Headers, msg.Body, jsonRedactOn)
		env := newMachineEnvelope(cmd, "", []any{item}, 1, 0, 1)
		env.objectResult = true
		env.DBPath = resolvedReadDBPath()
		env.WithProjectScope(msg.ProjectScope)
		return writeAgentJSON(env.WithQuery("traffic", "request", msg.Record.UUID, "--json"))
	}
	_, err = os.Stdout.Write(msg.Record.RawRequest)
	return err
}
