package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium match-not-found` answers "is this response its origin's not-found
// page?" for responses vigolium did not record — a caller's own fetches —
// against the baseline `vigolium fingerprint` stored for the origin. The
// decision is notFoundMatcher.classify, the same one `traffic --fields
// matches_not_found` and `--exclude-not-found` make for stored records.

// matchNotFoundMaxBody caps one item's decoded body. It is the transport's own
// read cap (pkg/http MaxBodyRead), so a body over it is cut to exactly what a
// recorded response would hold, and the comparison is the one a stored record
// would get.
const matchNotFoundMaxBody = int(vighttp.MaxBodyRead)

// matchNotFoundMaxFailures bounds the failures listed in the document; the
// count stays exact.
const matchNotFoundMaxFailures = 20

// matchNotFoundMaxLine caps one stdin line: a whole base64 body plus headroom
// for its encoding and the rest of the object. Named once because the scanner's
// bound and the over-length error that quotes it are a published pair.
var matchNotFoundMaxLine = base64.StdEncoding.EncodedLen(matchNotFoundMaxBody) + (1 << 20)

var matchNotFoundCmd = &cobra.Command{
	Use:   "match-not-found",
	Short: "Classify responses read from stdin against their origin's stored not-found baseline",
	Long: `Read JSON lines on stdin, one response per line, and say whether each is its origin's
not-found page — the same decision 'traffic --fields matches_not_found' makes for
stored records, applied to responses vigolium did not record:

  {"id": "r1", "url": "https://app.example/x", "status": 200,
   "headers": {"Content-Type": "text/html", "Set-Cookie": ["a=1", "b=2"]},
   "body_b64": "PGh0bWw+..."}

A 404 or 410 is not-found (reason status-404 / status-410). Any other status is
compared with every stable attribute of the baseline signature 'vigolium
fingerprint' stored for the URL's origin (host:port; reason signature). With no
stored baseline, or no body to compare, the answer is unknown: known false,
reason no-baseline or no-body. Omit body_b64 (or send null) when you do not have
the body; "" is an empty body. A decoded body over 30 MiB is cut to 30 MiB, as
the transport cuts a recorded response. A line that does not parse is listed in
failures and the rest are still answered.

Reads the project's database (--db, -S); never sends a request.`,
	Example: "  my-fetcher | vigolium match-not-found -j\n" +
		"  vigolium match-not-found -j < responses.jsonl\n" +
		"  vigolium match-not-found -S --db run.sqlite -j < responses.jsonl\n" +
		"  vigolium match-not-found --format tsv --fields id,matches,reason < responses.jsonl",
	Args: cobra.NoArgs,
	RunE: runMatchNotFound,
}

func init() {
	rootCmd.AddCommand(matchNotFoundCmd)
	f := matchNotFoundCmd.Flags()
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB")
	registerRowShapingFlags(f)
	registerTSVFlags(f)
}

// matchNotFoundShaping is match-not-found's --fields vocabulary; its rows have
// nothing bulky for --compact to drop.
var matchNotFoundShaping = rowShaping{path: "match-not-found", defaultTSV: []string{"id", "matches", "known", "reason", "url"}}

// matchNotFoundInput is one stdin line.
type matchNotFoundInput struct {
	ID      string               `json:"id"`
	URL     string               `json:"url"`
	Status  int                  `json:"status"`
	Headers matchNotFoundHeaders `json:"headers"`
	BodyB64 *string              `json:"body_b64"`
}

// matchNotFoundHeaders accepts each header as a string or a list of strings.
type matchNotFoundHeaders http.Header

func (h *matchNotFoundHeaders) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := http.Header{}
	for name, v := range raw {
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			out.Add(name, one)
			continue
		}
		var many []string
		if err := json.Unmarshal(v, &many); err != nil {
			return fmt.Errorf("header %q: want a string or a list of strings", name)
		}
		for _, m := range many {
			out.Add(name, m)
		}
	}
	*h = matchNotFoundHeaders(out)
	return nil
}

// matchNotFoundItem is one `match-not-found -j` row.
type matchNotFoundItem struct {
	ID  string `json:"id"`
	URL string `json:"url"`
	// Matches reports that the response is the origin's not-found page.
	Matches bool `json:"matches"`
	// Known is false when there is no answer (no baseline, or no body);
	// Matches is then false and means nothing.
	Known bool `json:"known"`
	// Reason is status-404, status-410, signature, no-baseline or no-body.
	Reason string `json:"reason" jsonschema:"enum=status-404,enum=status-410,enum=signature,enum=no-baseline,enum=no-body"`
}

// matchNotFoundFailure is one stdin line that could not be answered.
type matchNotFoundFailure struct {
	Line  int    `json:"line"`
	ID    string `json:"id,omitempty"`
	Error string `json:"error"`
}

// matchNotFoundExtras are `match-not-found -j`'s top-level keys.
type matchNotFoundExtras struct {
	// Failed counts the lines that did not parse; Failures lists the first 20.
	Failed   int                    `json:"failed,omitempty"`
	Failures []matchNotFoundFailure `json:"failures,omitempty"`
}

// matchNotFoundRequest turns one parsed line into the response classify reads.
func matchNotFoundRequest(in matchNotFoundInput) (notFoundResponse, error) {
	if strings.TrimSpace(in.URL) == "" {
		//vigolium:not-usage a stdin line's content, reported in failures[]; the command continues
		return notFoundResponse{}, errors.New("url is required")
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return notFoundResponse{}, fmt.Errorf("url %q: want an absolute http(s) URL", in.URL)
	}
	if in.Status < 100 || in.Status > 999 {
		return notFoundResponse{}, fmt.Errorf("status %d: want an HTTP status code", in.Status)
	}
	r := notFoundResponse{
		hostname: strings.ToLower(u.Hostname()), port: portFromURL(u), url: u, status: in.Status,
		headers: http.Header(in.Headers),
	}
	if in.BodyB64 != nil {
		body, err := base64.StdEncoding.DecodeString(*in.BodyB64)
		if err != nil {
			return notFoundResponse{}, fmt.Errorf("body_b64: %w", err)
		}
		if len(body) > matchNotFoundMaxBody {
			body = body[:matchNotFoundMaxBody]
		}
		r.body, r.hasResponse = body, true
	}
	return r, nil
}

func runMatchNotFound(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()
	format, err := matchNotFoundShaping.prepare(cmd)
	if err != nil {
		return err
	}
	if stdinIsTerminal() {
		return usageErrorf("match-not-found reads JSON lines on stdin; pipe them in (see --help)")
	}
	data, err := readStdin()
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	matcher := newNotFoundMatcher(context.Background(), db, projectUUID)

	items := []matchNotFoundItem{}
	var extras matchNotFoundExtras
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), matchNotFoundMaxLine)
	for line := 1; sc.Scan(); line++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var in matchNotFoundInput
		if err := json.Unmarshal(raw, &in); err != nil {
			extras.fail(line, "", err)
			continue
		}
		req, err := matchNotFoundRequest(in)
		if err != nil {
			extras.fail(line, in.ID, err)
			continue
		}
		v := matcher.classify(req)
		items = append(items, matchNotFoundItem{ID: in.ID, URL: in.URL, Matches: v.matches, Known: v.known, Reason: v.reason})
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("reading stdin: a line is over %d bytes (the body cap is %d decoded bytes)",
				matchNotFoundMaxLine, matchNotFoundMaxBody)
		}
		return fmt.Errorf("reading stdin: %w", err)
	}

	switch {
	case globalJSON:
		shaped, err := matchNotFoundShaping.apply(items)
		if err != nil {
			return err
		}
		opts := []envOpt{withProjectScope(projectUUID), withDBPath(resolvedReadDBPath())}
		if extras.Failed > 0 {
			opts = append(opts, withExtra("failed", extras.Failed), withExtra("failures", extras.Failures))
		}
		return emitRead(cmd, "", shaped, int64(len(items)), 0, 0, opts...)
	case format == "tsv":
		for _, f := range extras.Failures {
			fmt.Fprintf(os.Stderr, "%s line %d: %s\n", terminal.WarnPrefix(), f.Line, f.Error)
		}
		return matchNotFoundShaping.emitTSV(items)
	}
	for _, it := range items {
		verdict := terminal.Gray("unknown")
		switch {
		case it.Known && it.Matches:
			verdict = terminal.Orange("not-found")
		case it.Known:
			verdict = terminal.Green("page")
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", it.ID, verdict, it.Reason, it.URL)
	}
	for _, f := range extras.Failures {
		fmt.Printf("line %d\t%s\t%s\n", f.Line, terminal.Red("failed"), f.Error)
	}
	return nil
}

// fail records one line that could not be answered.
func (e *matchNotFoundExtras) fail(line int, id string, err error) {
	e.Failed++
	if len(e.Failures) < matchNotFoundMaxFailures {
		e.Failures = append(e.Failures, matchNotFoundFailure{Line: line, ID: id, Error: err.Error()})
	}
}
