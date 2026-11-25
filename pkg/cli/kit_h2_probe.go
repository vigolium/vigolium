package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/h2raw"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitH2ProbeTarget        string
	kitH2ProbeIgnoreScope   bool
	kitH2ProbeMethod        string
	kitH2ProbeData          string
	kitH2ProbeHeaders       []string
	kitH2ProbeContentLength int64
	kitH2ProbeOpenStream    bool
	kitH2ProbeChunkSize     int
	kitH2ProbeTimeout       time.Duration
	kitH2ProbeVerifyTLS     bool
	kitH2ProbeCleartext     bool
)

var kitH2ProbeCmd = &cobra.Command{
	Use:   "h2-probe [-t URL]",
	Short: "Send one hand-framed HTTP/2 request and time the answer",
	Long: `Send one HTTP/2 request whose frames are written by hand, for framing probes a
normal client refuses to send, and report how long the server took to answer
(response HEADERS, RST_STREAM or GOAWAY) or that it did not answer within
--timeout. A server that trusts a content-length the DATA never reaches waits
for the missing bytes: a timeout on that request beside a prompt answer to its
well-formed twin is the timing oracle of an HTTP/2 desync probe.

  vigolium kit h2-probe -t https://acme.test/ -X POST -d x --content-length 40 --open-stream -j
  vigolium kit h2-probe -t https://acme.test/ -X POST -d x --content-length 1 -j

One request per connection, over TLS negotiated to h2 by ALPN (--h2c for
cleartext prior knowledge); the connection is closed after the answer or the
timeout. --content-length is sent as written whatever the body's length;
--open-stream leaves the stream without END_STREAM; --chunk-size splits the
body across DATA frames. The body may not exceed 65535 bytes (the stream's
initial flow-control window). Exits 0 whether or not the server answered: a
timeout is the reading, reported as timed_out.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitH2Probe,
}

func init() {
	f := kitH2ProbeCmd.Flags()
	f.StringVarP(&kitH2ProbeTarget, "target", "t", "", "URL to probe (or pass it as the argument)")
	registerSendScopeFlags(f, &kitH2ProbeIgnoreScope, "Probe a host outside the configured host scope")
	f.StringVarP(&kitH2ProbeMethod, "method", "X", "GET", "HTTP method (:method)")
	f.StringVarP(&kitH2ProbeData, "data", "d", "", "Request body, sent as DATA frames")
	f.StringArrayVarP(&kitH2ProbeHeaders, "header", "H", nil, "Request header 'Name: value' (repeatable; names are lowercased)")
	f.Int64Var(&kitH2ProbeContentLength, "content-length", -1, "content-length header to declare, whatever the body's real length (-1 = none)")
	f.BoolVar(&kitH2ProbeOpenStream, "open-stream", false, "Leave the stream open: no END_STREAM on the last frame")
	f.IntVar(&kitH2ProbeChunkSize, "chunk-size", 0, "Split the body into DATA frames of at most N bytes (0 = one frame)")
	f.DurationVar(&kitH2ProbeTimeout, "timeout", 10*time.Second, "Wait this long for an answer after the last frame")
	f.BoolVar(&kitH2ProbeVerifyTLS, "verify-tls", false, "Verify the server certificate (off by default, as for scan traffic)")
	f.BoolVar(&kitH2ProbeCleartext, "h2c", false, "Speak cleartext HTTP/2 with prior knowledge instead of TLS")
	kitCmd.AddCommand(kitH2ProbeCmd)
	registerCommandSchema(contract.Command{Name: "kit h2-probe", Item: kitH2ProbeItem{},
		Description: "One hand-framed HTTP/2 request: what was sent (declared_content_length beside body_bytes, open_stream) and the answer — status, reset_code or goaway_code — or timed_out, with elapsed_ms from the last frame written."})
}

// kitH2ProbeItem is the -j row: what was sent and how the server answered.
type kitH2ProbeItem struct {
	URL                   string `json:"url"`
	Method                string `json:"method"`
	DeclaredContentLength *int64 `json:"declared_content_length,omitempty"`
	BodyBytes             int    `json:"body_bytes"`
	OpenStream            bool   `json:"open_stream"`
	ALPN                  string `json:"alpn"`
	Answered              bool   `json:"answered"`
	TimedOut              bool   `json:"timed_out"`
	ElapsedMS             int64  `json:"elapsed_ms"`
	Status                int    `json:"status,omitempty"`
	ResetCode             string `json:"reset_code,omitempty"`
	GoAwayCode            string `json:"goaway_code,omitempty"`
	ResponseBytes         int    `json:"response_bytes"`
}

func runKitH2Probe(cmd *cobra.Command, args []string) error {
	target := kitH2ProbeTarget
	if len(args) == 1 {
		if target != "" && target != args[0] {
			return clicommon.UsageErrorf("give the URL once: -t %s or the argument %s, not both", target, args[0])
		}
		target = args[0]
	}
	if target == "" {
		return clicommon.UsageErrorf("a target URL is required (-t URL)")
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return clicommon.UsageErrorf("target %q must be an http:// or https:// URL", target)
	}
	if u.Scheme == "http" && !kitH2ProbeCleartext {
		return clicommon.UsageErrorf("an http:// target speaks HTTP/2 only as cleartext prior knowledge: add --h2c")
	}
	headers, err := kitHeaderPairs(kitH2ProbeHeaders)
	if err != nil {
		return err
	}
	gate, err := newSendScopeGate(kitH2ProbeIgnoreScope)
	if err != nil {
		return err
	}
	if err := gate.check(target); err != nil {
		return err
	}

	addr := httpmsg.URLHostPort(u)
	path := u.RequestURI()
	req := h2raw.Request{
		Method: strings.ToUpper(kitH2ProbeMethod), Scheme: u.Scheme, Authority: u.Host, Path: path,
		Body: []byte(kitH2ProbeData), ChunkSize: kitH2ProbeChunkSize, OpenStream: kitH2ProbeOpenStream,
		Headers: headers,
	}
	if kitH2ProbeContentLength >= 0 {
		cl := kitH2ProbeContentLength
		req.ContentLength = &cl
	}
	opts := h2raw.Options{Timeout: kitH2ProbeTimeout, Cleartext: kitH2ProbeCleartext,
		TLSConfig: &tls.Config{InsecureSkipVerify: !kitH2ProbeVerifyTLS}} //nolint:gosec // scan traffic does not verify by default; --verify-tls opts in

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := h2raw.Send(ctx, addr, req, opts)
	switch {
	case errors.Is(err, h2raw.ErrNoH2):
		return clicommon.CLIError{Err: err, Code: apicontract.CodeFailed,
			Hint: "The server does not speak HTTP/2 over TLS; an HTTP/1.1 framing probe does not need this command"}
	case err != nil:
		return clicommon.CLIError{Err: fmt.Errorf("h2-probe: %w", err), Code: apicontract.CodeNoTargetsReachable,
			Hint: "Check that the target is up and reachable from here"}
	}
	item := kitH2ProbeItem{
		URL: target, Method: req.Method, DeclaredContentLength: req.ContentLength, BodyBytes: len(req.Body),
		OpenStream: req.OpenStream, ALPN: res.ALPN, Answered: res.Answered, TimedOut: res.TimedOut,
		ElapsedMS: res.Elapsed.Milliseconds(), Status: res.Status, ResetCode: res.ResetCode,
		GoAwayCode: res.GoAwayCode, ResponseBytes: len(res.Body),
	}
	if globalJSON {
		return emitRead(cmd, "probes", []kitH2ProbeItem{item}, 1, 0, 1)
	}
	outcome := fmt.Sprintf("HTTP %d", res.Status)
	switch {
	case res.TimedOut:
		outcome = "no answer (timed out)"
	case res.ResetCode != "":
		outcome = "RST_STREAM " + res.ResetCode
	case res.GoAwayCode != "":
		outcome = "GOAWAY " + res.GoAwayCode
	}
	fmt.Printf("%s %s\t%s\t%dms\n", req.Method, target, outcome, item.ElapsedMS)
	fmt.Fprintf(os.Stderr, "%s sent %d body byte(s), content-length %s, stream %s\n", terminal.InfoSymbol(), len(req.Body),
		declaredCL(req.ContentLength), map[bool]string{true: "left open", false: "ended"}[req.OpenStream])
	return nil
}

func declaredCL(cl *int64) string {
	if cl == nil {
		return "none"
	}
	return fmt.Sprint(*cl)
}
