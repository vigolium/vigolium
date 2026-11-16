package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `traffic --curl` and `finding --curl` render stored requests as curl
// commands (httpmsg.ToCurl): the handoff a person or an agent uses to re-send
// one exchange by hand. Rendering never sends anything.

// curlRenderLimit is how many commands --curl prints without -a/--all: a
// screenful of commands is a handoff, a thousand is an export.
const curlRenderLimit = 20

// curlItem is one rendered command in a -j document.
type curlItem struct {
	// UUID is the traffic record (traffic --curl).
	UUID string `json:"uuid,omitempty"`
	// ID / FindingHash / RecordUUID identify the finding and the record whose
	// request was rendered (finding --curl); RecordUUID is empty when the
	// finding's own stored evidence was used.
	ID          int64  `json:"id,omitempty"`
	FindingHash string `json:"finding_hash,omitempty"`
	RecordUUID  string `json:"record_uuid,omitempty"`

	Method string   `json:"method"`
	URL    string   `json:"url"`
	Curl   string   `json:"curl"`
	Argv   []string `json:"argv"`
	// StdinBase64 is set for a non-text body: argv reads it from stdin.
	StdinBase64 string `json:"stdin_base64,omitempty"`
	Redacted    bool   `json:"redacted,omitempty"`

	credentials bool
}

// recordCurl renders one stored record. The URL's scheme/host/port come from
// the record's own columns, never from its Host header.
func recordCurl(rec *database.HTTPRecord, redactAuth bool) (curlItem, error) {
	cmd, err := httpmsg.ToCurl(rec.RawRequest,
		database.EndpointOrigin(rec.Scheme, rec.Hostname, rec.Port),
		httpmsg.CurlOptions{RedactAuth: redactAuth, HTTP2: isHTTP2Version(rec.HTTPVersion)})
	if err != nil {
		return curlItem{}, err
	}
	return curlItemFrom(cmd, rec.Method, rec.URL), nil
}

func curlItemFrom(cmd httpmsg.CurlCommand, method, url string) curlItem {
	return curlItem{
		Method:      method,
		URL:         url,
		Curl:        cmd.Command,
		Argv:        cmd.Argv,
		StdinBase64: cmd.StdinBase64,
		Redacted:    cmd.Redacted,
		credentials: cmd.Credentials && !cmd.Redacted,
	}
}

// curlItemsRedacted reports whether any rendered command had a credential
// masked (--redact-auth, or -j redaction), for the envelope's `redacted`.
func curlItemsRedacted(items []curlItem) bool {
	for _, it := range items {
		if it.Redacted {
			return true
		}
	}
	return false
}

func isHTTP2Version(v string) bool {
	v = strings.ToUpper(strings.TrimSpace(v))
	return v == "HTTP/2" || v == "HTTP/2.0" || v == "H2"
}

// printCurlItems writes the human form: a comment naming the source, then the
// command, one block per item.
func printCurlItems(items []curlItem, label func(curlItem) string) {
	for i, it := range items {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("# %s %s %s\n", label(it), it.Method, it.URL)
		fmt.Println(it.Curl)
	}
}

// noteCurlCredentials tells a non-interactive caller that the commands it is
// capturing carry live credentials. A terminal user sees them on screen.
func noteCurlCredentials(items []curlItem) {
	if terminal.IsTerminal() {
		return
	}
	n := 0
	for _, it := range items {
		if it.credentials {
			n++
		}
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "%s %d curl command(s) carry credential headers (Authorization/Cookie/API key); pass --redact-auth to mask them\n",
			terminal.WarningSymbol(), n)
	}
}

// checkCurlCount refuses to render more than curlRenderLimit commands unless
// -a/--all asked for every one.
func checkCurlCount(n int, all bool, noun string) error {
	if n > curlRenderLimit && !all {
		return usageErrorf("--curl selected %d %s; it renders at most %d without -a/--all.\n\n"+
			"Narrow the selection (--uuid, --url, --host, -n %d) or pass -a to render all of them",
			n, noun, curlRenderLimit, curlRenderLimit)
	}
	return nil
}
