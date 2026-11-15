package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/replay"
)

func TestResolveJSONRedaction(t *testing.T) {
	agent := func(k string) string {
		if k == "CLAUDECODE" {
			return "1"
		}
		return ""
	}
	ci := func(k string) string {
		if k == "CI" || k == "GITHUB_ACTIONS" {
			return "true"
		}
		return ""
	}
	none := func(string) string { return "" }
	cases := []struct {
		name          string
		json, on, off bool
		env           func(string) string
		want          bool
	}{
		{"coding agent, -j", true, false, false, agent, true},
		{"coding agent, human output", false, false, false, agent, false},
		{"coding agent, --no-redact", true, false, true, agent, false},
		{"CI is not a coding agent", true, false, false, ci, false},
		{"plain shell", true, false, false, none, false},
		{"--redact", true, true, false, none, true},
		{"--redact without -j", false, true, false, none, false},
	}
	for _, c := range cases {
		if got := resolveJSONRedaction(c.json, c.on, c.off, c.env); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}

	swapGlobal(t, &globalRedact, true)
	swapGlobal(t, &globalNoRedact, true)
	var ue usageError
	require.ErrorAs(t, applyRedactionMode(), &ue)
}

const redactTestRequest = "GET /account?token=s3cr3t&id=7 HTTP/1.1\r\nHost: app.example\r\n" +
	"Cookie: session=abc123; theme=dark\r\nAuthorization: Bearer eyJhbGci\r\nX-Api-Key: k-999\r\n\r\n"

const redactTestResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
	"Set-Cookie: session=abc123; Path=/; HttpOnly\r\n\r\n{\"user\":\"alice\"}"

func requireNoSecrets(t *testing.T, where, s string) {
	t.Helper()
	for _, secret := range []string{"s3cr3t", "abc123", "eyJhbGci", "k-999"} {
		require.NotContainsf(t, s, secret, "%s still carries %q", where, secret)
	}
}

func TestRecordAndFindingViewsRedact(t *testing.T) {
	rec := &database.HTTPRecord{
		UUID: "rec-1", Method: "GET", URL: "https://app.example/account?token=s3cr3t&id=7",
		RawRequest: []byte(redactTestRequest), RawResponse: []byte(redactTestResponse), HasResponse: true,
		ResponseContentType: "application/json",
	}
	raw := compactRecordView(rec, agentViewOptions{fields: []string{"url", "request", "response", "response_headers"}})
	require.Contains(t, mustJSON(t, raw), "abc123", "redaction is off unless asked for")

	view := compactRecordView(rec, agentViewOptions{redact: true, fields: []string{"url", "request", "response", "response_headers"}})
	doc := mustJSON(t, view)
	requireNoSecrets(t, "record view", doc)
	require.Contains(t, doc, "session=<redacted>", "cookie names survive")
	require.Contains(t, doc, `{\"user\":\"alice\"}`, "bodies are evidence and are kept")
	require.Contains(t, doc, "id=7", "only sensitive parameters are masked")

	f := &database.Finding{ID: 1, Severity: "high", ModuleID: "m", URL: rec.URL, Request: redactTestRequest, Response: redactTestResponse}
	fv := compactFindingView(f, nil, agentViewOptions{redact: true, fullBody: true})
	requireNoSecrets(t, "finding view", mustJSON(t, fv))
}

func TestReplayAndHeaderViewsRedact(t *testing.T) {
	sum := &replay.Summary{Status: 200, Headers: http.Header{"Set-Cookie": {"session=abc123; Path=/"}}, FinalURL: "https://app.example/x?token=s3cr3t"}
	out := &replayOutput{Target: "https://app.example", Result: &replay.Result{MutatedRequest: redactTestRequest, Replay: sum}}
	red := redactReplayOutputs([]*replayOutput{out})
	requireNoSecrets(t, "replay row", mustJSON(t, red[0]))
	require.Contains(t, out.Result.MutatedRequest, "abc123", "the stream beside the document keeps the raw bytes")
	require.Equal(t, "session=abc123; Path=/", out.Result.Replay.Headers.Get("Set-Cookie"))

	entries := parseHeaderEntries(strings.SplitN(redactTestRequest, "\r\n\r\n", 2)[0])
	requireNoSecrets(t, "traffic headers", mustJSON(t, redactHeaderEntries(true, entries)))
	require.Equal(t, "GET /account?token=%3Credacted%3E&id=7 HTTP/1.1", redactStartLine(true, "GET /account?token=s3cr3t&id=7 HTTP/1.1"))

	swapGlobal(t, &jsonRedactOn, true)
	dry := redactFuzzDryRun(fuzzDryRunReport{Target: "https://app.example", Request: redactTestRequest,
		Positions: []fuzzDryRunPos{{Type: "URL_PARAM", Name: "id", Example: redactTestRequest}}})
	requireNoSecrets(t, "fuzz dry run", mustJSON(t, dry))
}

// The envelope always says whether its views were redacted.
func TestEnvelopeSaysRedacted(t *testing.T) {
	swapGlobal(t, &globalJSON, true)
	for _, on := range []bool{false, true} {
		swapGlobal(t, &jsonRedactOn, on)
		doc := emitCaptured(t, func() error { return emitRead(skillsListCmd, "", []int{}, 0, 0, 0) })
		v, present := doc["redacted"]
		require.True(t, present, "redacted is always rendered")
		require.Equal(t, on, v)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	require.NoError(t, enc.Encode(v))
	return buf.String()
}
