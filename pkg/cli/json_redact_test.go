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
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	agent := env("CLAUDECODE", "1")
	ci := env("CI", "true", "GITHUB_ACTIONS", "true")
	none := env()
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
		// VIGOLIUM_REDACT beats detection in both directions.
		{"VIGOLIUM_REDACT=0 under a coding agent", true, false, false, env("CLAUDECODE", "1", "VIGOLIUM_REDACT", "0"), false},
		{"VIGOLIUM_REDACT=false under a coding agent", true, false, false, env("CODEX_SANDBOX", "1", "VIGOLIUM_REDACT", "false"), false},
		{"VIGOLIUM_REDACT=1 in a plain shell", true, false, false, env("VIGOLIUM_REDACT", "1"), true},
		{"VIGOLIUM_REDACT blank falls through to detection", true, false, false, env("CLAUDECODE", "1", "VIGOLIUM_REDACT", " "), true},
		// The flags beat the variable.
		{"--no-redact beats VIGOLIUM_REDACT=1", true, false, true, env("VIGOLIUM_REDACT", "1"), false},
		{"--redact beats VIGOLIUM_REDACT=0", true, true, false, env("VIGOLIUM_REDACT", "0"), true},
		{"VIGOLIUM_REDACT=1 without -j", false, false, false, env("VIGOLIUM_REDACT", "1"), false},
		// VIGOLIUM_AGENT=0 marks nothing, so another marker still decides.
		{"VIGOLIUM_AGENT=0 is not an opt-out", true, false, false, env("VIGOLIUM_AGENT", "0", "CLAUDECODE", "1"), true},
	}
	for _, c := range cases {
		got, err := resolveJSONRedaction(c.json, c.on, c.off, c.env)
		require.NoError(t, err, c.name)
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}

	// A misspelt value is refused, not guessed: read as off it would print
	// the credentials the caller meant to keep out of the transcript.
	for _, bad := range []string{"yes-please", "2", "off"} {
		_, err := resolveJSONRedaction(true, false, false, env("VIGOLIUM_REDACT", bad))
		var ue usageError
		require.ErrorAs(t, err, &ue, bad)
		require.Contains(t, err.Error(), "VIGOLIUM_REDACT")
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

// `redacted` describes the document: true only when a view in it was produced
// masked, never merely because the mode is on.
func TestEnvelopeSaysRedacted(t *testing.T) {
	swapGlobal(t, &globalJSON, true)
	t.Cleanup(func() { viewsRedacted.Store(false) })
	for _, on := range []bool{false, true} {
		swapGlobal(t, &jsonRedactOn, on)
		viewsRedacted.Store(false)
		doc := emitCaptured(t, func() error { return emitRead(skillsListCmd, "", []int{}, 0, 0, 0) })
		v, present := doc["redacted"]
		require.True(t, present, "redacted is always rendered")
		require.Equal(t, false, v, "a document with no raw view masked nothing (mode on=%v)", on)
	}

	// A record view built under the mode is masked, and the envelope says so.
	swapGlobal(t, &jsonRedactOn, true)
	viewsRedacted.Store(false)
	rec := &database.HTTPRecord{UUID: "rec-1", Method: "GET", URL: "https://app.example/account?token=s3cr3t",
		RawRequest: []byte(redactTestRequest), RawResponse: []byte(redactTestResponse), HasResponse: true}
	doc := emitCaptured(t, func() error {
		view := compactRecordView(rec, agentViewOptions{redact: jsonRedactOn, fields: []string{"url", "request"}})
		return emitRead(skillsListCmd, "", []any{view}, 1, 0, 1)
	})
	require.Equal(t, true, doc["redacted"])
	requireNoSecrets(t, "document", mustJSON(t, doc))

	// The same view with the mode off is raw and says so.
	swapGlobal(t, &jsonRedactOn, false)
	viewsRedacted.Store(false)
	doc = emitCaptured(t, func() error {
		view := compactRecordView(rec, agentViewOptions{redact: jsonRedactOn, fields: []string{"url", "request"}})
		return emitRead(skillsListCmd, "", []any{view}, 1, 0, 1)
	})
	require.Equal(t, false, doc["redacted"])
	require.Contains(t, mustJSON(t, doc), "abc123")

	// A command's own masking (withRedacted) is reported the same way.
	viewsRedacted.Store(false)
	doc = emitCaptured(t, func() error { return emitRead(skillsListCmd, "", []int{1}, 1, 0, 1, withRedacted(true)) })
	require.Equal(t, true, doc["redacted"])
}

// applyRedactionMode starts every invocation with nothing marked, so a
// previous document's masking never leaks into the next one's `redacted`.
func TestApplyRedactionModeResetsTheMark(t *testing.T) {
	markRedacted()
	t.Cleanup(func() { viewsRedacted.Store(false) })
	require.NoError(t, applyRedactionMode())
	require.False(t, viewsRedacted.Load())
}

// redactRequested is the mode as if -j were on; jsonRedactOn is it under -j.
func TestApplyRedactionModeResolvesOnce(t *testing.T) {
	swapGlobal(t, &redactRequested, false)
	swapGlobal(t, &jsonRedactOn, false)
	t.Setenv("VIGOLIUM_REDACT", "1")
	swapGlobal(t, &globalJSON, false)
	require.NoError(t, applyRedactionMode())
	require.True(t, redactRequested)
	require.False(t, jsonRedactOn, "without -j no envelope is masked")

	swapGlobal(t, &globalJSON, true)
	require.NoError(t, applyRedactionMode())
	require.True(t, jsonRedactOn)
}

// VIGOLIUM_REDACT and VIGOLIUM_REQUIRE_SCOPE share one strict parse: blank is
// unset, ParseBool's forms are values, anything else is a usage error (exit 2).
func TestStrictEnvBool(t *testing.T) {
	for _, name := range []string{redactEnvVar, requireScopeEnvVar} {
		get := func(v string) func(string) string {
			return func(k string) string {
				if k == name {
					return v
				}
				return ""
			}
		}
		for raw, want := range map[string][2]bool{"": {false, false}, " ": {false, false}, "1": {true, true}, "TRUE": {true, true}, "0": {false, true}, "false": {false, true}} {
			v, set, err := strictEnvBool(get(raw), name)
			require.NoError(t, err, "%s=%q", name, raw)
			require.Equal(t, want, [2]bool{v, set}, "%s=%q", name, raw)
		}
		for _, bad := range []string{"yes", "on", "sure"} {
			_, _, err := strictEnvBool(get(bad), name)
			var ue usageError
			require.ErrorAs(t, err, &ue, "%s=%q", name, bad)
			require.Equal(t, ExitUsageError, classifyExitCode(err))
			require.Contains(t, err.Error(), name)
		}
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
