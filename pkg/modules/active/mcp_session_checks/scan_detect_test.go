package mcp_session_checks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

const toolsListResult = `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"},{"name":"add"}]}}`

// vulnSessionHandler is wide open: it hands out a short, low-entropy session id
// on initialize, honours a client-supplied (fixated) session id, and serves
// tools/list with no session at all.
func vulnSessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			// If the client supplied its own session id, echo it back (fixation).
			if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
				w.Header().Set("Mcp-Session-Id", sid)
			} else {
				// Short + low entropy => flagged as weak.
				w.Header().Set("Mcp-Session-Id", "aaaa")
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, toolsListResult)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// fixationSessionHandler models a genuine fixation primitive: it issues strong
// random session ids, ENFORCES a session for tools/list (rejects anonymous), but
// accepts and echoes a client-supplied Mcp-Session-Id on initialize. This is the
// only shape that should produce a fixation finding — a wide-open server (which
// requires no session at all) must not.
func fixationSessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
				w.Header().Set("Mcp-Session-Id", sid) // accept attacker-supplied id
			} else {
				buf := make([]byte, 32)
				_, _ = rand.Read(buf)
				w.Header().Set("Mcp-Session-Id", hex.EncodeToString(buf)) // strong => not weak
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			// Enforce a session: reject anonymous, accept any non-empty id.
			if r.Header.Get("Mcp-Session-Id") == "" {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"session required"}}`)
				return
			}
			_, _ = io.WriteString(w, toolsListResult)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// strictSessionHandler is well behaved: strong random session ids, requires a
// session for tools/list, and ignores client-supplied session ids on init.
func strictSessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			buf := make([]byte, 32)
			_, _ = rand.Read(buf)
			w.Header().Set("Mcp-Session-Id", hex.EncodeToString(buf)) // 64 chars, high entropy
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			// Require a server-issued session; reject anonymous + fixated ids.
			sid := r.Header.Get("Mcp-Session-Id")
			if len(sid) < 32 {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"session required"}}`)
				return
			}
			_, _ = io.WriteString(w, toolsListResult)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsSessionWeaknesses flags weak session ids, anonymous
// tool enumeration, and session fixation on a wide-open server.
func TestScanPerHost_DetectsSessionWeaknesses(t *testing.T) {
	srv := httptest.NewServer(vulnSessionHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "weak session handling must yield findings")

	names := map[string]bool{}
	for _, e := range res {
		names[e.Info.Name] = true
	}
	assert.True(t, names["MCP Tool List Available Without Session"], "sessionless tools/list should be inventoried")
	assert.True(t, names["MCP Session ID Weakness"], "short low-entropy session id should be flagged")
	// On a wide-open server (tools/list works with no session at all), "fixation"
	// is not a distinct vulnerability — the anonymous-access finding already
	// captures it. It must NOT be reported here (regression guard for the former
	// false positive where our injected id merely persisted client-side).
	assert.False(t, names["MCP Session Fixation Candidate (Attacker-Supplied Mcp-Session-Id)"], "fixation must not be flagged on a sessionless/open server")
	for _, event := range res {
		if event.Info.Name == "MCP Tool List Available Without Session" {
			assert.Equal(t, output.RecordKindObservation, event.RecordKind)
		}
		if event.Info.Name == "MCP Session ID Weakness" {
			assert.Equal(t, output.RecordKindCandidate, event.RecordKind, "repeated session IDs are a candidate")
			assert.NotContains(t, event.ExtractedResults, "aaaa")
		}
	}
}

// TestScanPerHost_DetectsFixation flags fixation only on a server that enforces
// sessions yet accepts an attacker-supplied one.
func TestScanPerHost_DetectsFixation(t *testing.T) {
	srv := httptest.NewServer(fixationSessionHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)

	names := map[string]bool{}
	for _, e := range res {
		names[e.Info.Name] = true
	}
	assert.True(t, names["MCP Session Fixation Candidate (Attacker-Supplied Mcp-Session-Id)"], "fixation candidate should be flagged")
	assert.False(t, names["MCP Tool List Available Without Session"], "session-enforcing server must not be flagged for sessionless access")
	assert.False(t, names["MCP Session ID Weakness"], "strong random session ids must not be flagged weak")
	for _, event := range res {
		if event.Info.Name == "MCP Session Fixation Candidate (Attacker-Supplied Mcp-Session-Id)" {
			assert.Equal(t, output.RecordKindCandidate, event.RecordKind)
			assert.Equal(t, output.EvidenceGradeDifferential, event.EvidenceGrade)
		}
	}
}

// TestScanPerHost_StrictServerNoFinding ensures a server with strong session
// management produces no findings.
func TestScanPerHost_StrictServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(strictSessionHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server with strong session management must not be flagged")
}

// TestShannonEntropy sanity-checks the helper used to grade session ids.
func TestShannonEntropy(t *testing.T) {
	assert.Equal(t, 0.0, shannonEntropy(""))
	assert.Equal(t, 0.0, shannonEntropy("aaaa"), "single repeated rune => zero entropy")
	assert.InDelta(t, 1.0, shannonEntropy("abab"), 0.001, "two equiprobable runes => 1 bit/char")
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
