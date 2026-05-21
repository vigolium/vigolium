package pistream

import (
	"bytes"
	"strings"
	"testing"
)

// TestStream_AuditDriverStreamCustomMessages verifies that piolium's
// "role":"custom","customType":"audit-stream" events — which Pi emits
// for every phase/tool action — are rendered. Before the custom-message
// path was added, json.Unmarshal failed silently because content is a
// string (not a []contentBlock) and the entire feed would collapse to
// just the session header.
func TestStream_AuditDriverStreamCustomMessages(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"session","version":3,"id":"019de4a7-7388-719e-95d9-a857414db37e","timestamp":"2026-05-01T17:47:52.584Z","cwd":"/tmp/repo"}`,
		// duplicated start/end events as observed in the wild — should render once
		`{"type":"message_start","message":{"role":"custom","customType":"audit-stream","content":"[Q2] → read  piolium/attack-surface/lite-recon.md","display":true,"details":{"kind":"tool-start","phase":"Q2","toolName":"read","body":"piolium/attack-surface/lite-recon.md"},"timestamp":1777657678251}}`,
		`{"type":"message_end","message":{"role":"custom","customType":"audit-stream","content":"[Q2] → read  piolium/attack-surface/lite-recon.md","display":true,"details":{"kind":"tool-start","phase":"Q2","toolName":"read","body":"piolium/attack-surface/lite-recon.md"},"timestamp":1777657678251}}`,
		`{"type":"message_end","message":{"role":"custom","customType":"audit-stream","content":"[Q2] ← read  # Lite Recon — Q0","display":true,"details":{"kind":"tool-end","phase":"Q2","toolName":"read","body":"# Lite Recon"},"timestamp":1777657678260}}`,
		`{"type":"message_end","message":{"role":"custom","customType":"audit-stream","content":"[Q2] ✗ read  ENOENT: no such file","display":true,"details":{"kind":"tool-error","phase":"Q2","toolName":"read","body":"ENOENT"},"timestamp":1777657678255}}`,
	}, "\n")

	var out bytes.Buffer
	if err := Stream(strings.NewReader(in), &out, Options{}); err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	got := out.String()

	mustContain := []string{
		"[piolium]",
		"019de4a7",
		"[Q2] → read",
		"[Q2] ← read",
		"[Q2] ✗ read",
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, got)
		}
	}

	// Each unique content string should appear exactly once — duplicated
	// message_start/message_end pairs must collapse to a single line.
	if n := strings.Count(got, "[Q2] → read"); n != 1 {
		t.Errorf("expected tool-start to render once, got %d occurrences:\n%s", n, got)
	}
}

// TestStream_StandardAgentMessageStillRenders ensures the change to
// agentMessage.Content (now json.RawMessage) didn't break the normal
// assistant-text rendering path used by non-custom Pi messages.
func TestStream_StandardAgentMessageStillRenders(t *testing.T) {
	in := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"hello world"}]}}`

	var out bytes.Buffer
	if err := Stream(strings.NewReader(in), &out, Options{}); err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	if !strings.Contains(out.String(), "hello world") {
		t.Errorf("expected assistant text in output, got:\n%s", out.String())
	}
}

// TestStream_CustomMessageRespectsDisplayFlag ensures display:false
// custom events stay hidden so we don't leak suppressed-by-design
// piolium internals into the CLI feed.
func TestStream_CustomMessageRespectsDisplayFlag(t *testing.T) {
	in := `{"type":"message_end","message":{"role":"custom","customType":"audit-stream","content":"hidden noise","display":false,"details":{"kind":"tool-start"}}}`

	var out bytes.Buffer
	if err := Stream(strings.NewReader(in), &out, Options{}); err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	if strings.Contains(out.String(), "hidden noise") {
		t.Errorf("display:false content leaked into output:\n%s", out.String())
	}
}
