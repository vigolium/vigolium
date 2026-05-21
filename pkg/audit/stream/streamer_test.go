package stream

import (
	"bytes"
	"strings"
	"testing"
)

// fixtureStream is a minimal-but-realistic NDJSON sample drawn from
// platform/vigolium-audit/tests/fixtures/audit-json-output.jsonl (trimmed to
// the events the renderer cares about). Inlined so the test does not
// depend on the vendored TS fixture moving.
const fixtureStream = `{"kind":"auditStart","auditId":"aud-1","mode":"lite","totalPhases":3,"runnablePhases":3}
{"kind":"phaseStart","auditId":"aud-1","phase":{"id":"Q0","title":"Quick Recon","agent":null},"index":1,"total":3}
{"kind":"phaseAdapterEvent","auditId":"aud-1","phaseId":"Q0","event":{"kind":"session","sessionId":"sess-1"}}
{"kind":"phaseAdapterEvent","auditId":"aud-1","phaseId":"Q0","event":{"kind":"toolCall","id":"item_1","tool":"Bash","input":{"command":"ls audit"}}}
{"kind":"phaseAdapterEvent","auditId":"aud-1","phaseId":"Q0","event":{"kind":"toolResult","id":"item_1","output":"audit-state.json\n","isError":false}}
{"kind":"phaseAdapterEvent","auditId":"aud-1","phaseId":"Q0","event":{"kind":"finish","ok":true,"result":"","usd":0.01,"tokens":{"input":100,"output":20},"durationMs":4500}}
{"kind":"phaseEnd","auditId":"aud-1","phase":{"id":"Q0","title":"Quick Recon","agent":null},"ok":true,"usd":0.01,"tokens":{"input":100,"output":20},"durationMs":4500}
{"kind":"findingDiscovered","auditId":"aud-1","phaseId":null,"path":"/tmp/x/audit/findings-draft/q2-001.md","relPath":"audit/findings-draft/q2-001.md"}
{"kind":"auditEnd","auditId":"aud-1","status":"complete","usd":0.05,"tokens":{"input":3000,"output":200},"findings":{"total":4,"bySeverity":{"High":4}}}
{"kind":"result","auditId":"aud-1","status":"complete","totalUsd":0.05,"totalTokens":{"input":3000,"output":200},"findings":{"total":4,"bySeverity":{"High":4}},"failedPhases":[],"skippedPhases":[]}
`

func TestStream_CapturesResult(t *testing.T) {
	var rendered, raw bytes.Buffer
	res, err := Stream(strings.NewReader(fixtureStream), &rendered, Options{RawLog: &raw})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}

	if res.AuditID != "aud-1" {
		t.Errorf("auditID = %q, want %q", res.AuditID, "aud-1")
	}
	if res.Status != "complete" {
		t.Errorf("status = %q, want %q", res.Status, "complete")
	}
	if res.TotalUSD != 0.05 {
		t.Errorf("totalUsd = %v, want 0.05", res.TotalUSD)
	}
	if got := res.TotalTokens; got.Input != 3000 || got.Output != 200 {
		t.Errorf("totalTokens = %+v, want {3000 200}", got)
	}
	if res.Findings.Total != 4 {
		t.Errorf("findings.total = %d, want 4", res.Findings.Total)
	}
	if res.Findings.BySeverity["High"] != 4 {
		t.Errorf("findings.bySeverity[High] = %d, want 4", res.Findings.BySeverity["High"])
	}

	out := rendered.String()
	wantSubstrings := []string{
		"audit aud-1",
		"phase Q0",
		"Quick Recon",
		"Bash",
		"ls audit",
		"finding draft",
		"q2-001.md",
		"status=complete",
		"High:4",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("rendered output missing %q\n---\n%s", s, out)
		}
	}

	// Raw log must contain every input line.
	if rawLines := strings.Count(raw.String(), "\n"); rawLines != strings.Count(fixtureStream, "\n") {
		t.Errorf("raw log line count = %d, want %d", rawLines, strings.Count(fixtureStream, "\n"))
	}
}

// A chained `audit run --modes deep,confirm` emits one `result` event
// per mode. Stream must report the aggregate (summed cost/tokens, latest
// status/auditId, max findings) — not just the final leg.
func TestStream_AccumulatesMultipleResults(t *testing.T) {
	const chained = `{"kind":"result","auditId":"aud-deep","status":"complete","totalUsd":0.40,"totalTokens":{"input":3000,"output":200},"findings":{"total":5,"bySeverity":{"High":5}},"failedPhases":[],"skippedPhases":[]}
{"kind":"result","auditId":"aud-confirm","status":"complete","totalUsd":0.10,"totalTokens":{"input":800,"output":50},"findings":{"total":3,"bySeverity":{"High":3}},"failedPhases":["p9"],"skippedPhases":[]}
`
	var rendered bytes.Buffer
	res, err := Stream(strings.NewReader(chained), &rendered, Options{})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}

	if got := res.TotalUSD; got != 0.50 {
		t.Errorf("totalUsd = %v, want 0.50 (0.40+0.10)", got)
	}
	if got := res.TotalTokens; got.Input != 3800 || got.Output != 250 {
		t.Errorf("totalTokens = %+v, want {3800 250}", got)
	}
	// Latest leg wins for identity / status / phase lists.
	if res.AuditID != "aud-confirm" {
		t.Errorf("auditID = %q, want aud-confirm (latest leg)", res.AuditID)
	}
	if len(res.FailedPhases) != 1 || res.FailedPhases[0] != "p9" {
		t.Errorf("failedPhases = %v, want [p9] (latest leg)", res.FailedPhases)
	}
	// findings/ is cumulative across chained modes — the larger snapshot
	// is kept, never summed.
	if res.Findings.Total != 5 {
		t.Errorf("findings.total = %d, want 5 (max, not 8)", res.Findings.Total)
	}
}

func TestStream_ZeroResultWhenNoResultEvent(t *testing.T) {
	const partial = `{"kind":"auditStart","auditId":"aud-2","mode":"lite","totalPhases":1,"runnablePhases":1}
{"kind":"phaseStart","auditId":"aud-2","phase":{"id":"Q0","title":"Quick Recon","agent":null},"index":1,"total":1}
`
	var rendered bytes.Buffer
	res, err := Stream(strings.NewReader(partial), &rendered, Options{})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	if !res.IsZero() {
		t.Errorf("expected zero Result when stream cuts off before result event, got %+v", res)
	}
}

func TestStream_TolerantOfMalformedLine(t *testing.T) {
	const garbage = `not-json
{"kind":"auditStart","auditId":"aud-3","mode":"lite","totalPhases":1,"runnablePhases":1}
{"kind":"result","auditId":"aud-3","status":"complete","totalUsd":0,"totalTokens":{"input":0,"output":0},"findings":{"total":0,"bySeverity":{}}}
`
	var rendered bytes.Buffer
	res, err := Stream(strings.NewReader(garbage), &rendered, Options{})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	if res.AuditID != "aud-3" {
		t.Errorf("expected to parse past malformed line; got auditID = %q", res.AuditID)
	}
}
