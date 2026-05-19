package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlanFileFlagRegistered guards that --plan-file stays wired on both
// agentic-scan entry points. If this fails the single-file plan workflow
// silently regresses to requiring --input + --instruction-file.
func TestPlanFileFlagRegistered(t *testing.T) {
	assert.NotNil(t, agentAutopilotCmd.Flags().Lookup("plan-file"),
		"--plan-file must be registered on `vigolium agent autopilot`")
	assert.NotNil(t, agentSwarmCmd.Flags().Lookup("plan-file"),
		"--plan-file must be registered on `vigolium agent swarm`")
}

func writePlan(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plan.md")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestResolvePlanFile_RejectsConflictingFlags(t *testing.T) {
	p := writePlan(t, "GET /a HTTP/2\nHost: x.test\n")

	if _, _, err := resolvePlanFile(p, "curl https://x.test", "", ""); err == nil ||
		!strings.Contains(err.Error(), "--input") {
		t.Fatalf("expected --input conflict error, got %v", err)
	}
	if _, _, err := resolvePlanFile(p, "", "do the thing", ""); err == nil ||
		!strings.Contains(err.Error(), "--instruction") {
		t.Fatalf("expected --instruction conflict error, got %v", err)
	}
	if _, _, err := resolvePlanFile(p, "", "", "/tmp/instr.txt"); err == nil ||
		!strings.Contains(err.Error(), "--instruction-file") {
		t.Fatalf("expected --instruction-file conflict error, got %v", err)
	}
}

func TestResolvePlanFile_MissingFile(t *testing.T) {
	if _, _, err := resolvePlanFile("/no/such/plan.md", "", "", ""); err == nil {
		t.Fatal("expected error for missing plan file")
	}
}

func TestResolvePlanFile_EmptyPlanRejected(t *testing.T) {
	p := writePlan(t, "   \n\n  \n")
	if _, _, err := resolvePlanFile(p, "", "", ""); err == nil ||
		!strings.Contains(err.Error(), "no instruction or HTTP request") {
		t.Fatalf("expected empty-plan error, got %v", err)
	}
}

func TestResolvePlanFile_ProseAndRequest(t *testing.T) {
	p := writePlan(t, "order IDs 0254685, 0254774 — focus on IDOR\n\n"+
		"GET /order/details?orderId=0254809 HTTP/2\nHost: ginandjuice.shop\nCookie: session=abc\n")

	instr, reqs, err := resolvePlanFile(p, "", "", "")
	require.NoError(t, err)
	assert.Contains(t, instr, "focus on IDOR")
	assert.NotContains(t, instr, "GET /order/details")
	require.Len(t, reqs, 1)
	assert.True(t, strings.HasPrefix(reqs[0], "GET /order/details?orderId=0254809 HTTP/2"))
	assert.Contains(t, reqs[0], "Cookie: session=abc")
}

func TestAppendExtraRequests(t *testing.T) {
	out := appendExtraRequests("focus IDOR", []string{
		"GET /order?id=2 HTTP/2\nHost: x",
		"GET /order?id=3 HTTP/2\nHost: x",
	})
	assert.True(t, strings.HasPrefix(out, "focus IDOR"))
	assert.Contains(t, out, "Additional related requests")
	assert.Contains(t, out, "--- additional request 1 ---")
	assert.Contains(t, out, "--- additional request 2 ---")
	assert.Contains(t, out, "GET /order?id=2 HTTP/2")

	// No extras → instruction returned unchanged.
	assert.Equal(t, "just this", appendExtraRequests("just this", nil))
}
