package secret_detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHead = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"

func TestBuildEvidenceResponse_SmallBodyShownInFull(t *testing.T) {
	body := []byte("var apiKey = \"AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk\";\n")
	got := BuildEvidenceResponse(testHead, body, "AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk", 1)

	assert.Equal(t, testHead+string(body), got)
	assert.NotContains(t, got, "truncated", "small body must not be truncated")
}

func TestBuildEvidenceResponse_LargeMultilineWindowsAroundMatch(t *testing.T) {
	secret := "AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk"
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "line %d filler content padding padding padding\n", i)
	}
	// Insert the secret on a known line, well past evidenceFullThreshold.
	sb.WriteString("const key = \"" + secret + "\";\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "trailing %d more filler content padding padding\n", i)
	}
	body := []byte(sb.String())
	require.Greater(t, len(body), evidenceFullThreshold)

	got := BuildEvidenceResponse(testHead, body, secret, 0)

	assert.True(t, strings.HasPrefix(got, testHead), "must keep response head")
	assert.Contains(t, got, secret, "window must include the matched secret")
	assert.Contains(t, got, "line 199", "window must include the line just before the match")
	assert.Contains(t, got, "trailing 0", "window must include the line just after the match")
	assert.NotContains(t, got, "line 190", "window must not reach 10 lines before the match")
	assert.NotContains(t, got, "trailing 10", "window must not reach 10 lines after the match")
	assert.Contains(t, got, "bytes truncated", "large body must mark truncated edges")
}

func TestBuildEvidenceResponse_MinifiedSingleLineCharClamped(t *testing.T) {
	secret := "AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk"
	// One giant line (minified bundle): line windowing would span everything, so
	// the char cap must bound the window instead.
	left := strings.Repeat("a", 50_000)
	right := strings.Repeat("b", 50_000)
	body := []byte(left + secret + right)
	require.Greater(t, len(body), evidenceFullThreshold)

	got := BuildEvidenceResponse(testHead, body, secret, 1)

	assert.Contains(t, got, secret)
	assert.Contains(t, got, "bytes truncated")
	// The window keeps at most ~evidenceContextChars on each side of the match,
	// so the rendered output is far smaller than the full body.
	assert.Less(t, len(got), len(testHead)+len(secret)+4*evidenceContextChars+200,
		"minified line must be clamped to the char window, not dumped whole")
	// And the far ends of the bundle must be excluded.
	assert.NotContains(t, got, strings.Repeat("a", evidenceContextChars+50))
	assert.NotContains(t, got, strings.Repeat("b", evidenceContextChars+50))
}
