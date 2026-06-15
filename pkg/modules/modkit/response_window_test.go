package modkit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultOpts() ResponseWindowOpts { return DefaultResponseWindowOpts() }

func TestWindowBody_SmallBodyUnchanged(t *testing.T) {
	body := []byte("var apiKey = \"AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk\";\n")
	got := WindowBody(body, []string{"AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk"}, 1, defaultOpts())

	assert.Equal(t, string(body), got)
	assert.NotContains(t, got, "truncated", "small body must not be truncated")
}

func TestWindowBody_LargeMultilineWindowsAroundMatch(t *testing.T) {
	secret := "AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk"
	var sb strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "line %d filler content padding padding padding\n", i)
	}
	sb.WriteString("const key = \"" + secret + "\";\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "trailing %d more filler content padding padding\n", i)
	}
	body := []byte(sb.String())
	require.Greater(t, len(body), DefaultResponseWindowOpts().FullThreshold)

	got := WindowBody(body, []string{secret}, 0, defaultOpts())

	assert.Contains(t, got, secret, "window must include the matched value")
	// 10 lines of context on each side.
	assert.Contains(t, got, "line 399", "window must include the line just before the match")
	assert.Contains(t, got, "line 390", "window must include 10 lines before the match")
	assert.NotContains(t, got, "line 389", "window must not reach 11 lines before the match")
	assert.Contains(t, got, "trailing 9", "window must include 10 lines after the match")
	assert.NotContains(t, got, "trailing 10", "window must not reach 11 lines after the match")
	assert.Contains(t, got, "bytes truncated", "large body must mark truncated edges")
}

func TestWindowBody_MinifiedSingleLineCharClamped(t *testing.T) {
	secret := "AIzaSyAFi5SqFWHuSSGO5cyrhrLKdgLpMsa1Jmk"
	left := strings.Repeat("a", 50_000)
	right := strings.Repeat("b", 50_000)
	body := []byte(left + secret + right)
	opts := defaultOpts()
	require.Greater(t, len(body), opts.FullThreshold)

	got := WindowBody(body, []string{secret}, 1, opts)

	assert.Contains(t, got, secret)
	assert.Contains(t, got, "bytes truncated")
	// At most ~ContextChars on each side, far smaller than the full body.
	assert.Less(t, len(got), len(secret)+4*opts.ContextChars+200,
		"minified line must be clamped to the char window, not dumped whole")
	assert.NotContains(t, got, strings.Repeat("a", opts.ContextChars+50))
	assert.NotContains(t, got, strings.Repeat("b", opts.ContextChars+50))
}

func TestWindowBody_TruncationByteCountsAreAccurate(t *testing.T) {
	secret := "SECRET"
	left := strings.Repeat("x", 10_000)
	right := strings.Repeat("y", 10_000)
	body := []byte(left + secret + right)
	opts := ResponseWindowOpts{FullThreshold: 8 * 1024, ContextLines: 5, ContextChars: 512, FallbackLines: 5}

	got := WindowBody(body, []string{secret}, 0, opts)

	leadPrefix := fmt.Sprintf("... [%d bytes truncated] ...\n", 10_000-opts.ContextChars)
	assert.True(t, strings.HasPrefix(got, leadPrefix), "got prefix: %q", got[:min(60, len(got))])
	trailSuffix := fmt.Sprintf("\n... [%d bytes truncated] ...", 10_000-opts.ContextChars)
	assert.True(t, strings.HasSuffix(got, trailSuffix))
}

func TestWindowBody_LocatorTailAfterColon(t *testing.T) {
	// Module wraps the matched token in a descriptive label; the verbatim label is
	// not in the body but its tail (the real token) is.
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&sb, "noise line %d padding padding padding padding\n", i)
	}
	sb.WriteString("throw new Error('boom'); // Traceback (most recent call last)\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&sb, "tail line %d padding padding padding padding\n", i)
	}
	body := []byte(sb.String())
	require.Greater(t, len(body), DefaultResponseWindowOpts().FullThreshold)

	got := WindowBody(body, []string{"Matched: Traceback (most recent call last)"}, 0, defaultOpts())

	assert.Contains(t, got, "Traceback (most recent call last)", "tail-after-colon locator must center the window")
	assert.Contains(t, got, "noise line 299")
	assert.NotContains(t, got, "noise line 280")
}

func TestWindowBody_FallbackFirstNLines(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "L%d padding padding padding padding padding padding\n", i)
	}
	body := []byte(sb.String())
	require.Greater(t, len(body), DefaultResponseWindowOpts().FullThreshold)

	// No locator matches and no line anchor → first FallbackLines (5) lines.
	got := WindowBody(body, []string{"NOT-IN-BODY"}, 0, defaultOpts())

	assert.Contains(t, got, "L0")
	assert.Contains(t, got, "L4", "first 5 lines (L0..L4) must be shown")
	assert.NotContains(t, got, "L5", "fallback must stop after the first 5 lines")
	assert.Contains(t, got, "bytes truncated", "the rest of the body must be marked truncated")
	assert.False(t, strings.HasPrefix(got, "... ["), "fallback must not prefix a leading truncation marker")
}

func TestWindowBody_FallbackMinifiedByteCapped(t *testing.T) {
	// A huge single-line body with no locator: firstNLinesEnd would return the
	// whole body, so the FullThreshold byte cap must bound the fallback.
	body := []byte(strings.Repeat("z", 200_000))
	opts := defaultOpts()

	got := WindowBody(body, nil, 0, opts)

	assert.LessOrEqual(t, len(got), opts.FullThreshold+64, "fallback must be byte-capped for a single-line body")
	assert.Contains(t, got, "bytes truncated")
}

func TestWindowBody_LineAnchorFallback(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "row %d padding padding padding padding padding\n", i)
	}
	body := []byte(sb.String())
	require.Greater(t, len(body), DefaultResponseWindowOpts().FullThreshold)

	// Locator absent, but a 1-indexed line anchor points at row 250 (line 251).
	got := WindowBody(body, []string{"absent"}, 251, defaultOpts())

	assert.Contains(t, got, "row 250", "line anchor must center the window")
	assert.Contains(t, got, "row 240")
	assert.NotContains(t, got, "row 230")
}

func TestHasStaticAssetExtension(t *testing.T) {
	for _, p := range []string{"/static/app.js", "/a/b/main.css", "/assets/index.MAP", "/f.woff2", "/i.png"} {
		assert.True(t, HasStaticAssetExtension(p), "expected static: %s", p)
	}
	for _, p := range []string{"/api/users", "/index.html", "/", "/report.json", "/assets/page"} {
		assert.False(t, HasStaticAssetExtension(p), "expected non-static: %s", p)
	}
}
