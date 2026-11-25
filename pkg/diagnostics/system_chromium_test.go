package diagnostics

import (
	"errors"
	"strings"
	"testing"
)

// stageNoCfTBuild makes checkChromium see a host with no Chrome for Testing
// build whose system browser lookup answers resolve.
func stageNoCfTBuild(t *testing.T, resolve func() (string, string, error)) {
	t.Helper()
	prevSupported, prevSystem := cftSupported, systemChromium
	t.Cleanup(func() { cftSupported, systemChromium = prevSupported, prevSystem })
	cftSupported = func() bool { return false }
	systemChromium = resolve
}

// TestCheckChromiumNamesSystemBinaryWithoutCfT: on a platform with no CfT
// build, doctor reports the system binary it resolved and the lookup order.
func TestCheckChromiumNamesSystemBinaryWithoutCfT(t *testing.T) {
	stageNoCfTBuild(t, func() (string, string, error) { return "/usr/bin/chromium-browser", "chromium-browser", nil })
	probed := ""
	withProbe(t, func(p string) error { probed = p; return nil })

	got := checkChromium(true)
	if got.Status != StatusOK || got.Path != "/usr/bin/chromium-browser" {
		t.Fatalf("checkChromium = %+v, want OK at the system chromium-browser", got)
	}
	if !strings.Contains(got.Message, "system chromium-browser") || !strings.Contains(got.Message, "no Chrome for Testing build") {
		t.Errorf("message %q does not name the system binary and why", got.Message)
	}
	if !strings.Contains(strings.Join(got.Details, "\n"), "chromium, chromium-browser, google-chrome") {
		t.Errorf("details %v do not state the lookup order", got.Details)
	}
	if probed != "/usr/bin/chromium-browser" {
		t.Errorf("launch probe ran on %q, want the resolved binary", probed)
	}
}

// TestCheckChromiumNoSystemBrowserWithoutCfT: nothing on PATH is a warning
// carrying the install hint.
func TestCheckChromiumNoSystemBrowserWithoutCfT(t *testing.T) {
	stageNoCfTBuild(t, func() (string, string, error) {
		return "", "", errors.New("no system Chromium on PATH (looked up chromium, chromium-browser, google-chrome in that order)")
	})
	got := checkChromium(false)
	if got.Status != StatusWarning || got.Path != "" {
		t.Fatalf("checkChromium = %+v, want a warning with no path", got)
	}
	if !strings.Contains(got.Message, "chromium, chromium-browser, google-chrome") || got.Tip == "" {
		t.Errorf("warning %+v lacks the lookup order or the install hint", got)
	}
}
