package browser

import (
	"context"
	"strings"
	"testing"
)

// --offline drops every download rung (Chrome for Testing download,
// rod auto-download); cached and system browsers stay.
func TestOfflineDropsDownloadCandidates(t *testing.T) {
	SetOffline(true)
	defer SetOffline(false)
	embedded := func() (string, error) { return "", nil }
	cands := buildBrowserCandidates(context.Background(), "linux", "amd64", "", []string{"/usr/bin/chromium"}, embedded)
	for _, c := range cands {
		if strings.Contains(c.label, "download") {
			t.Errorf("offline candidate list contains %q", c.label)
		}
	}
	if len(cands) == 0 {
		t.Fatal("system/cached candidates must remain")
	}
}
