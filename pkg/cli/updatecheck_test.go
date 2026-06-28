package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestIsVersionBehind(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"equal with v prefix mix", "v0.1.41-beta", "0.1.41-beta", false},
		{"patch behind", "v0.1.41-beta", "0.1.42-beta", true},
		{"minor behind", "v0.1.41-beta", "0.2.0-beta", true},
		{"ahead", "v0.2.0-beta", "0.1.99-beta", false},
		{"prerelease older than release", "v0.1.41-beta", "0.1.41", true},
		{"release not behind its own prerelease", "v0.1.41", "0.1.41-beta", false},
		{"both v prefixed", "v1.0.0", "v1.0.1", true},
		{"dev build never behind", "dev", "9.9.9", false},
		{"git hash never behind", "a1b2c3d", "9.9.9", false},
		{"empty latest", "v0.1.41-beta", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVersionBehind(tc.current, tc.latest); got != tc.want {
				t.Fatalf("isVersionBehind(%q,%q)=%v want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

func TestNormalizedSemver(t *testing.T) {
	cases := map[string]string{
		"0.1.41-beta":  "v0.1.41-beta",
		"v0.1.41-beta": "v0.1.41-beta",
		"  1.2.3  ":    "v1.2.3",
		"":             "",
	}
	for in, want := range cases {
		if got := normalizedSemver(in); got != want {
			t.Errorf("normalizedSemver(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCacheStale(t *testing.T) {
	now := time.Now().Unix()
	if cacheStale(updateCacheData{CheckedAt: now}) {
		t.Errorf("a just-checked cache should be fresh")
	}
	old := now - int64((25 * time.Hour).Seconds())
	if !cacheStale(updateCacheData{CheckedAt: old}) {
		t.Errorf("a 25h-old cache should be stale")
	}
	// Zero-value (never written) is always stale.
	if !cacheStale(updateCacheData{}) {
		t.Errorf("an empty cache should be stale")
	}
}

func TestUpdateCacheRoundTrip(t *testing.T) {
	// config.ExpandPath resolves ~ via $HOME on unix; redirect it to a temp dir.
	t.Setenv("HOME", t.TempDir())

	if _, ok := readUpdateCache(); ok {
		t.Fatalf("expected no cache initially")
	}
	writeUpdateCache("0.9.9-beta")
	got, ok := readUpdateCache()
	if !ok {
		t.Fatalf("expected cache after write")
	}
	if got.LatestVersion != "0.9.9-beta" {
		t.Errorf("LatestVersion=%q want 0.9.9-beta", got.LatestVersion)
	}
	if cacheStale(got) {
		t.Errorf("freshly written cache should not be stale")
	}
}

func TestFetchLatestNpmVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"latest":"0.1.42-beta","linux-x64":"0.1.42-beta-linux-x64"}`))
	}))
	defer srv.Close()

	prev := npmDistTagsURL
	npmDistTagsURL = srv.URL
	t.Cleanup(func() { npmDistTagsURL = prev })

	got, err := fetchLatestNpmVersion()
	if err != nil {
		t.Fatalf("fetch error: %v", err)
	}
	if got != "0.1.42-beta" {
		t.Errorf("latest=%q want 0.1.42-beta", got)
	}
}

func TestFetchLatestNpmVersionBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	prev := npmDistTagsURL
	npmDistTagsURL = srv.URL
	t.Cleanup(func() { npmDistTagsURL = prev })

	if _, err := fetchLatestNpmVersion(); err == nil {
		t.Fatalf("expected error on non-200 status")
	}
}

func TestUpdateCheckHardDisabled(t *testing.T) {
	cmd := func(name string) *cobra.Command { return &cobra.Command{Use: name} }
	const valid = "v0.1.41-beta"

	// Excluded commands are always disabled.
	for _, name := range []string{"version", "update", "init"} {
		if !updateCheckHardDisabled(cmd(name), valid) {
			t.Errorf("%q should be hard-disabled", name)
		}
	}

	// A non-comparable (dev/hash) version is always disabled.
	if !updateCheckHardDisabled(cmd("scan"), "vdev") {
		t.Errorf("a non-semver version should be hard-disabled")
	}

	// A normal command on a valid release build is enabled by default...
	t.Setenv(envDisableUpdateCheck, "")
	t.Setenv(envAutoUpdateReexeced, "")
	if updateCheckHardDisabled(cmd("scan"), valid) {
		t.Errorf("scan should not be hard-disabled by default")
	}

	// ...but the disable env switches it off.
	t.Setenv(envDisableUpdateCheck, "1")
	if !updateCheckHardDisabled(cmd("scan"), valid) {
		t.Errorf("VIGOLIUM_DISABLE_UPDATE_CHECK should hard-disable")
	}
	t.Setenv(envDisableUpdateCheck, "")

	// The re-exec sentinel also switches it off (loop guard).
	t.Setenv(envAutoUpdateReexeced, "1")
	if !updateCheckHardDisabled(cmd("scan"), valid) {
		t.Errorf("re-exec sentinel should hard-disable")
	}
}

func TestScheduleUpdateNoticeFromCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeUpdateCache("99.0.0") // fresh cache, far ahead of any real version
	t.Cleanup(func() { pendingUpdateNotice = "" })

	pendingUpdateNotice = ""
	scheduleUpdateNotice("v0.1.41-beta")
	if pendingUpdateNotice == "" {
		t.Fatalf("expected a notice when behind")
	}
	if !strings.Contains(pendingUpdateNotice, "99.0.0") {
		t.Errorf("notice should mention the latest version: %s", pendingUpdateNotice)
	}

	pendingUpdateNotice = ""
	scheduleUpdateNotice("v99.0.1") // ahead of cache
	if pendingUpdateNotice != "" {
		t.Errorf("did not expect a notice when ahead: %s", pendingUpdateNotice)
	}
}

func TestFormatUpdateNotice(t *testing.T) {
	notice := formatUpdateNotice("v0.1.41-beta", "v0.1.42-beta")
	for _, want := range []string{"v0.1.41-beta", "v0.1.42-beta", "vigolium update"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice missing %q:\n%s", want, notice)
		}
	}
}
