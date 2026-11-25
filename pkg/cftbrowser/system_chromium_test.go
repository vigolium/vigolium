package cftbrowser

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stageHost makes the package see platform as the host and resolve only the
// names in onPath (name -> path).
func stageHost(t *testing.T, platform string, onPath map[string]string) *[]string {
	t.Helper()
	prevHost, prevLook := hostPlatform, lookPath
	t.Cleanup(func() { hostPlatform, lookPath = prevHost, prevLook })
	hostPlatform = func() string { return platform }
	var asked []string
	lookPath = func(name string) (string, error) {
		asked = append(asked, name)
		if p, ok := onPath[name]; ok {
			return p, nil
		}
		return "", exec.ErrNotFound
	}
	return &asked
}

// TestSystemChromiumLookupOrder: chromium first, then chromium-browser, then
// google-chrome; the first one on PATH wins and is named.
func TestSystemChromiumLookupOrder(t *testing.T) {
	asked := stageHost(t, "linux_arm64", map[string]string{
		"chromium-browser": "/usr/bin/chromium-browser",
		"google-chrome":    "/usr/bin/google-chrome",
	})
	path, name, err := SystemChromium()
	if err != nil {
		t.Fatalf("SystemChromium: %v", err)
	}
	if path != "/usr/bin/chromium-browser" || name != "chromium-browser" {
		t.Fatalf("SystemChromium = %q %q, want chromium-browser", path, name)
	}
	if strings.Join(*asked, ",") != "chromium,chromium-browser" {
		t.Fatalf("lookup order = %v, want chromium then chromium-browser", *asked)
	}
}

// TestEnsureBrowserLinuxARM64UsesSystemChromium: with no CfT build for the
// host, EnsureBrowser downloads nothing and returns the system browser.
func TestEnsureBrowserLinuxARM64UsesSystemChromium(t *testing.T) {
	stageHost(t, "linux_arm64", map[string]string{"google-chrome": "/opt/google/chrome"})
	prevAPI := apiURL
	apiURL = "http://127.0.0.1:1/never-fetched"
	t.Cleanup(func() { apiURL = prevAPI })

	if IsSupported() {
		t.Fatal("linux/arm64 reported as a Chrome for Testing platform")
	}
	var events []ProgressEvent
	bin, err := EnsureBrowser(context.Background(), func(ev ProgressEvent) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("EnsureBrowser: %v", err)
	}
	if bin != "/opt/google/chrome" {
		t.Fatalf("EnsureBrowser = %q, want the system google-chrome", bin)
	}
	if len(events) != 0 {
		t.Fatalf("no download should be announced, got %+v", events)
	}
}

// TestEnsureBrowserLinuxARM64NoSystemBrowser: the error names the lookup
// order and the install remedy.
func TestEnsureBrowserLinuxARM64NoSystemBrowser(t *testing.T) {
	stageHost(t, "linux_arm64", nil)
	_, err := EnsureBrowser(context.Background(), nil)
	if err == nil {
		t.Fatal("EnsureBrowser succeeded with no browser installed")
	}
	for _, want := range []string{"linux/arm64", "chromium, chromium-browser, google-chrome", "apt install chromium"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if errors.Is(err, exec.ErrNotFound) {
		t.Error("the PATH miss should be summarized, not wrapped raw")
	}
}

// TestCacheRootFollowsStateDir: the Chrome for Testing cache lives under
// VIGOLIUM_STATE_DIR when it is set.
func TestCacheRootFollowsStateDir(t *testing.T) {
	state := t.TempDir()
	t.Setenv("VIGOLIUM_STATE_DIR", state)
	root, err := cacheRoot()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(state, "cache", "vigolium"); root != want {
		t.Fatalf("cacheRoot = %q, want %q", root, want)
	}
}
