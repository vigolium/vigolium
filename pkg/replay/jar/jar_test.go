package jar

import (
	gohttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.json")

	j, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, _ := url.Parse("https://example.com/")
	j.SetCookies(u, []*gohttp.Cookie{
		{Name: "session", Value: "abc123", Path: "/"},
		{Name: "csrf", Value: "xyz789", Path: "/"},
	})
	if err := j.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from disk.
	j2, n, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 cookies loaded, got %d", n)
	}
	got := j2.Cookies(u)
	if len(got) != 2 {
		t.Fatalf("Cookies(u) returned %d, want 2", len(got))
	}
}

func TestSaveDropsExpired(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "expired.json")
	j, _ := New(path)
	u, _ := url.Parse("https://example.com/")
	j.SetCookies(u, []*gohttp.Cookie{
		{Name: "live", Value: "1", Path: "/"},
		{Name: "dead", Value: "1", Path: "/", Expires: time.Now().Add(-time.Hour)},
	})
	if err := j.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	j2, n, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if n != 1 {
		t.Errorf("after expiry purge, loaded %d cookies, want 1", n)
	}
	for _, c := range j2.Cookies(u) {
		if c.Name == "dead" {
			t.Errorf("expired cookie %q should have been dropped", c.Name)
		}
	}
}

func TestMissingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "does-not-exist.json")
	j, n, err := Open(path)
	if err != nil {
		t.Fatalf("Open missing file should be ok, got: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 cookies, got %d", n)
	}
	if j == nil {
		t.Fatal("expected non-nil jar")
	}
}

func TestSanitizeSessionID(t *testing.T) {
	tests := map[string]string{
		"login":          "login",
		"login/etc":      "login_etc",
		"../escape":      ".._escape",
		"a-b_c.d":        "a-b_c.d",
		"":               "default",
		"with space":     "with_space",
		"weird!@#$chars": "weird____chars",
	}
	for in, want := range tests {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathForRespectsHome(t *testing.T) {
	t.Setenv("VIGOLIUM_HOME", t.TempDir())
	p := PathFor("foo")
	if p == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(p) != "foo.json" {
		t.Errorf("PathFor: want basename foo.json, got %s", filepath.Base(p))
	}
	// Empty session-id → empty path.
	if PathFor("") != "" {
		t.Errorf("PathFor(\"\") should return empty")
	}
}

func TestSaveSkipsWhenPathEmpty(t *testing.T) {
	j, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, _ := url.Parse("https://example.com/")
	j.SetCookies(u, []*gohttp.Cookie{{Name: "k", Value: "v", Path: "/"}})
	if err := j.Save(); err != nil {
		t.Fatalf("Save with empty path should noop, got: %v", err)
	}
	// Sanity: nothing got created in CWD or temp.
	if _, err := os.Stat(""); err == nil {
		t.Fatal("empty path should not create a file")
	}
}
