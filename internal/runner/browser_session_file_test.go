package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// A harvest written by one invocation is read back by the next, mode 0600,
// with cookies and both User-Agents intact and the bearer token dropped (the
// file is clearance, a token an identity); expired cookies and a host left with
// nothing to send are dropped.
func TestBrowserSessionFile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	in := map[string]httpmsg.CarriedSession{
		"App.Test": {
			CookieHeader: "cf_clearance=abc; sid=1",
			Cookies: []httpmsg.CarriedCookie{
				{Name: "cf_clearance", Value: "abc", Domain: "app.test", Path: "/", Secure: true, Expires: now.Add(time.Hour)},
				{Name: "sid", Value: "1", Domain: "app.test", Path: "/", HostOnly: true},
				{Name: "old", Value: "x", Domain: "app.test", Path: "/", Expires: now.Add(-time.Minute)},
			},
			BrowserUserAgent:    "Mozilla/5.0 test",
			AuthorizationHeader: "Bearer t0k",
			Origin:              "https://app.test",
		},
		"stale.test": {
			CookieHeader: "gone=1",
			Cookies:      []httpmsg.CarriedCookie{{Name: "gone", Value: "1", Domain: "stale.test", Expires: now.Add(-time.Hour)}},
		},
	}
	if err := writeBrowserSessionFile(path, in, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("session file mode %v, want owner-only", perm)
	}

	out, err := readBrowserSessionFile(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("hosts = %v, want app.test only (stale.test fully expired)", out)
	}
	s, ok := out["app.test"]
	if !ok {
		t.Fatalf("host key not normalized: %v", out)
	}
	if len(s.Cookies) != 2 || s.Cookies[0].Name != "cf_clearance" || !s.Cookies[0].Secure || !s.Cookies[1].HostOnly {
		t.Fatalf("cookies = %+v", s.Cookies)
	}
	if s.BrowserUserAgent != "Mozilla/5.0 test" || s.UserAgent != "" || s.AuthorizationHeader != "" || s.Origin != "https://app.test" {
		t.Fatalf("session = %+v", s)
	}
}

func TestBrowserSessionFile_MissingAndBad(t *testing.T) {
	dir := t.TempDir()
	if got, err := readBrowserSessionFile(filepath.Join(dir, "none.json"), time.Now()); got != nil || err != nil {
		t.Fatalf("missing file = %v, %v; want nothing and no error", got, err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"version":9,"sessions":{}}`), 0o600)
	if _, err := readBrowserSessionFile(bad, time.Now()); err == nil {
		t.Fatal("a file of another version must be refused")
	}
	_ = os.WriteFile(bad, []byte(`not json`), 0o600)
	if _, err := readBrowserSessionFile(bad, time.Now()); err == nil {
		t.Fatal("a malformed file must be refused")
	}
}

// loadBrowserSessionFile puts the file's sessions on the runner (discovery) and
// the requester (every later phase); saveBrowserSessionFile writes them back.
func TestRunner_LoadsAndSavesBrowserSessionFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := writeBrowserSessionFile(path, map[string]httpmsg.CarriedSession{
		"app.test": {CookieHeader: "cf_clearance=abc"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	req := http.NewOfflineRequester("test")
	off := &Runner{options: &types.Options{BrowserSessionFile: path}}
	off.loadBrowserSessionFile(nil)
	if off.browserSessions != nil {
		t.Fatal("--no-carry-browser-session refuses the file's sessions too")
	}
	r := &Runner{options: &types.Options{BrowserSessionFile: path, CarryBrowserSession: true}}
	r.loadBrowserSessionFile(&phaseInfra{httpRequester: req})
	if r.browserSessions["app.test"].CookieHeader != "cf_clearance=abc" {
		t.Fatalf("runner sessions = %v", r.browserSessions)
	}

	out := filepath.Join(t.TempDir(), "out.json")
	r.options.BrowserSessionFile = out
	r.saveBrowserSessionFile()
	back, err := readBrowserSessionFile(out, time.Now())
	if err != nil || back["app.test"].CookieHeader != "cf_clearance=abc" {
		t.Fatalf("saved = %v, %v", back, err)
	}

	none := &Runner{options: &types.Options{}}
	none.loadBrowserSessionFile(nil)
	none.saveBrowserSessionFile()
	if none.browserSessions != nil {
		t.Fatal("no file named, nothing carried")
	}
}

// A run that speaks as an identity - a session it authenticates as, or a typed
// Cookie / Authorization header - leaves the file as it found it: its harvest
// holds that identity's cookies, which the next leg (a --no-auth leg, another
// principal's crawl) must never send.
func TestBrowserSessionFile_IdentityRunWritesNothing(t *testing.T) {
	harvest := map[string]httpmsg.CarriedSession{"app.test": {CookieHeader: "cf_clearance=abc; sid=alice"}}
	for name, r := range map[string]*Runner{
		"session":        {options: &types.Options{}, identityCarried: true},
		"cookie header":  {options: &types.Options{Headers: []string{"Cookie: sid=alice"}}},
		"bearer header":  {options: &types.Options{Headers: []string{"authorization: Bearer x"}}},
		"no-auth cookie": {options: &types.Options{NoAuth: true, Headers: []string{"Cookie: sid=alice"}}},
	} {
		path := filepath.Join(t.TempDir(), "s.json")
		r.options.BrowserSessionFile = path
		r.browserSessions = harvest
		r.saveBrowserSessionFile()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s: an identity run wrote the session file (err=%v)", name, err)
		}
	}
	// An anonymous run writes clearance; so does a --no-auth leg whose sessions
	// are switched off.
	noAuthWithSession := &Runner{options: &types.Options{NoAuth: true}, identityCarried: true}
	if noAuthWithSession.runCarriesIdentity() {
		t.Fatal("--no-auth switches the run's sessions off")
	}
	for name, opts := range map[string]*types.Options{
		"anonymous": {},
		"no-auth":   {NoAuth: true},
	} {
		path := filepath.Join(t.TempDir(), "s.json")
		opts.BrowserSessionFile = path
		r := &Runner{options: opts, browserSessions: harvest}
		r.saveBrowserSessionFile()
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: clearance not written: %v", name, err)
		}
	}
}

func TestHeadersCarryIdentity(t *testing.T) {
	if headersCarryIdentity([]string{"X-Forwarded-For: 1.2.3.4", "User-Agent: x"}) {
		t.Fatal("plain headers are no identity")
	}
	if !headersCarryIdentity([]string{"X-A: 1", " Cookie : a=b"}) {
		t.Fatal("a Cookie header is an identity")
	}
}
