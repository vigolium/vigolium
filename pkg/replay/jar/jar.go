// Package jar implements a disk-persistent http.CookieJar wrapper so a
// multi-step auth flow (login → CSRF cookie → action) survives between
// vigolium CLI invocations.
//
// SetCookies snapshots each call into a list keyed by request URL.
// Save() serializes the list; Load() replays SetCookies(url, cookies)
// against a fresh stdlib jar — this preserves the inner jar's
// domain/path logic without us having to peek inside it.
package jar

import (
	"encoding/json"
	"fmt"
	gohttp "net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// PersistentJar wraps a stdlib cookiejar.Jar with disk-backed
// SetCookies tracking. It satisfies http.CookieJar so an *http.Client
// can use it transparently.
type PersistentJar struct {
	mu       sync.Mutex
	inner    *cookiejar.Jar
	path     string
	snapshot []cookieRecord
}

// cookieRecord is one (request URL, cookie) pair as observed via
// SetCookies. We persist these tuples rather than the jar's internal
// state so Load() can faithfully reconstruct it.
type cookieRecord struct {
	URL    string         `json:"url"`
	Cookie *gohttp.Cookie `json:"cookie"`
}

// New returns an empty PersistentJar that will persist to path on
// Save(). path is not read here — call Load() (or use Open()) if you
// want to pre-populate from an existing file.
func New(path string) (*PersistentJar, error) {
	inner, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("create inner jar: %w", err)
	}
	return &PersistentJar{inner: inner, path: path}, nil
}

// Open returns a PersistentJar pre-populated from path. A missing file
// is not an error — it's the first-use case. Returns the jar plus the
// number of cookies replayed (useful for status messages).
func Open(path string) (*PersistentJar, int, error) {
	j, err := New(path)
	if err != nil {
		return nil, 0, err
	}
	n, err := j.Load()
	if err != nil {
		return nil, 0, err
	}
	return j, n, nil
}

// Path returns the disk path Save() will write to.
func (j *PersistentJar) Path() string { return j.path }

// SetCookies records the cookies in the snapshot and delegates to the
// inner jar so future Cookies() calls return them.
func (j *PersistentJar) SetCookies(u *url.URL, cookies []*gohttp.Cookie) {
	if u == nil || len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	for _, c := range cookies {
		if c == nil {
			continue
		}
		// Copy the cookie so later mutations in the inner jar (or by the
		// caller) don't disturb our snapshot.
		cp := *c
		j.snapshot = append(j.snapshot, cookieRecord{URL: u.String(), Cookie: &cp})
	}
	j.mu.Unlock()
	j.inner.SetCookies(u, cookies)
}

// Cookies returns the cookies the inner jar would attach to a request
// for u.
func (j *PersistentJar) Cookies(u *url.URL) []*gohttp.Cookie {
	return j.inner.Cookies(u)
}

// Save writes the snapshot to j.Path() atomically (write-tmp + rename)
// so an interrupted save can't leave a partial file behind. Returns
// nil silently when j.path is empty (caller opted out of persistence).
//
// Expired cookies are dropped at save time so the on-disk file doesn't
// grow unbounded across sessions.
func (j *PersistentJar) Save() error {
	if j == nil || j.path == "" {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	// Drop expired cookies.
	now := time.Now()
	live := j.snapshot[:0]
	for _, r := range j.snapshot {
		if !r.Cookie.Expires.IsZero() && r.Cookie.Expires.Before(now) {
			continue
		}
		live = append(live, r)
	}
	j.snapshot = live

	if err := os.MkdirAll(filepath.Dir(j.path), 0o755); err != nil {
		return fmt.Errorf("mkdir jar dir: %w", err)
	}
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open jar tmp: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(j.snapshot); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encode jar: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close jar tmp: %w", err)
	}
	if err := os.Rename(tmp, j.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename jar: %w", err)
	}
	return nil
}

// Load reads the snapshot at j.Path() and replays SetCookies into the
// inner jar. Returns the number of cookies loaded; a missing file is
// treated as zero (not an error).
func (j *PersistentJar) Load() (int, error) {
	if j == nil || j.path == "" {
		return 0, nil
	}
	data, err := os.ReadFile(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read jar: %w", err)
	}
	var snapshot []cookieRecord
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return 0, fmt.Errorf("decode jar: %w", err)
	}
	j.mu.Lock()
	j.snapshot = snapshot
	j.mu.Unlock()
	// Replay SetCookies per record so the inner jar's domain/path logic
	// makes the same choices it did on the original write.
	loaded := 0
	for _, r := range snapshot {
		u, err := url.Parse(r.URL)
		if err != nil || u == nil {
			continue
		}
		j.inner.SetCookies(u, []*gohttp.Cookie{r.Cookie})
		loaded++
	}
	return loaded, nil
}

// DefaultDir returns the directory replay jars live in. Honours
// VIGOLIUM_HOME if set; otherwise defaults to ~/.vigolium/replay-jars/.
// Returns "" if neither can be resolved.
func DefaultDir() string {
	if v := os.Getenv("VIGOLIUM_HOME"); v != "" {
		return filepath.Join(v, "replay-jars")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vigolium", "replay-jars")
}

// PathFor returns the on-disk path for a given session-id under
// DefaultDir(). Empty sessionID returns "".
func PathFor(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	dir := DefaultDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sanitize(sessionID)+".json")
}

// sanitize replaces filesystem-hostile characters with underscores so a
// user-supplied --session-id can't escape the jar dir.
func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}
