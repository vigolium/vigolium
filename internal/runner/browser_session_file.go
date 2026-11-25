package runner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// browserSessionFileVersion is the format version of --browser-session-file.
// A reader refuses a file of another version rather than guess at its fields.
const browserSessionFileVersion = 1

// browserSessionFile is the on-disk shape of --browser-session-file: the
// spider's harvested sessions keyed by lowercased hostname. It holds live
// credentials (cookies, a bearer token), so it is written 0600.
type browserSessionFile struct {
	Version  int                           `json:"version"`
	SavedAt  time.Time                     `json:"saved_at"`
	Sessions map[string]browserSessionHost `json:"sessions"`
}

// browserSessionHost is one host's carried session.
type browserSessionHost struct {
	CookieHeader string                 `json:"cookie_header,omitempty"`
	Cookies      []browserSessionCookie `json:"cookies,omitempty"`
	// UserAgent is pinned on later requests when set; BrowserUserAgent is the
	// one the browser presented, recorded for a caller replaying the cookies.
	UserAgent           string `json:"user_agent,omitempty"`
	BrowserUserAgent    string `json:"browser_user_agent,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
	Origin              string `json:"origin,omitempty"`
}

type browserSessionCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain,omitempty"`
	Path     string    `json:"path,omitempty"`
	HostOnly bool      `json:"host_only,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	Expires  time.Time `json:"expires,omitzero"`
}

// writeBrowserSessionFile writes sessions to path atomically, mode 0600.
//
// The file carries CLEARANCE - the edge's challenge and bot-management cookies
// and the client string they were issued to - from one invocation to the next.
// A bearer token is an identity by definition, so it is never written: the
// next invocation may be a --no-auth leg or another principal's crawl.
func writeBrowserSessionFile(path string, sessions map[string]httpmsg.CarriedSession, now time.Time) error {
	doc := browserSessionFile{Version: browserSessionFileVersion, SavedAt: now.UTC(), Sessions: make(map[string]browserSessionHost, len(sessions))}
	for host, s := range sessions {
		h := browserSessionHost{
			CookieHeader:     s.CookieHeader,
			UserAgent:        s.UserAgent,
			BrowserUserAgent: s.BrowserUserAgent,
			Origin:           s.Origin,
		}
		for _, c := range s.Cookies {
			h.Cookies = append(h.Cookies, browserSessionCookie(c))
		}
		doc.Sessions[httpmsg.NormalizeHost(host)] = h
	}
	return atomicfile.WriteFile(path, 0o600, func(w *bufio.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	})
}

// readBrowserSessionFile reads path. A missing file is (nil, nil): the first
// invocation of a chain has nothing to carry. Cookies already expired at now
// are dropped, and a host left with nothing to send is dropped with them.
func readBrowserSessionFile(path string, now time.Time) (map[string]httpmsg.CarriedSession, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc browserSessionFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("browser session file %s: %w", path, err)
	}
	if doc.Version != browserSessionFileVersion {
		return nil, fmt.Errorf("browser session file %s: version %d, this build reads %d", path, doc.Version, browserSessionFileVersion)
	}
	out := make(map[string]httpmsg.CarriedSession, len(doc.Sessions))
	for host, h := range doc.Sessions {
		// A file's authorization_header is never carried: a bearer is an identity,
		// and the file is clearance (writeBrowserSessionFile writes none).
		s := httpmsg.CarriedSession{
			CookieHeader:     h.CookieHeader,
			UserAgent:        h.UserAgent,
			BrowserUserAgent: h.BrowserUserAgent,
			Origin:           h.Origin,
		}
		for _, c := range h.Cookies {
			if !c.Expires.IsZero() && !c.Expires.After(now) {
				continue
			}
			s.Cookies = append(s.Cookies, httpmsg.CarriedCookie(c))
		}
		if len(h.Cookies) > 0 && len(s.Cookies) == 0 {
			// Every attributed cookie expired: the flat header is the same jar.
			s.CookieHeader = ""
		}
		if len(s.Cookies) == 0 && s.CookieHeader == "" {
			continue
		}
		out[httpmsg.NormalizeHost(host)] = s
	}
	return out, nil
}

// runCarriesIdentity reports whether this run speaks as a named identity: a
// session it authenticates as (none under --no-auth), or a Cookie /
// Authorization header typed on the command line, which --no-auth does not
// remove.
func (r *Runner) runCarriesIdentity() bool {
	return (r.identityCarried && !r.options.NoAuth) || headersCarryIdentity(r.options.Headers)
}

// headersCarryIdentity reports whether any "Name: value" header is a Cookie or
// an Authorization header - the two that say who the caller is (RFC 6265,
// RFC 9110 section 11.6.2).
func headersCarryIdentity(headers []string) bool {
	for _, h := range headers {
		name, _, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "cookie", "authorization":
			return true
		}
	}
	return false
}

// loadBrowserSessionFile carries the sessions --browser-session-file holds into
// this scan: discovery (buildDeparosConfig reads r.browserSessions) and the
// shared requester. A file that cannot be read is logged and skipped — the scan
// runs as if none had been named — never fatal.
func (r *Runner) loadBrowserSessionFile(infra *phaseInfra) {
	path := r.options.BrowserSessionFile
	if path == "" || !r.options.CarryBrowserSession {
		// --no-carry-browser-session refuses a carried session wherever it
		// comes from.
		return
	}
	sessions, err := readBrowserSessionFile(path, time.Now())
	if err != nil {
		zap.L().Warn("Browser session file not loaded", zap.String("path", path), zap.Error(err))
		return
	}
	if len(sessions) == 0 {
		return
	}
	r.browserSessions = sessions
	if infra != nil && infra.httpRequester != nil {
		infra.httpRequester.SetCarriedSessions(sessions)
	}
	hosts := make([]string, 0, len(sessions))
	for h := range sessions {
		hosts = append(hosts, h)
	}
	zap.L().Info("Loaded carried browser sessions", zap.String("path", path), zap.Strings("hosts", hosts))
}

// saveBrowserSessionFile writes r.browserSessions to --browser-session-file -
// only from a run that carried no identity. A crawl that spoke as a session
// (auth files, inline or DB sessions, a typed Cookie or Authorization header)
// harvested that session's cookies, and writing them back would hand them to
// the next leg that loads the file: a --no-auth leg or another principal's
// crawl. Such a run leaves the file as it found it.
func (r *Runner) saveBrowserSessionFile() {
	path := r.options.BrowserSessionFile
	if path == "" || len(r.browserSessions) == 0 {
		return
	}
	if r.runCarriesIdentity() {
		zap.L().Info("Browser session file not written: this run carried an identity, and the file carries clearance only",
			zap.String("path", path))
		return
	}
	if err := writeBrowserSessionFile(path, r.browserSessions, time.Now()); err != nil {
		zap.L().Warn("Browser session file not written", zap.String("path", path), zap.Error(err))
	}
}
