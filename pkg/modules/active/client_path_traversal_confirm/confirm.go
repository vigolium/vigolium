package client_path_traversal_confirm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// confirmResult is the evidence bundle for one browser-confirmed CSPT primitive.
type confirmResult struct {
	Candidate Candidate

	ControlURL    string
	ControlMethod string

	Payload1URL string
	Payload2URL string
	Method      string // the method the browser actually sent on the escaped request
	NormPath    string // normalized escaped path (round 1)

	Canary1 string
	Canary2 string
}

// confirmCandidate runs the multi-round browser confirmation for one candidate:
//
//  1. CONTROL: a benign source value must land UNDER the intended prefix (and
//     never escape) — proves the source reaches the path and the page is stable.
//  2. PAYLOAD round 1: `../vgl-cspt-<canary1>` must escape the prefix, with the
//     canary present in the normalized path.
//  3. PAYLOAD round 2: a DIFFERENT canary must escape the same way.
//
// Confirm only when the control stays under the prefix AND both distinct
// canaries escape (so the escape is payload-driven, not incidental). Escape is a
// real path normalization (RFC-3986-style dot-segment removal), so a percent-
// encoded `../` that stays as data never confirms.
func (m *Module) confirmCandidate(ctx context.Context, base string, cand Candidate, cookies []*http.Cookie) *confirmResult {
	prefix := strings.TrimSpace(cand.Prefix)
	if prefix == "" {
		return nil // without a known prefix we can't reason about an escape
	}

	// 1. Control.
	controlTok := "vglcsptc" + randToken()
	controlReqs := m.navigate(ctx, base, cand.SourceParam, controlTok, cookies)
	controlUnder, controlEscaped := false, false
	var controlURL, controlMethod string
	for _, r := range controlReqs {
		if !strings.Contains(cleanRawPath(r.URL), controlTok) {
			continue // not our injected request
		}
		if esc, _ := escapesPrefix(prefix, r.URL); esc {
			controlEscaped = true
		} else {
			controlUnder = true
			controlURL, controlMethod = r.URL, r.Method
		}
	}
	if !controlUnder || controlEscaped {
		return nil
	}

	// 2 & 3. Two payload rounds with distinct canaries.
	r1 := m.escapeRound(ctx, base, cand, cookies, prefix)
	if r1 == nil {
		return nil
	}
	r2 := m.escapeRound(ctx, base, cand, cookies, prefix)
	if r2 == nil || r2.canary == r1.canary {
		return nil
	}

	return &confirmResult{
		Candidate:     cand,
		ControlURL:    controlURL,
		ControlMethod: controlMethod,
		Payload1URL:   r1.url,
		Payload2URL:   r2.url,
		Method:        r1.method,
		NormPath:      r1.norm,
		Canary1:       r1.canary,
		Canary2:       r2.canary,
	}
}

type roundResult struct {
	url    string
	method string
	norm   string
	canary string
}

// escapeRound navigates one `../<canary>` payload and returns the captured
// request that escaped the prefix carrying that canary, or nil.
func (m *Module) escapeRound(ctx context.Context, base string, cand Candidate, cookies []*http.Cookie, prefix string) *roundResult {
	canary := "vgl-cspt-" + randToken()
	value := "../" + canary
	for _, r := range m.navigate(ctx, base, cand.SourceParam, value, cookies) {
		esc, norm := escapesPrefix(prefix, r.URL)
		if esc && strings.Contains(norm, canary) {
			return &roundResult{url: r.URL, method: r.Method, norm: norm, canary: canary}
		}
	}
	return nil
}

// navigate injects value into the source position of base and asks the (possibly
// faked) Navigate seam to drive a browser, returning the captured requests. A
// navigation error with no captured requests yields nil.
func (m *Module) navigate(ctx context.Context, base, sourceParam, value string, cookies []*http.Cookie) []CapturedRequest {
	reqs, err := m.Navigate(ctx, NavRequest{
		URL:        buildNavURL(base, sourceParam, value),
		Cookies:    cookies,
		NavTimeout: probeNavTimeout,
		WaitExtra:  probeWaitExtra,
	})
	if err != nil && len(reqs) == 0 {
		return nil
	}
	return reqs
}

// buildNavURL injects value into the URL position named by sourceParam
// (location.hash → fragment, location.search/URLSearchParams → a cspt query
// param, otherwise the fragment as the most attacker-controllable default).
func buildNavURL(base, sourceParam, value string) string {
	u, err := url.Parse(base)
	if err != nil || u == nil {
		return base
	}
	switch sp := strings.ToLower(sourceParam); {
	case strings.Contains(sp, "search"), strings.Contains(sp, "urlsearchparams"):
		q := u.Query()
		q.Set("cspt", value)
		u.RawQuery = q.Encode()
	default: // hash / href / pathname / unknown
		u.Fragment = value
	}
	return u.String()
}

// escapesPrefix reports whether requestURL's path escaped prefix after a real
// dot-segment normalization, returning the normalized path. A literal `../`
// collapses (escape); a percent-encoded `%2e%2e%2f` is a single opaque segment
// that path.Clean leaves in place (stays as data → no escape).
func escapesPrefix(prefix, requestURL string) (bool, string) {
	norm := cleanRawPath(requestURL)
	return !underPrefix(norm, prefix), norm
}

// cleanRawPath extracts the path component of rawURL WITHOUT percent-decoding it
// (so encoded `..` stays opaque), then normalizes dot segments via path.Clean.
func cleanRawPath(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			s = rest[j:]
		} else {
			s = "/"
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		s = "/"
	}
	return path.Clean(s)
}

// underPrefix reports whether cleanedPath is at or below the (cleaned) prefix.
func underPrefix(cleanedPath, prefix string) bool {
	cp := path.Clean(prefix)
	if cleanedPath == cp {
		return true
	}
	return strings.HasPrefix(cleanedPath, cp+"/")
}

// randToken returns 8 hex chars of cryptographic randomness (falls back to a
// fixed marker only if the RNG fails, which never happens in practice).
func randToken() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b[:])
}
