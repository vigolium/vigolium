package browsercookie

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRenderPlaywrightSessionCookieUsesNegativeOne(t *testing.T) {
	// Playwright reads expires as seconds with -1 meaning "session". Writing 0
	// instead creates a cookie that expired in 1970, which it silently drops —
	// the storageState loads and the context is simply not logged in.
	cookies := []Cookie{
		{Name: "sid", Value: "abc", Domain: ".acme.test", Path: "", Secure: true, HTTPOnly: true},
		{Name: "pref", Value: "dark", Domain: "acme.test", Path: "/app", Expires: time.Unix(1800000000, 0)},
	}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatPlaywright, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var state struct {
		Cookies []struct {
			Name     string  `json:"name"`
			Path     string  `json:"path"`
			Expires  float64 `json:"expires"`
			SameSite string  `json:"sameSite"`
			HTTPOnly bool    `json:"httpOnly"`
		} `json:"cookies"`
		Origins []any `json:"origins"`
	}
	if err := json.Unmarshal(buf.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(state.Cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(state.Cookies))
	}
	if state.Cookies[0].Expires != PlaywrightSessionExpiry {
		t.Errorf("session cookie expires = %v, want %v", state.Cookies[0].Expires, PlaywrightSessionExpiry)
	}
	if state.Cookies[0].Path != "/" {
		t.Errorf("empty path = %q, want / (Playwright rejects an empty path)", state.Cookies[0].Path)
	}
	if !state.Cookies[0].HTTPOnly {
		t.Error("httpOnly was lost")
	}
	if state.Cookies[1].Expires != 1800000000 {
		t.Errorf("expires = %v, want seconds since the epoch", state.Cookies[1].Expires)
	}
	if state.Cookies[0].SameSite != DefaultSameSite {
		t.Errorf("sameSite = %q, want the documented default %q", state.Cookies[0].SameSite, DefaultSameSite)
	}
	if state.Origins == nil {
		t.Error("origins must be present, even empty")
	}
}

func TestRenderPlaywrightSameSiteOverride(t *testing.T) {
	cookies := []Cookie{{Name: "sid", Value: "x", Domain: ".acme.test", Secure: true}}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatPlaywright, RenderOptions{SameSite: "none"}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), `"sameSite": "None"`) {
		t.Errorf("override not applied, got:\n%s", buf.String())
	}
}

func TestRenderPlaywrightKeepsStoredSameSiteOverDefault(t *testing.T) {
	cookies := []Cookie{{Name: "sid", Value: "x", Domain: ".acme.test", SameSite: "Strict"}}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatPlaywright, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), `"sameSite": "Strict"`) {
		t.Errorf("a recorded SameSite must win over the default, got:\n%s", buf.String())
	}
}

func TestRenderNetscapeFlagsHTTPOnlyWithCurlPrefix(t *testing.T) {
	cookies := []Cookie{
		{Name: "sid", Value: "abc", Domain: ".acme.test", Path: "/", Secure: true, HTTPOnly: true, Expires: time.Unix(1800000000, 0)},
		{Name: "plain", Value: "v", Domain: "acme.test", Path: "/"},
	}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatNetscape, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	lines := nonCommentLines(buf.String())
	if len(lines) != 2 {
		t.Fatalf("got %d data lines, want 2:\n%s", len(lines), buf.String())
	}
	// #HttpOnly_ is curl's marker; without it curl drops the flag on load and
	// the replayed session differs from the browser's.
	if !strings.HasPrefix(lines[0], "#HttpOnly_.acme.test\t") {
		t.Errorf("httpOnly line = %q, want the #HttpOnly_ prefix", lines[0])
	}
	fields := strings.Split(lines[0], "\t")
	if len(fields) != 7 {
		t.Fatalf("got %d fields, want 7: %q", len(fields), lines[0])
	}
	if fields[1] != "TRUE" {
		t.Errorf("include-subdomains for a leading-dot domain = %q, want TRUE", fields[1])
	}
	if fields[3] != "TRUE" {
		t.Errorf("secure = %q, want TRUE", fields[3])
	}
	if fields[4] != "1800000000" {
		t.Errorf("expires = %q, want epoch seconds", fields[4])
	}
	second := strings.Split(lines[1], "\t")
	if second[1] != "FALSE" {
		t.Errorf("include-subdomains for a host-only domain = %q, want FALSE", second[1])
	}
	if second[4] != "0" {
		t.Errorf("session cookie expires = %q, want 0 in this format", second[4])
	}
}

func TestRenderHeaderCollapsesDuplicateNamesByPathSpecificity(t *testing.T) {
	// A Cookie header carries no path, so a duplicated name has to resolve to
	// one value. A browser sends the more specific path first; this keeps that
	// one rather than whichever the store happened to yield first.
	cookies := []Cookie{
		{Name: "sid", Value: "root", Domain: "acme.test", Path: "/"},
		{Name: "sid", Value: "deep", Domain: "acme.test", Path: "/app/admin"},
		{Name: "a", Value: "1", Domain: "acme.test", Path: "/"},
	}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatHeader, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "a=1; sid=deep" {
		t.Errorf("header = %q, want %q", got, "a=1; sid=deep")
	}
}

func TestRenderJSONLIsOnePerLine(t *testing.T) {
	cookies := []Cookie{
		{Name: "a", Value: "1", Domain: "acme.test"},
		{Name: "b", Value: "2", Domain: "acme.test"},
	}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatJSONL, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	lines := nonCommentLines(buf.String())
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		var c Cookie
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Errorf("line %q is not a JSON object: %v", line, err)
		}
	}
}

func TestRenderJSONEmitsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, nil, FormatJSON, RenderOptions{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Errorf("empty JSON export = %q, want []", got)
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":              FormatJSON,
		"playwright":    FormatPlaywright,
		"storage-state": FormatPlaywright,
		"NETSCAPE":      FormatNetscape,
		"curl":          FormatNetscape,
		"header":        FormatHeader,
		"jsonl":         FormatJSONL,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = (%v, %v), want %v", in, got, err, want)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("an unknown format should be rejected")
	}
}

func TestValidateSameSite(t *testing.T) {
	for _, ok := range []string{"", "strict", "Lax", "NONE"} {
		if err := ValidateSameSite(ok); err != nil {
			t.Errorf("ValidateSameSite(%q) = %v, want nil", ok, err)
		}
	}
	if err := ValidateSameSite("maybe"); err == nil {
		t.Error("an unknown same-site value should be rejected")
	}
}

func TestRedactKeepsATailAndHidesTheRest(t *testing.T) {
	got := Redact("supersecretvalue")
	if strings.Contains(got, "supersecret") {
		t.Errorf("Redact leaked the value: %q", got)
	}
	if !strings.HasSuffix(got, "alue") {
		t.Errorf("Redact(%q) = %q, want a 4-character tail", "supersecretvalue", got)
	}
	// The mask is a fixed width on purpose: a 600-character session cookie
	// masked to its own length makes the listing unreadable.
	if len(got) != 12 {
		t.Errorf("Redact(%q) = %q (%d chars), want a fixed 12", "supersecretvalue", got, len(got))
	}
	if long := Redact(strings.Repeat("x", 600) + "tail"); len(long) != 12 {
		t.Errorf("a 604-character value redacted to %d chars, want 12", len(long))
	}
	// A short value reveals no suffix: four characters of a six-character
	// token are most of it. The mask is the same fixed width, so it does not
	// disclose the length either.
	for _, short := range []string{"abc", "123456", "elevenchars"} {
		if got := Redact(short); got != "********" {
			t.Errorf("Redact(%q) = %q, want the bare 8-star mask", short, got)
		}
	}
	if got := Redact("twelvechars!"); got != "********ars!" {
		t.Errorf("Redact(12 chars) = %q, want the mask plus a 4-character tail", got)
	}
	if got := Redact(""); got != "" {
		t.Errorf("Redact(\"\") = %q, want empty", got)
	}
}

func TestDistinctDomains(t *testing.T) {
	cookies := []Cookie{
		{Domain: "b.test"}, {Domain: "a.test"}, {Domain: "b.test"},
	}
	if got := DistinctDomains(cookies); !slices.Equal(got, []string{"a.test", "b.test"}) {
		t.Errorf("DistinctDomains = %v", got)
	}
}

// nonCommentLines returns the non-empty, non-comment lines of s, ignoring the
// curl #HttpOnly_ marker which is data rather than a comment.
func nonCommentLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func TestRenderPlaywrightWithholdsNoneFromInsecureCookies(t *testing.T) {
	// SameSite=None without Secure is not ignored by a browser — the whole
	// cookie is rejected. Applying the override blindly would drop exactly the
	// non-Secure session cookies a real profile carries (SID, APISID, SIDCC).
	cookies := []Cookie{
		{Name: "secure-one", Value: "a", Domain: ".acme.test", Secure: true},
		{Name: "insecure-one", Value: "b", Domain: ".acme.test"},
	}
	opts := RenderOptions{SameSite: "none"}
	var buf bytes.Buffer
	if err := Render(&buf, cookies, FormatPlaywright, opts); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var state struct {
		Cookies []struct {
			Name     string `json:"name"`
			SameSite string `json:"sameSite"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := map[string]string{}
	for _, c := range state.Cookies {
		got[c.Name] = c.SameSite
	}
	if got["secure-one"] != "None" {
		t.Errorf("secure cookie sameSite = %q, want None", got["secure-one"])
	}
	if got["insecure-one"] != DefaultSameSite {
		t.Errorf("insecure cookie sameSite = %q, want %q — None would make a browser reject it", got["insecure-one"], DefaultSameSite)
	}
	if n := SameSiteNoneWithheld(cookies, opts); n != 1 {
		t.Errorf("SameSiteNoneWithheld = %d, want 1", n)
	}
	if n := SameSiteNoneWithheld(cookies, RenderOptions{}); n != 0 {
		t.Errorf("SameSiteNoneWithheld with no override = %d, want 0", n)
	}
}
