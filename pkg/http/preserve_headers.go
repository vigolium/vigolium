package http

import (
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// WithPreservedHeaders returns a shallow clone whose requests keep the
// module's own value for each key instead of the session's or the operator's
// (-H) copy (MISS-11). Keys use the Options.PreserveHeaders format: a header
// name, or "cookie:<name>" for one cookie inside Cookie. Keys accumulate over
// the receiver's. An empty list returns r unchanged.
func (r *Requester) WithPreservedHeaders(keys []string) *Requester {
	if r == nil || len(keys) == 0 {
		return r
	}
	clone := *r
	merged := make([]string, 0, len(r.preserved)+len(keys))
	merged = append(merged, r.preserved...)
	for _, k := range keys {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			merged = append(merged, k)
		}
	}
	clone.preserved = merged
	return &clone
}

// preservedSnapshot is the module's own values for the preserved keys, read
// off the request before defaults, carried sessions, -H and session
// credentials are applied.
type preservedSnapshot struct {
	headers map[string][]string // canonical name -> module's values (non-empty only)
	cookies []cookiePair        // module's values for preserved cookie names, in request order
}

type cookiePair struct{ name, value string }

func (s *preservedSnapshot) empty() bool {
	return s == nil || (len(s.headers) == 0 && len(s.cookies) == 0)
}

// snapshotPreserved records the request's current values for keys. A header
// the request does not carry (or carries empty) is not recorded: preserving
// never adds a missing header.
func snapshotPreserved(h http.Header, keys ...[]string) *preservedSnapshot {
	var snap *preservedSnapshot
	var cookieNames map[string]bool
	for _, list := range keys {
		for _, k := range list {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				continue
			}
			if name, ok := strings.CutPrefix(k, httpmsg.PreserveCookieKeyPrefix); ok {
				if name == "" {
					continue
				}
				if cookieNames == nil {
					cookieNames = make(map[string]bool)
				}
				cookieNames[name] = true
				continue
			}
			canon := http.CanonicalHeaderKey(k)
			vals := h[canon]
			if len(vals) == 0 || vals[0] == "" {
				continue
			}
			if snap == nil {
				snap = &preservedSnapshot{}
			}
			if snap.headers == nil {
				snap.headers = make(map[string][]string)
			}
			snap.headers[canon] = append([]string(nil), vals...)
		}
	}
	if len(cookieNames) > 0 {
		for _, kv := range strings.Split(h.Get("Cookie"), ";") {
			kv = strings.TrimSpace(kv)
			name, value, _ := strings.Cut(kv, "=")
			name = strings.TrimSpace(name)
			if name == "" || !cookieNames[strings.ToLower(name)] {
				continue
			}
			if snap == nil {
				snap = &preservedSnapshot{}
			}
			snap.cookies = append(snap.cookies, cookiePair{name: name, value: value})
		}
	}
	return snap
}

// restore puts the module's values back after the credential surface was
// applied: whole headers verbatim, single cookies spliced into whatever
// Cookie header the session / -H produced (replaced by name, else appended).
func (s *preservedSnapshot) restore(h http.Header) {
	if s.empty() {
		return
	}
	for canon, vals := range s.headers {
		h[canon] = vals
	}
	if len(s.cookies) == 0 {
		return
	}
	if _, whole := s.headers["Cookie"]; whole {
		return
	}
	h.Set("Cookie", spliceCookies(h.Get("Cookie"), s.cookies))
}

// spliceCookies replaces each pair's cookie in header (name matched
// case-insensitively) or appends it when absent.
func spliceCookies(header string, pairs []cookiePair) string {
	var parts []string
	for _, kv := range strings.Split(header, ";") {
		if kv = strings.TrimSpace(kv); kv != "" {
			parts = append(parts, kv)
		}
	}
	for _, p := range pairs {
		replaced := false
		for i, kv := range parts {
			name, _, _ := strings.Cut(kv, "=")
			if strings.EqualFold(strings.TrimSpace(name), p.name) {
				parts[i] = p.name + "=" + p.value
				replaced = true
				break
			}
		}
		if !replaced {
			parts = append(parts, p.name+"="+p.value)
		}
	}
	return strings.Join(parts, "; ")
}
