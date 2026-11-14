package http

import (
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// WithPreservedHeaders returns a shallow clone whose requests keep the
// module's own value for each key instead of the session's or the operator's
// (-H) copy. A key is a header name, or "cookie:<name>" for one cookie inside
// Cookie, which is then spliced into the session/-H cookie string rather than
// replacing it; a header the request lacks is never added. Keys accumulate
// over the receiver's. An empty list returns r unchanged.
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
	clone.preservedScope = ""
	if len(merged) > 0 {
		clone.preservedScope = "|preserve:" + strings.Join(merged, ",")
	}
	return &clone
}

// preservedSnapshot is the module's own values for the preserved keys, read
// off the request before defaults, carried sessions, -H and session
// credentials are applied.
type preservedSnapshot struct {
	headers map[string][]string // canonical name -> module's values (non-empty only)
	cookies []string            // module's "name=value" for preserved cookie names, in request order
}

// snapshotPreserved records the request's current values for keys (already
// normalized by WithPreservedHeaders). A header the request does not carry
// (or carries empty) is not recorded: preserving never adds a missing header.
// nil when nothing was recorded.
func snapshotPreserved(h http.Header, keys []string) *preservedSnapshot {
	var snap *preservedSnapshot
	var cookieNames map[string]bool
	for _, k := range keys {
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
			snap.cookies = append(snap.cookies, name+"="+value)
		}
	}
	return snap
}

// restore puts the module's values back after the credential surface was
// applied: whole headers verbatim, single cookies spliced into whatever
// Cookie header the session / -H produced (replaced by name, else appended).
func (s *preservedSnapshot) restore(h http.Header) {
	if s == nil {
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
	h.Set("Cookie", httpmsg.OverrideCookieHeaders(h.Get("Cookie"), strings.Join(s.cookies, "; ")))
}
