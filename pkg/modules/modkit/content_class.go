package modkit

import (
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ContentClass is a coarse categorization of a response body by media type,
// used to skip modules whose findings structurally require a different body
// shape (e.g. clickjacking analysis on a JSON API response). The string values
// are the canonical class names; the modules package's content-class tag
// derivation and the executor's content-class gate compare against these
// lowercase literals, so keep them in sync.
type ContentClass string

const (
	ContentClassUnknown ContentClass = ""
	ContentClassHTML    ContentClass = "html"
	ContentClassJSON    ContentClass = "json"
	ContentClassXML     ContentClass = "xml"
	ContentClassText    ContentClass = "text"
	ContentClassBinary  ContentClass = "binary"
)

// ClassifyContentType maps a Content-Type header value to a ContentClass.
// Parameters (e.g. "; charset=utf-8") are ignored. xhtml is treated as HTML
// (checked before XML). Returns ContentClassUnknown for empty or unrecognized
// types so the caller can fail open.
func ClassifyContentType(ct string) ContentClass {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return ContentClassUnknown
	}
	switch {
	case strings.Contains(ct, "html"): // text/html, application/xhtml+xml
		return ContentClassHTML
	case strings.Contains(ct, "json"): // application/json, application/*+json
		return ContentClassJSON
	case strings.Contains(ct, "xml"): // application/xml, text/xml, image/svg+xml, *+xml
		return ContentClassXML
	case strings.HasPrefix(ct, "text/"):
		return ContentClassText
	case strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "font/"),
		ct == "application/octet-stream",
		ct == "application/pdf",
		ct == "application/zip":
		return ContentClassBinary
	default:
		return ContentClassUnknown
	}
}

// ResponseContentClass returns the ContentClass of an item's response, derived
// from its Content-Type header. Returns ContentClassUnknown when the response
// or header is absent.
func ResponseContentClass(item *httpmsg.HttpRequestResponse) ContentClass {
	if item == nil {
		return ContentClassUnknown
	}
	resp := item.Response()
	if resp == nil {
		return ContentClassUnknown
	}
	return ClassifyContentType(resp.Header("Content-Type"))
}

// ContentClassAllows reports whether a module requiring the given content
// classes may run against a response of the observed class. It fails open: an
// unknown or plain-text response always runs (text/plain can carry mislabeled
// markup that a browser still treats as a document only when sniffed, so it is
// never hard-excluded). A confirmed structured class (html/json/xml/binary)
// that is not in the required set is the only case that skips.
func ContentClassAllows(required []string, class ContentClass) bool {
	if len(required) == 0 {
		return true
	}
	if class == ContentClassUnknown || class == ContentClassText {
		return true
	}
	for _, r := range required {
		if ContentClass(strings.ToLower(strings.TrimSpace(r))) == class {
			return true
		}
	}
	return false
}

// ContentClassRegistry records a per-host content-class hint seeded from the
// heuristics root probe. It is consulted only as a fallback when an individual
// record's own Content-Type is indeterminate, so module gating can still defer
// markup-only modules on a host whose root was a JSON/XML API. Thread-safe.
type ContentClassRegistry struct {
	mu     sync.RWMutex
	byHost map[string]ContentClass
}

// NewContentClassRegistry returns an empty registry.
func NewContentClassRegistry() *ContentClassRegistry {
	return &ContentClassRegistry{byHost: make(map[string]ContentClass)}
}

// Set records the content class observed for host. Empty host or unknown class
// is a no-op.
func (r *ContentClassRegistry) Set(host string, c ContentClass) {
	if r == nil || c == ContentClassUnknown {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	r.mu.Lock()
	r.byHost[host] = c
	r.mu.Unlock()
}

// Get returns the recorded content class for host, or ContentClassUnknown.
func (r *ContentClassRegistry) Get(host string) ContentClass {
	if r == nil {
		return ContentClassUnknown
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ContentClassUnknown
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byHost[host]
}
