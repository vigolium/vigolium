package httpmsg

import "strings"

// HeaderOwner is implemented by insertion points whose payload lives in a
// request header the requester would otherwise overwrite with the session's
// or the operator's (-H) value. OwnedHeaderKeys returns lowercased keys in
// the http.Requester.WithPreservedHeaders format: a header name ("x-api-key")
// or "cookie:<name>" for a single cookie inside the Cookie header.
type HeaderOwner interface {
	OwnedHeaderKeys() []string
}

// PreserveCookieKeyPrefix marks a preserved-header key naming one cookie.
const PreserveCookieKeyPrefix = "cookie:"

// OwnedHeaderKeys: a header insertion point owns its header.
func (h *HeaderInsertionPoint) OwnedHeaderKeys() []string {
	if h == nil || h.headerName == "" {
		return nil
	}
	return []string{strings.ToLower(h.headerName)}
}

// OwnedHeaderKeys: a cookie parameter owns its one cookie; other parameter
// types live in the URL or body and own no header.
func (p *ParameterInsertionPoint) OwnedHeaderKeys() []string {
	if p == nil || p.insertionType != INS_PARAM_COOKIE || p.Name() == "" {
		return nil
	}
	return []string{PreserveCookieKeyPrefix + strings.ToLower(p.Name())}
}

// OwnedHeaderKeys: a nested point's payload travels inside its outermost
// parent, so it owns whatever that root owns.
func (n *NestedInsertionPoint) OwnedHeaderKeys() []string {
	if n == nil {
		return nil
	}
	root := n
	for root.parentNested != nil {
		root = root.parentNested
	}
	if owner, ok := root.parentParam.(HeaderOwner); ok {
		return owner.OwnedHeaderKeys()
	}
	return nil
}

// OwnedHeaderKeysOf returns ip's owned header keys, or nil when ip does not
// implement HeaderOwner.
func OwnedHeaderKeysOf(ip InsertionPoint) []string {
	if owner, ok := ip.(HeaderOwner); ok {
		return owner.OwnedHeaderKeys()
	}
	return nil
}
