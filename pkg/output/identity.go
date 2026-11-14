package output

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"net/url"
	"strings"
)

// Finding identity.
//
// The v1 identity (and so stored finding_hash) is the content hash of module +
// description + severity + matched URL. Prose is not identity: a timing module
// that writes the measured delay into its description gets a new v1 identity
// on every run, so a re-detection becomes a new row, `fixed` is never reopened
// and triage is lost.
//
// Identity v2 is location-based and applies to findings tied to an insertion
// point (the executor stamps InsertionPointType): kind, module, rule, method,
// the canonical location of the scanned request (scheme://host[:port]/path, no
// query) and the point. Findings with no insertion point keep the v1 content
// identity: for passive and per-host modules the description is what tells two
// distinct issues on one URL apart, and the v6 store migration re-keys exactly
// the same set (see database.RekeyFindingIdentities), so a re-detection after
// the migration lands on the migrated row. An explicit DedupKey always wins.

// IdentityFields are the inputs of a v2 (location-based) finding identity.
type IdentityFields struct {
	Kind     RecordKind
	ModuleID string
	Rule     string // Info.Name (module_name in the store)
	Method   string
	URL      string // the scanned (unmutated) request's URL; the query is dropped
	IPType   string
	Param    string
}

// IdentityKeyV2 renders the v2 identity key:
// kind|module_id|rule|METHOD|canonical-location|ip_type:param.
func IdentityKeyV2(f IdentityFields) string {
	kind := f.Kind
	if kind == "" {
		kind = RecordKindFinding
	}
	var b strings.Builder
	b.Grow(len(f.ModuleID) + len(f.Rule) + len(f.URL) + len(f.IPType) + len(f.Param) + 32)
	b.WriteString(string(kind))
	b.WriteByte('|')
	b.WriteString(f.ModuleID)
	b.WriteByte('|')
	b.WriteString(f.Rule)
	b.WriteByte('|')
	b.WriteString(strings.ToUpper(strings.TrimSpace(f.Method)))
	b.WriteByte('|')
	b.WriteString(CanonicalLocation(f.URL))
	b.WriteByte('|')
	b.WriteString(f.IPType)
	b.WriteByte(':')
	b.WriteString(f.Param)
	return b.String()
}

// CanonicalLocation reduces a URL to scheme://host[:port]/path: scheme and
// host lowercased, the scheme's default port dropped, query and fragment cut,
// an empty path read as "/". An unparseable value is returned with its query
// and fragment cut.
func CanonicalLocation(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// RequestMethod reads the method token from a raw HTTP request ("" when none).
func RequestMethod(rawRequest string) string {
	rawRequest = strings.TrimLeft(rawRequest, "\r\n ")
	if i := strings.IndexAny(rawRequest, " \t\r\n"); i > 0 {
		return strings.ToUpper(rawRequest[:i])
	}
	return ""
}

// usesLocationIdentity reports whether the event takes the v2 identity.
func (r *ResultEvent) usesLocationIdentity() bool {
	return r.DedupKey == "" && r.InsertionPointType != ""
}

// identityFields maps the event onto IdentityFields. The location is the
// unmutated item's URL the executor stamped (BaseURL); events from other paths
// fall back to URL, then Matched.
func (r *ResultEvent) identityFields() IdentityFields {
	loc := r.BaseURL
	if loc == "" {
		loc = r.URL
	}
	if loc == "" {
		loc = r.Matched
	}
	return IdentityFields{
		Kind:     r.EffectiveRecordKind(),
		ModuleID: r.ModuleID,
		Rule:     r.Info.Name,
		Method:   RequestMethod(r.Request),
		URL:      loc,
		IPType:   r.InsertionPointType,
		Param:    r.FuzzingParameter,
	}
}

// IdentityKey is the finding's identity in clear text: the DedupKey when the
// producer set one, the v2 location key for insertion-point findings, and the
// v1 content key (module|description|severity|matched) otherwise. ID() is its
// SHA-1, so two events with the same IdentityKey are the same finding. The
// DedupKey and v1 forms are byte-identical to the pre-v2 hash input, so those
// findings keep their stored hashes.
func (r *ResultEvent) IdentityKey() string {
	if r.usesLocationIdentity() {
		return IdentityPrefixV2 + IdentityKeyV2(r.identityFields())
	}
	kind := r.EffectiveRecordKind()
	if r.DedupKey != "" {
		var b strings.Builder
		writeKindPrefix(&b, kind)
		b.WriteString("dedup|")
		b.WriteString(r.DedupKey)
		return b.String()
	}
	return contentKeyV1(kind, r.ModuleID, r.Info.Description, r.Info.Severity.String(), r.Matched)
}

// writeKindPrefix prefixes a non-finding kind ("candidate|"), so a candidate
// can later be promoted without colliding with itself.
func writeKindPrefix(b *strings.Builder, kind RecordKind) {
	if kind != "" && kind != RecordKindFinding {
		b.WriteString(string(kind))
		b.WriteByte('|')
	}
}

// contentKeyV1 is the v1 content identity key:
// [kind|]module|description|severity|matched.
func contentKeyV1(kind RecordKind, moduleID, description, sev, matched string) string {
	var b strings.Builder
	b.Grow(len(kind) + len(moduleID) + len(description) + len(sev) + len(matched) + 5)
	writeKindPrefix(&b, kind)
	b.WriteString(moduleID)
	b.WriteByte('|')
	b.WriteString(description)
	b.WriteByte('|')
	b.WriteString(sev)
	b.WriteByte('|')
	b.WriteString(matched)
	return b.String()
}

// IdentityPrefixV2 marks a v2 identity key, so a v2 hash can never equal a v1
// one.
const IdentityPrefixV2 = "v2|"

// HashIdentity is the finding_hash of an identity key (SHA-1, hex).
func HashIdentity(key string) string {
	h := sha1Pool.Get().(hash.Hash)
	h.Reset()
	_, _ = io.WriteString(h, key)
	var buf [sha1.Size]byte
	id := hex.EncodeToString(h.Sum(buf[:0]))
	sha1Pool.Put(h)
	return id
}

// HashIdentityV2 is the v2 finding_hash for the given fields.
func HashIdentityV2(f IdentityFields) string {
	return HashIdentity(IdentityPrefixV2 + IdentityKeyV2(f))
}

// HashContentV1 is the pre-v2 content finding_hash: (kind prefix for
// non-findings) module|description|severity|matched. The store migration uses
// it to tell a content-hashed row (re-keyable) from a DedupKey row (kept).
func HashContentV1(kind RecordKind, moduleID, description, sev, matched string) string {
	return HashIdentity(contentKeyV1(kind, moduleID, description, sev, matched))
}
