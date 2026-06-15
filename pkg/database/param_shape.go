package database

import (
	"net/url"
	"sort"
	"strings"
)

// DefaultMaxParamShapeSamples is the per-shape representative cap used when
// param-shape coalescing is enabled without an explicit override.
const DefaultMaxParamShapeSamples = 3

// recordURLDesc is the minimal per-record info param-shape coalescing needs. The
// stored Params (extracted insertion points, name+type+value) let us shape POST/
// PUT/PATCH and JSON bodies without the raw request body — only their content type
// and length are read alongside the URL.
type recordURLDesc struct {
	method        string
	url           string
	contentType   string
	contentLength int64
	params        []EmbeddedParam
}

// paramShapeRepresentative decides whether a record participates in param-shape
// coalescing and, if so, returns its grouping key (host + path + method + sorted
// coalescable param NAMES, values ignored) and a value signature (sorted
// name=value pairs).
//
// Coalescable params are the "same endpoint, varying values" fan-out inputs: URL
// query params (read from the URL) plus form ("body") and JSON params (read from
// the stored parameter list). Cookie/header params are auth/session churn rather
// than endpoint fan-out; path params already separate records via the path
// component of the key; xml params we don't flatten reliably — all excluded.
//
// The hard safety rule is preserved from the GET-only original: coalescing must
// never drop a request whose body we cannot fully see. A body-bearing method
// (POST/PUT/PATCH) or a non-zero request body with NO stored form/JSON params
// means there is an unseen payload that could differ between records, so the
// record is kept (coalescable=false). Multipart bodies (file uploads carry binary
// not captured as a param value) are never coalesced.
func paramShapeRepresentative(d recordURLDesc) (shapeKey, valueSig string, coalescable bool) {
	method := strings.ToUpper(strings.TrimSpace(d.method))
	u, err := url.Parse(d.url)
	if err != nil {
		return "", "", false
	}
	if strings.Contains(strings.ToLower(d.contentType), "multipart/") {
		return "", "", false
	}

	type pv struct{ key, val string }
	var collected []pv

	// u.Query() allocates a map even for an empty query; skip it when the URL
	// carries no query string (the common case for body-bearing requests).
	if u.RawQuery != "" {
		for name, vals := range u.Query() {
			sorted := append([]string(nil), vals...)
			sort.Strings(sorted)
			collected = append(collected, pv{"u:" + name, strings.Join(sorted, ",")})
		}
	}

	hasSeenBody := false
	for _, p := range d.params {
		switch p.Type {
		case "body":
			collected = append(collected, pv{"b:" + p.Name, p.Value})
			hasSeenBody = true
		case "json":
			collected = append(collected, pv{"j:" + p.Name, p.Value})
			hasSeenBody = true
		}
	}

	bodyBearing := method == "POST" || method == "PUT" || method == "PATCH"
	if (bodyBearing || d.contentLength > 0) && !hasSeenBody {
		return "", "", false // unseen body — never coalesce
	}
	if len(collected) == 0 {
		return "", "", false // nothing varies that we can key on
	}

	sort.Slice(collected, func(i, j int) bool { return collected[i].key < collected[j].key })

	const sep = "\x00"
	names := make([]string, len(collected))
	pairs := make([]string, len(collected))
	for i, c := range collected {
		names[i] = c.key
		pairs[i] = c.key + "=" + c.val
	}
	shapeKey = strings.ToLower(u.Host) + sep + u.Path + sep + method + sep + strings.Join(names, ",")
	valueSig = strings.Join(pairs, "&")
	return shapeKey, valueSig, true
}

// coalesceUUIDsByParamShape walks uuids in their given (priority) order and
// keeps at most maxSamples value-distinct representatives per param shape,
// dropping identical-value duplicates and the long tail beyond the cap. Records
// not present in descByUUID, and any request that is not a coalescable GET, are
// always kept. Order is preserved, so when the input is risk-prioritized the
// highest-value records claim the per-shape sample slots first.
//
// maxSamples <= 0 disables coalescing (returns the input unchanged).
func coalesceUUIDsByParamShape(uuids []string, descByUUID map[string]recordURLDesc, maxSamples int) (kept []string, dropped int) {
	if maxSamples <= 0 || len(uuids) == 0 {
		return uuids, 0
	}
	seenByShape := make(map[string]map[string]struct{})
	kept = make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		d, ok := descByUUID[uuid]
		if !ok {
			kept = append(kept, uuid)
			continue
		}
		shapeKey, valueSig, coalescable := paramShapeRepresentative(d)
		if !coalescable {
			kept = append(kept, uuid)
			continue
		}
		seen := seenByShape[shapeKey]
		if seen == nil {
			seen = make(map[string]struct{})
			seenByShape[shapeKey] = seen
		}
		if _, dup := seen[valueSig]; dup {
			dropped++ // identical query values as an already-kept representative
			continue
		}
		if len(seen) >= maxSamples {
			dropped++ // per-shape sample cap reached
			continue
		}
		seen[valueSig] = struct{}{}
		kept = append(kept, uuid)
	}
	return kept, dropped
}
