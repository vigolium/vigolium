package httpmsg

// insertion_point_extra.go - opt-in insertion points CreateAllInsertionPoints
// never builds: parameter NAMES, the entire body, and a synthetic new parameter.
//
// They are opt-in because the scanner's active modules mostly accept every
// insertion-point type (AllInsertionPointTypes) and the URL/body param type sets
// already include the name types, so emitting them by default would roughly
// double per-insertion-point work across the module set. `vigolium fuzz` asks
// for them explicitly through CreateInsertionPoints.
//
// Two different "parameter name" semantics live here and stay distinct:
//   - ParamNameInsertionPoint RENAMES an existing parameter: ?id=1 → ?<payload>=1.
//   - NewParamInsertionPoint ADDS one (Arjun-style discovery): ?id=1 → ?id=1&<payload>=<canary>.

import (
	"bytes"
	"encoding/json"
	"strings"
)

// IsExtraInsertionPointType reports whether t is one of the opt-in types the
// scanner builds but no module receives unless it asks: parameter names and
// the entire body.
func IsExtraInsertionPointType(t InsertionPointType) bool {
	return t == INS_PARAM_NAME_URL || t == INS_PARAM_NAME_BODY || t == INS_ENTIRE_BODY
}

// NewParamLocation says where a NewParamInsertionPoint adds its parameter.
type NewParamLocation string

const (
	// NewParamAuto picks the location from the request: a JSON body gets a
	// JSON key, a form body (or any body-bearing method with a body) gets a
	// form field, everything else gets a query parameter.
	NewParamAuto NewParamLocation = ""
	// NewParamQuery appends name=value to the query string.
	NewParamQuery NewParamLocation = "query"
	// NewParamBody appends name=value to an application/x-www-form-urlencoded body.
	NewParamBody NewParamLocation = "body"
	// NewParamJSON adds a top-level "name":"value" key to a JSON object body.
	NewParamJSON NewParamLocation = "json"
)

// DefaultNewParamValue is the canary value a NewParamInsertionPoint gives the
// parameter it adds when NewParamSpec.Value is empty. Distinctive enough to
// spot when reflected, plain enough to pass type checks on a string field.
const DefaultNewParamValue = "vigolium7c4n4ry"

// NewParamSpec configures the synthetic new-parameter insertion point.
type NewParamSpec struct {
	Location NewParamLocation
	// Value is the value the added parameter carries; the payload is its name.
	// Empty means DefaultNewParamValue.
	Value string
}

// InsertionPointOptions selects which insertion points CreateInsertionPoints
// builds. The zero value builds exactly what CreateAllInsertionPoints(req,
// false) builds: parameter values, cookies and headers.
type InsertionPointOptions struct {
	// IncludeNested also discovers nested values (JSON/XML/Base64 inside params).
	IncludeNested bool
	// ParamNames adds a rename point (INS_PARAM_NAME_URL / INS_PARAM_NAME_BODY)
	// for every URL query parameter and form-body parameter. JSON keys are not
	// covered: their offsets only exist through nested discovery.
	ParamNames bool
	// EntireBody adds one INS_ENTIRE_BODY point when the request has a body.
	EntireBody bool
	// NewParam, when non-nil, adds one synthetic point whose payload becomes the
	// NAME of a parameter appended to the request.
	NewParam *NewParamSpec
}

// CreateInsertionPoints builds the insertion points o selects.
// CreateAllInsertionPoints is the zero-extras wrapper the scanner uses.
func CreateInsertionPoints(request []byte, o InsertionPointOptions) ([]InsertionPoint, error) {
	return createInsertionPoints(request, o)
}

// ResolveNewParamLocation returns the concrete location NewParamAuto stands for
// on request.
func ResolveNewParamLocation(request []byte, loc NewParamLocation) NewParamLocation {
	if loc != NewParamAuto {
		return loc
	}
	ct, _ := GetContentType(request)
	ct = strings.ToLower(ct)
	body, _ := GetBody(request)
	switch {
	case strings.Contains(ct, "json"):
		return NewParamJSON
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return NewParamBody
	case len(bytes.TrimSpace(body)) > 0 && json.Valid(body) && bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")):
		return NewParamJSON
	case len(body) > 0:
		return NewParamBody
	default:
		return NewParamQuery
	}
}

// extraInsertionPoints builds the opt-in points for createInsertionPoints.
func extraInsertionPoints(shared *sharedBaseRequest, params []*Param, o InsertionPointOptions) []InsertionPoint {
	var out []InsertionPoint
	if o.ParamNames {
		for _, p := range params {
			switch p.Type() {
			case ParamURL, ParamBody:
				out = append(out, &ParamNameInsertionPoint{base: shared.raw, param: p})
			}
		}
	}
	if o.EntireBody {
		if body, err := GetBody(shared.raw); err == nil && len(body) > 0 {
			out = append(out, &EntireBodyInsertionPoint{base: shared.raw, original: string(body)})
		}
	}
	if o.NewParam != nil {
		value := o.NewParam.Value
		if value == "" {
			value = DefaultNewParamValue
		}
		out = append(out, &NewParamInsertionPoint{
			base:     shared.raw,
			location: ResolveNewParamLocation(shared.raw, o.NewParam.Location),
			value:    value,
		})
	}
	return out
}

// ==================== PARAMETER NAME (rename) ====================

// ParamNameInsertionPoint replaces an existing URL or form-body parameter's
// NAME with the payload, keeping its value.
type ParamNameInsertionPoint struct {
	base  []byte
	param *Param
}

// Name returns the parameter's original name.
func (p *ParamNameInsertionPoint) Name() string { return p.param.Name() }

// BaseValue is the original name: it is what sits at this position.
func (p *ParamNameInsertionPoint) BaseValue() string { return p.param.Name() }

// Type is INS_PARAM_NAME_URL for query parameters, INS_PARAM_NAME_BODY for
// form-body ones.
func (p *ParamNameInsertionPoint) Type() InsertionPointType {
	if p.param.Type() == ParamBody {
		return INS_PARAM_NAME_BODY
	}
	return INS_PARAM_NAME_URL
}

// BuildRequest splices the URL-encoded payload over the name span and, for a
// body parameter, refreshes Content-Length.
func (p *ParamNameInsertionPoint) BuildRequest(payload []byte) []byte {
	out := spliceBytes(p.base, p.param.NameStart(), p.param.NameEnd(), EncodeQueryValueBytes(payload))
	if p.param.Type() == ParamBody {
		if updated, err := UpdateContentLength(out); err == nil {
			out = updated
		}
	}
	return out
}

// PayloadOffsets returns the encoded payload's span in the built request. The
// name precedes the body, so a Content-Length rewrite before it shifts it by
// the length delta; locating it by search keeps that honest.
func (p *ParamNameInsertionPoint) PayloadOffsets(payload []byte) []int {
	enc := EncodeQueryValueBytes(payload)
	built := p.BuildRequest(payload)
	from := p.param.NameStart()
	if from > len(built) {
		from = 0
	}
	if i := bytes.Index(built[from:], enc); i >= 0 {
		return []int{from + i, from + i + len(enc)}
	}
	return nil
}

// ==================== ENTIRE BODY ====================

// EntireBodyInsertionPoint replaces the whole request body with the payload and
// refreshes Content-Length.
type EntireBodyInsertionPoint struct {
	base     []byte
	original string
}

// Name is the fixed label "body".
func (e *EntireBodyInsertionPoint) Name() string { return "body" }

// BaseValue is the original body.
func (e *EntireBodyInsertionPoint) BaseValue() string { return e.original }

// Type is INS_ENTIRE_BODY.
func (e *EntireBodyInsertionPoint) Type() InsertionPointType { return INS_ENTIRE_BODY }

// BuildRequest swaps the body, patching Content-Length in place when the
// request has exactly one, and rebuilding it otherwise.
func (e *EntireBodyInsertionPoint) BuildRequest(payload []byte) []byte {
	if out, ok := replaceBodyWithCL(e.base, payload); ok {
		return out
	}
	out, err := SetBody(e.base, payload)
	if err != nil {
		return bytes.Clone(e.base)
	}
	return out
}

// PayloadOffsets returns the body span of the built request.
func (e *EntireBodyInsertionPoint) PayloadOffsets(payload []byte) []int {
	built := e.BuildRequest(payload)
	start := findBodyOffsetStrict(built, 0)
	if start < 0 {
		return nil
	}
	return []int{start, start + len(payload)}
}

// ==================== NEW PARAMETER (add) ====================

// NewParamInsertionPoint adds a parameter that is not in the request: the
// payload is the new parameter's NAME and the value is a fixed canary. This is
// parameter discovery (Arjun's semantics) expressed as an insertion point, so
// fuzz's baseline, calibration and anomaly machinery apply unchanged.
type NewParamInsertionPoint struct {
	base     []byte
	location NewParamLocation
	value    string
}

// Name is "<new>": there is no existing parameter to name.
func (n *NewParamInsertionPoint) Name() string { return "<new>" }

// BaseValue is empty: nothing is at this position before injection.
func (n *NewParamInsertionPoint) BaseValue() string { return "" }

// Location reports where the parameter is added (never NewParamAuto).
func (n *NewParamInsertionPoint) Location() NewParamLocation { return n.location }

// Value reports the canary the added parameter carries.
func (n *NewParamInsertionPoint) Value() string { return n.value }

// Type is INS_PARAM_NAME_URL for the query location and INS_PARAM_NAME_BODY
// for the body locations.
func (n *NewParamInsertionPoint) Type() InsertionPointType {
	if n.location == NewParamQuery {
		return INS_PARAM_NAME_URL
	}
	return INS_PARAM_NAME_BODY
}

// BuildRequest appends `<payload>=<value>` at the configured location. A
// request it cannot rewrite comes back unchanged rather than half-built.
func (n *NewParamInsertionPoint) BuildRequest(payload []byte) []byte {
	name := string(payload)
	switch n.location {
	case NewParamBody:
		body, err := GetBody(n.base)
		if err != nil {
			return bytes.Clone(n.base)
		}
		pair := EncodeQueryValue(name) + "=" + EncodeQueryValue(n.value)
		var nb []byte
		if len(bytes.TrimSpace(body)) == 0 {
			nb = []byte(pair)
		} else {
			nb = make([]byte, 0, len(body)+1+len(pair))
			nb = append(nb, body...)
			nb = append(nb, '&')
			nb = append(nb, pair...)
		}
		return n.withBody(nb, "application/x-www-form-urlencoded")
	case NewParamJSON:
		body, err := GetBody(n.base)
		if err != nil {
			return bytes.Clone(n.base)
		}
		return n.withBody(addJSONKey(body, name, n.value), "application/json")
	default:
		out, err := AppendURLParameter(n.base, name, n.value)
		if err != nil {
			return bytes.Clone(n.base)
		}
		return out
	}
}

// withBody installs body (refreshing Content-Length) and supplies a
// Content-Type when the request carries none, so the server parses the field.
func (n *NewParamInsertionPoint) withBody(body []byte, contentType string) []byte {
	req := n.base
	if ct, _ := GetContentType(req); ct == "" {
		if updated, err := AddOrReplaceHeader(req, "Content-Type", contentType); err == nil {
			req = updated
		}
	}
	if out, ok := replaceBodyWithCL(req, body); ok {
		return out
	}
	out, err := SetBody(req, body)
	if err != nil {
		return bytes.Clone(n.base)
	}
	return out
}

// PayloadOffsets returns the span of the added name in the built request (the
// last occurrence: the parameter is always appended).
func (n *NewParamInsertionPoint) PayloadOffsets(payload []byte) []int {
	built := n.BuildRequest(payload)
	needle := payload
	switch n.location {
	case NewParamQuery, NewParamBody:
		needle = EncodeQueryValueBytes(payload)
	}
	if n.location == NewParamQuery {
		line := built
		if nl := bytes.IndexByte(built, '\n'); nl >= 0 {
			line = built[:nl]
		}
		if i := bytes.LastIndex(line, needle); i >= 0 {
			return []int{i, i + len(needle)}
		}
		return nil
	}
	if i := bytes.LastIndex(built, needle); i >= 0 {
		return []int{i, i + len(needle)}
	}
	return nil
}

// addJSONKey adds "name":"value" as the last member of a JSON object body. An
// empty or non-object body becomes a one-member object: there is nothing to
// preserve that a top-level key could live in.
func addJSONKey(body []byte, name, value string) []byte {
	k, _ := json.Marshal(name)
	v, _ := json.Marshal(value)
	member := append(append(append([]byte{}, k...), ':'), v...)

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !json.Valid(trimmed) {
		return append(append([]byte{'{'}, member...), '}')
	}
	// Splice before the closing brace of the original bytes, keeping any
	// trailing whitespace after it.
	end := bytes.LastIndexByte(body, '}')
	inner := bytes.TrimSpace(trimmed[1 : len(trimmed)-1])
	out := make([]byte, 0, len(body)+len(member)+1)
	out = append(out, body[:end]...)
	if len(inner) > 0 {
		out = append(out, ',')
	}
	out = append(out, member...)
	out = append(out, body[end:]...)
	return out
}
