// Package parampollution provides SHARED MUTATION INFRASTRUCTURE for HTTP
// Parameter Pollution (HPP) — crafting requests that carry the SAME parameter
// name more than once so a front-end (WAF / proxy / router) and the back-end
// application disagree about which occurrence is authoritative.
//
// It is deliberately NOT a finding-emitting module and NOT technology-gated. HPP
// is a delivery strategy, not a vulnerability: a consuming active module (e.g.
// sqli_boolean_blind) keeps its own tech/scope gates and its own confirmation
// bar, and only reaches for HPP as an additive fallback to change HOW a payload
// is delivered — never to lower the evidence required to confirm.
//
// # Wire-order fidelity
//
// The whole point of HPP is that duplicate parameters must survive on the wire
// in the exact order they were written — a parser discrepancy only exists
// because different components pick a different occurrence. Every builder here
// goes through httpmsg.AddParameter / AddMultipleParameters / BuildParameter,
// which APPEND raw name=value pairs in call order and never collapse or dedup
// duplicates. The map-based param helpers (SetBodyParametersMap, the *Map
// accessors) MUST NOT be used — a Go map would silently collapse the duplicate
// keys that are the entire mechanism.
//
// Values are URL-encoded for URL/body parameters (matching
// ParameterInsertionPoint.BuildRequest) so a payload containing spaces or quotes
// still yields a well-formed request line / body; benign ASCII values pass
// through unchanged.
package parampollution

import (
	"bytes"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// maxVariants caps how many pollution variants AllVariants / VariantInsertionPoints
// emit for a single insertion point, bounding the extra traffic a consumer spends
// on the fallback. The union of the default strategies for any single parameter
// stays under this cap; it is a defensive ceiling, not a target.
const maxVariants = 8

// Ordering describes which occurrence carries the attack payload on the wire.
const (
	// OrderingSafeFirst places the benign value first and the payload last
	// (x=safe&x=payload). Components that read the LAST occurrence (e.g. many
	// application frameworks / PHP $_GET) see the payload; a front-end that reads
	// the FIRST occurrence sees only the benign value.
	OrderingSafeFirst = "safe-first"
	// OrderingPayloadFirst places the payload first and the benign value last
	// (x=payload&x=safe). Mirrors OrderingSafeFirst for components that read the
	// FIRST occurrence (e.g. ASP.NET comma-joins, some routers/WAFs).
	OrderingPayloadFirst = "payload-first"
)

// Channels describes where the duplicated occurrences live.
const (
	ChannelQuery     = "query"
	ChannelBody      = "body"
	ChannelQueryBody = "query+body"
)

// Variant is one crafted HPP request: a human-readable Name, the Ordering and
// Channels that describe its shape, and the fully-built Raw request (wire-order
// preserved) with the payload substituted in the polluted slot.
type Variant struct {
	Name     string // e.g. "query-dup-payload-last"
	Ordering string // "safe-first" | "payload-first"
	Channels string // "query" | "body" | "query+body"
	Raw      []byte // crafted raw request, wire-order preserved
}

// Strategy is one family of parameter-pollution mutations. Applicable reports
// whether the strategy makes sense for the given insertion point (e.g. a
// query-duplicate only applies to a URL parameter); Variants builds the crafted
// requests for a concrete payload.
type Strategy interface {
	Applicable(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) bool
	Variants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant
}

// builder produces a polluted raw request that injects payload into the attack
// slot while keeping the benign value in the safe slot, preserving wire order.
type builder func(payload string) []byte

// variantSpec is the reusable recipe behind a Variant and a
// VariantInsertionPoint: the descriptive metadata plus a builder that can be
// re-invoked with any payload (so a consumer can drive its own confirmation
// battery through the same pollution channel, not just a single fixed payload).
type variantSpec struct {
	name     string
	ordering string
	channels string
	// pure marks a single-channel plain duplicate (name=a&name=b) as opposed to a
	// split or array variant. Consumers that need the two wire orderings of the
	// same duplicate (e.g. to probe whether ordering changes the response) select
	// on this rather than parsing the display name.
	pure  bool
	build builder
}

// specStrategy is the internal extension of Strategy that also exposes the
// reusable specs, so AllVariants and VariantInsertionPoints can share one source
// of truth with each strategy's public Variants method.
type specStrategy interface {
	Strategy
	specs(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []variantSpec
}

// DefaultStrategies returns the built-in pollution strategies in priority order.
//
// JSON-key duplication (two identical keys in a JSON body) is deliberately kept
// OUT of the default set: it targets last-write-wins JSON parsers specifically
// and is better suited to a deep/opt-in mode; add it as a follow-up strategy
// rather than paying its cost on every consumer.
func DefaultStrategies() []Strategy {
	return []Strategy{
		queryDuplicate{},
		bodyDuplicate{},
		queryBodySplit{},
		bracketArray{},
	}
}

// AllVariants returns the union of every applicable strategy's variants for one
// insertion point and payload, bounded at maxVariants.
func AllVariants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant {
	var out []Variant
	for _, s := range DefaultStrategies() {
		if !s.Applicable(req, ip) {
			continue
		}
		out = append(out, s.Variants(req, ip, payload)...)
		if len(out) >= maxVariants {
			return out[:maxVariants]
		}
	}
	return out
}

// CleanControl builds a request that duplicates the insertion point's parameter
// with TWO benign (base) values (x=base&x=base) in its native channel. A
// consumer sends this first: an endpoint that blocks, errors on, or mangles a
// purely benign duplicate handles duplicates hostilely, so any differential a
// polluted variant later produces would be a duplicate-handling artifact rather
// than the application's own logic — the consumer should skip HPP for that point.
//
// ok is false when the insertion point is not a URL or body parameter (the only
// channels these default strategies pollute).
func CleanControl(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) ([]byte, bool) {
	switch ip.Type() {
	case httpmsg.INS_PARAM_URL, httpmsg.INS_PARAM_BODY:
		safe := ip.BaseValue()
		pt := paramTypeForIP(ip)
		return buildDuplicate(baseRaw(req), ip.Name(), pt, safe, safe), true
	default:
		return nil, false
	}
}

// VariantInsertionPoints returns the applicable variants as InsertionPoints
// wrapping ip, bounded at maxVariants. Because each one satisfies
// httpmsg.InsertionPoint, a consuming module can drive its EXISTING confirmation
// logic — which calls ip.BuildRequest(payload) for arbitrary re-derived payloads
// — straight through the pollution channel with no changes to that logic.
func VariantInsertionPoints(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []VariantInsertionPoint {
	var out []VariantInsertionPoint
	for _, s := range DefaultStrategies() {
		if !s.Applicable(req, ip) {
			continue
		}
		ss, ok := s.(specStrategy)
		if !ok {
			continue
		}
		for _, spec := range ss.specs(req, ip) {
			out = append(out, VariantInsertionPoint{base: ip, spec: spec})
			if len(out) >= maxVariants {
				return out
			}
		}
	}
	return out
}

// ==================== VariantInsertionPoint ====================

// VariantInsertionPoint adapts a base InsertionPoint so that BuildRequest(payload)
// yields the HPP-polluted request for one fixed variant shape (strategy +
// ordering + channels), while Name/BaseValue/Type delegate to the base point.
// This lets a consumer swap a plain insertion point for a polluting one and reuse
// its entire differential + confirmation battery unchanged.
type VariantInsertionPoint struct {
	base httpmsg.InsertionPoint
	spec variantSpec
}

// Name returns the base parameter name (unchanged, so findings still attribute to it).
func (v VariantInsertionPoint) Name() string { return v.base.Name() }

// BaseValue returns the base parameter's original value.
func (v VariantInsertionPoint) BaseValue() string { return v.base.BaseValue() }

// Type returns the base insertion point type (so consumer type checks — e.g.
// header vs param — behave exactly as on the plain point).
func (v VariantInsertionPoint) Type() httpmsg.InsertionPointType { return v.base.Type() }

// BuildRequest builds the polluted request injecting payload into this variant's
// attack slot.
func (v VariantInsertionPoint) BuildRequest(payload []byte) []byte {
	return v.spec.build(string(payload))
}

// PayloadOffsets returns the byte range of the (URL-encoded) payload's last
// occurrence in the built request, best-effort. HPP is not on a response-offset
// hot path; consumers that need exact offsets should not rely on this.
func (v VariantInsertionPoint) PayloadOffsets(payload []byte) []int {
	built := v.spec.build(string(payload))
	enc := httpmsg.EncodeQueryValue(string(payload))
	idx := bytes.LastIndex(built, []byte(enc))
	if idx < 0 {
		return nil
	}
	return []int{idx, idx + len(enc)}
}

// VariantName returns the descriptive variant name (e.g. "query-dup-payload-last").
func (v VariantInsertionPoint) VariantName() string { return v.spec.name }

// Ordering returns the wire ordering ("safe-first" | "payload-first").
func (v VariantInsertionPoint) Ordering() string { return v.spec.ordering }

// Channels returns the polluted channel(s) ("query" | "body" | "query+body").
func (v VariantInsertionPoint) Channels() string { return v.spec.channels }

// IsPureDuplicate reports whether this is a single-channel plain duplicate
// (name=a&name=b), as opposed to a query/body split or an array variant.
func (v VariantInsertionPoint) IsPureDuplicate() bool { return v.spec.pure }

// ==================== strategies ====================

// queryDuplicate duplicates a URL query parameter with the two orderings.
type queryDuplicate struct{}

func (queryDuplicate) Applicable(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) bool {
	return ip.Type() == httpmsg.INS_PARAM_URL
}

func (s queryDuplicate) specs(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []variantSpec {
	if !s.Applicable(req, ip) {
		return nil
	}
	raw, name, safe := baseRaw(req), ip.Name(), ip.BaseValue()
	return []variantSpec{
		{
			name: "query-dup-payload-last", ordering: OrderingSafeFirst, channels: ChannelQuery, pure: true,
			build: func(p string) []byte { return buildDuplicate(raw, name, httpmsg.ParamURL, safe, p) },
		},
		{
			name: "query-dup-payload-first", ordering: OrderingPayloadFirst, channels: ChannelQuery, pure: true,
			build: func(p string) []byte { return buildDuplicate(raw, name, httpmsg.ParamURL, p, safe) },
		},
	}
}

func (s queryDuplicate) Variants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant {
	return specsToVariants(s.specs(req, ip), payload)
}

// bodyDuplicate duplicates a form-body parameter with the two orderings.
type bodyDuplicate struct{}

func (bodyDuplicate) Applicable(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) bool {
	return ip.Type() == httpmsg.INS_PARAM_BODY
}

func (s bodyDuplicate) specs(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []variantSpec {
	if !s.Applicable(req, ip) {
		return nil
	}
	raw, name, safe := baseRaw(req), ip.Name(), ip.BaseValue()
	return []variantSpec{
		{
			name: "body-dup-payload-last", ordering: OrderingSafeFirst, channels: ChannelBody, pure: true,
			build: func(p string) []byte { return buildDuplicate(raw, name, httpmsg.ParamBody, safe, p) },
		},
		{
			name: "body-dup-payload-first", ordering: OrderingPayloadFirst, channels: ChannelBody, pure: true,
			build: func(p string) []byte { return buildDuplicate(raw, name, httpmsg.ParamBody, p, safe) },
		},
	}
}

func (s bodyDuplicate) Variants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant {
	return specsToVariants(s.specs(req, ip), payload)
}

// queryBodySplit puts the same parameter name in the query and the body at once —
// the classic proxy/backend split where one component reads the query copy and
// the other the body copy.
type queryBodySplit struct{}

func (queryBodySplit) Applicable(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) bool {
	if ip.Type() != httpmsg.INS_PARAM_URL && ip.Type() != httpmsg.INS_PARAM_BODY {
		return false
	}
	return bodyAllowed(req)
}

func (s queryBodySplit) specs(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []variantSpec {
	if !s.Applicable(req, ip) {
		return nil
	}
	raw, name, safe := baseRaw(req), ip.Name(), ip.BaseValue()
	return []variantSpec{
		{
			// safe in the query, payload in the body.
			name: "split-payload-in-body", ordering: OrderingSafeFirst, channels: ChannelQueryBody,
			build: func(p string) []byte { return buildSplit(raw, name, safe, p) },
		},
		{
			// payload in the query, safe in the body.
			name: "split-payload-in-query", ordering: OrderingPayloadFirst, channels: ChannelQueryBody,
			build: func(p string) []byte { return buildSplit(raw, name, p, safe) },
		},
	}
}

func (s queryBodySplit) Variants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant {
	return specsToVariants(s.specs(req, ip), payload)
}

// bracketArray expresses the duplicate as an array — x[]=safe&x[]=payload and
// x[0]=safe&x[1]=payload — which frameworks that auto-cast array params to a
// scalar (taking the last element, or stringifying) resolve differently from a
// front-end that only inspects the bare name.
type bracketArray struct{}

func (bracketArray) Applicable(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) bool {
	return ip.Type() == httpmsg.INS_PARAM_URL || ip.Type() == httpmsg.INS_PARAM_BODY
}

func (s bracketArray) specs(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) []variantSpec {
	if !s.Applicable(req, ip) {
		return nil
	}
	raw, name, safe := baseRaw(req), ip.Name(), ip.BaseValue()
	pt := paramTypeForIP(ip)
	ch := ChannelQuery
	if pt == httpmsg.ParamBody {
		ch = ChannelBody
	}
	return []variantSpec{
		{
			name: "array-brackets", ordering: OrderingSafeFirst, channels: ch,
			build: func(p string) []byte {
				return buildArray(raw, name, pt, name+"[]", safe, name+"[]", p)
			},
		},
		{
			name: "array-indexed", ordering: OrderingSafeFirst, channels: ch,
			build: func(p string) []byte {
				return buildArray(raw, name, pt, name+"[0]", safe, name+"[1]", p)
			},
		},
	}
}

func (s bracketArray) Variants(req *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, payload string) []Variant {
	return specsToVariants(s.specs(req, ip), payload)
}

// ==================== raw builders ====================

// buildDuplicate returns raw with parameter name (of type pt) duplicated with two
// values in wire order (first then second). It strips any existing occurrence of
// name first, then appends both values via AddMultipleParameters, which never
// collapses or reorders duplicates.
func buildDuplicate(raw []byte, name string, pt httpmsg.ParamType, first, second string) []byte {
	cleaned := removeParam(raw, name, pt)
	out, err := httpmsg.AddMultipleParameters(cleaned, []*httpmsg.Param{
		httpmsg.BuildParameter(name, encode(first), pt),
		httpmsg.BuildParameter(name, encode(second), pt),
	})
	if err != nil || len(out) == 0 {
		return raw
	}
	return out
}

// buildSplit returns raw with name present once in the query (queryVal) and once
// in the body (bodyVal), after removing any existing occurrence in either channel.
func buildSplit(raw []byte, name, queryVal, bodyVal string) []byte {
	cleaned := removeParam(removeParam(raw, name, httpmsg.ParamURL), name, httpmsg.ParamBody)
	withQuery, err := httpmsg.AddParameter(cleaned, httpmsg.BuildParameter(name, encode(queryVal), httpmsg.ParamURL))
	if err != nil || len(withQuery) == 0 {
		withQuery = cleaned
	}
	out, err := httpmsg.AddParameter(withQuery, httpmsg.BuildParameter(name, encode(bodyVal), httpmsg.ParamBody))
	if err != nil || len(out) == 0 {
		return withQuery
	}
	return out
}

// buildArray returns raw with the base name removed and two bracketed names added
// in order (n1=v1 then n2=v2) in the given channel.
func buildArray(raw []byte, base string, pt httpmsg.ParamType, n1, v1, n2, v2 string) []byte {
	cleaned := removeParam(raw, base, pt)
	out, err := httpmsg.AddMultipleParameters(cleaned, []*httpmsg.Param{
		httpmsg.BuildParameter(n1, encode(v1), pt),
		httpmsg.BuildParameter(n2, encode(v2), pt),
	})
	if err != nil || len(out) == 0 {
		return raw
	}
	return out
}

// removeParam removes every occurrence of name (of type pt) from raw, returning
// raw unchanged on error. RemoveParameter matches by name over the raw query /
// body string and does not touch other parameters.
func removeParam(raw []byte, name string, pt httpmsg.ParamType) []byte {
	out, err := httpmsg.RemoveParameter(raw, httpmsg.BuildParameter(name, "", pt))
	if err != nil || len(out) == 0 {
		return raw
	}
	return out
}

// encode URL-encodes a value so a payload with spaces/quotes stays wire-safe;
// benign ASCII (letters, digits, - _ . ~) passes through unchanged.
func encode(v string) string { return httpmsg.EncodeQueryValue(v) }

// paramTypeForIP maps an insertion point's type to the parameter type used to
// build duplicates (URL or body).
func paramTypeForIP(ip httpmsg.InsertionPoint) httpmsg.ParamType {
	return httpmsg.InsertionPointTypeToParamType(ip.Type())
}

// baseRaw returns the request's raw bytes (nil-safe).
func baseRaw(req *httpmsg.HttpRequestResponse) []byte {
	if req == nil || req.Request() == nil {
		return nil
	}
	return req.Request().Raw()
}

// bodyAllowed reports whether it is meaningful to place a parameter in the body:
// either a body already exists, or the method conventionally carries one.
func bodyAllowed(req *httpmsg.HttpRequestResponse) bool {
	if req == nil || req.Request() == nil {
		return false
	}
	if len(req.Request().Body()) > 0 {
		return true
	}
	switch strings.ToUpper(req.Request().Method()) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// specsToVariants materializes each spec into a Variant for the given payload.
func specsToVariants(specs []variantSpec, payload string) []Variant {
	if len(specs) == 0 {
		return nil
	}
	out := make([]Variant, 0, len(specs))
	for _, s := range specs {
		out = append(out, Variant{
			Name:     s.name,
			Ordering: s.ordering,
			Channels: s.channels,
			Raw:      s.build(payload),
		})
	}
	return out
}
