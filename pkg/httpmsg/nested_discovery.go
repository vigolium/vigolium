package httpmsg

// nested_discovery.go - Nested parameter discovery for insertion points
//
// This file provides functionality to discover nested parameters within
// parameter values (e.g., JSON embedded in URL params, Base64-encoded data).

import (
	"bytes"
	"net/url"
	"strings"
)

// DiscoverNestedInsertionPoints analyzes parameters for nested structures and creates
// nested insertion points by reusing existing parsers.
//
// Prefer discoverNestedInsertionPointsShared when a *sharedBaseRequest is already
// in hand; this entry point exists for callers holding only raw bytes and simply
// wraps them.
func DiscoverNestedInsertionPoints(request []byte, params []*Param) []*NestedInsertionPoint {
	return discoverNestedInsertionPointsShared(newSharedBaseRequest(bytes.Clone(request)), params)
}

// discoverNestedInsertionPointsShared creates nested insertion points for every
// parameter whose value is itself a structured document, reusing one shared base
// request across all of them.
func discoverNestedInsertionPointsShared(shared *sharedBaseRequest, params []*Param) []*NestedInsertionPoint {
	discovered := make([]*NestedInsertionPoint, 0)

	for _, param := range params {
		nestedIPs := createNestedShared(shared, param, DetectParameterFormat(param.Value()))
		if len(nestedIPs) == 0 {
			continue
		}
		// Adopt the first batch wholesale rather than growing from empty: a
		// request with one large structured parameter is the common shape, and
		// this is the whole allocation in that case.
		if len(discovered) == 0 {
			discovered = nestedIPs
			continue
		}
		discovered = append(discovered, nestedIPs...)
	}

	return discovered
}

// encoderForFormat maps a nested document format to the encoder and insertion
// point type its children are addressed through. Shared by the direct formats and
// by the base64 path, which resolves the format of its decoded payload.
func encoderForFormat(format ParameterFormat) (Encoder, InsertionPointType) {
	switch format {
	case FormatXML:
		return &NoopEncoder{}, INS_PARAM_XML
	case FormatURLEncoded:
		return &URLEncoder{}, INS_PARAM_URL
	default: // FormatJSON, and the conservative fallback for anything else
		return &JSONEscapeEncoder{}, INS_PARAM_JSON
	}
}

// parseNested parses buf according to format, returning the child parameters it
// contains. A format with no structured parser returns nil.
func parseNested(buf []byte, format ParameterFormat) []*Param {
	var params []*Param
	switch format {
	case FormatJSON:
		params, _ = ParseJSONBody(buf, 0)
	case FormatXML:
		params, _ = ParseXMLBody(buf, 0)
	case FormatURLEncoded:
		params, _ = ParseURLEncodedBody(buf, 0)
	}
	return params
}

// createNestedShared builds the nested insertion points for one structured
// parameter value, resolving the buffer the children are addressed against.
//
// For base64 the addressable buffer is the *decoded* payload and the format is
// whatever that payload turns out to be; for the direct formats it is the
// parameter value itself.
func createNestedShared(shared *sharedBaseRequest, parentParam *Param, format ParameterFormat) []*NestedInsertionPoint {
	var childBuf []byte
	var layers []Encoder

	switch format {
	case FormatNone:
		return nil

	case FormatBase64:
		decoded, variant, ok := decodeBase64Variant(strings.TrimSpace(parentParam.Value()))
		if !ok {
			return nil
		}
		if format = DetectParameterFormat(string(decoded)); format == FormatNone {
			return nil
		}
		childBuf = decoded
		// Re-apply the base64 layer — in the variant it was found in — on the
		// way out; without it the child document went back raw.
		layers = []Encoder{variant.encoder()}

	case FormatURLEncoded:
		decoded, err := url.QueryUnescape(parentParam.Value())
		if err != nil {
			return nil
		}
		childBuf = []byte(decoded)

	default:
		childBuf = []byte(parentParam.Value())
	}

	encoder, ipType := encoderForFormat(format)
	nested := nestedFromParsed(shared, parentParam, childBuf, parseNested(childBuf, format), encoder, ipType)
	for _, n := range nested {
		n.layers = layers
	}
	return nested
}

// nestedFromParsed pairs each parsed child with its parent into a nested
// insertion point.
//
// childBuf is materialized once by the caller and SHARED by every child (see
// newEncodedInsertionPointShared) — cloning it per child made retained memory
// quadratic in the child count.
//
// The parent insertion point, by contrast, is deliberately built fresh per child
// and must not be hoisted out of the loop: splitIntoNonConflictingGroups keys its
// payload and same-parent maps on the parent InsertionPoint's pointer identity,
// so collapsing N children onto one parent would merge those map entries and
// change which requests get built.
func nestedFromParsed(shared *sharedBaseRequest, parentParam *Param, childBuf []byte, children []*Param, encoder Encoder, ipType InsertionPointType) []*NestedInsertionPoint {
	if len(children) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0, len(children))

	for _, child := range children {
		if child.ValueStart() < 0 ||
			child.ValueEnd() < 0 ||
			child.ValueEnd() > len(childBuf) ||
			child.ValueStart() > child.ValueEnd() {
			continue
		}

		parentIP := newParameterInsertionPointShared(shared, parentParam)
		childIP := newEncodedInsertionPointShared(
			child.Name(),
			childBuf,
			child.ValueStart(),
			child.ValueEnd(),
			encoder,
			ipType,
		)

		nestedIPs = append(nestedIPs, newNestedInsertionPointShared(shared, parentIP, childIP))
	}

	return nestedIPs
}
