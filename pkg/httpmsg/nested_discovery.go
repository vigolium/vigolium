package httpmsg

// nested_discovery.go - Nested parameter discovery for insertion points
//
// This file provides functionality to discover nested parameters within
// parameter values (e.g., JSON embedded in URL params, Base64-encoded data).

import (
	"encoding/base64"
	"net/url"
)

// DiscoverNestedInsertionPoints analyzes parameters for nested structures and creates
// nested insertion points by reusing existing parsers.
func DiscoverNestedInsertionPoints(request []byte, params []*Param) []*NestedInsertionPoint {
	discovered := make([]*NestedInsertionPoint, 0)

	for _, param := range params {
		format := DetectParameterFormat(param.Value())
		if format == FormatNone {
			continue
		}

		var nestedIPs []*NestedInsertionPoint

		switch format {
		case FormatJSON:
			nestedIPs = createNestedFromJSON(request, param)
		case FormatXML:
			nestedIPs = createNestedFromXML(request, param)
		case FormatURLEncoded:
			nestedIPs = createNestedFromURLEncoded(request, param)
		case FormatBase64:
			nestedIPs = createNestedFromBase64(request, param)
		}

		discovered = append(discovered, nestedIPs...)
	}

	return discovered
}

// discoverNestedInsertionPointsShared is like DiscoverNestedInsertionPoints but uses a
// shared base request reference for parent insertion points to avoid redundant clones.
func discoverNestedInsertionPointsShared(shared *sharedBaseRequest, params []*Param) []*NestedInsertionPoint {
	discovered := make([]*NestedInsertionPoint, 0)

	for _, param := range params {
		format := DetectParameterFormat(param.Value())
		if format == FormatNone {
			continue
		}

		var nestedIPs []*NestedInsertionPoint

		switch format {
		case FormatJSON:
			nestedIPs = createNestedFromJSONShared(shared, param)
		case FormatXML:
			nestedIPs = createNestedFromXMLShared(shared, param)
		case FormatURLEncoded:
			nestedIPs = createNestedFromURLEncodedShared(shared, param)
		case FormatBase64:
			nestedIPs = createNestedFromBase64Shared(shared, param)
		}

		discovered = append(discovered, nestedIPs...)
	}

	return discovered
}

// createNestedFromJSONShared uses shared base request for the parent insertion point.
func createNestedFromJSONShared(shared *sharedBaseRequest, parentParam *Param) []*NestedInsertionPoint {
	nestedParams, err := ParseJSONBody([]byte(parentParam.Value()), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(parentParam.Value()) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := newParameterInsertionPointShared(shared, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(parentParam.Value()),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&JSONEscapeEncoder{},
			nil,
			INS_PARAM_JSON,
		)

		nestedIP := newNestedInsertionPointShared(shared, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromXMLShared uses shared base request for the parent insertion point.
func createNestedFromXMLShared(shared *sharedBaseRequest, parentParam *Param) []*NestedInsertionPoint {
	nestedParams, err := ParseXMLBody([]byte(parentParam.Value()), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(parentParam.Value()) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := newParameterInsertionPointShared(shared, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(parentParam.Value()),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&NoopEncoder{},
			nil,
			INS_PARAM_XML,
		)

		nestedIP := newNestedInsertionPointShared(shared, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromURLEncodedShared uses shared base request for the parent insertion point.
func createNestedFromURLEncodedShared(shared *sharedBaseRequest, parentParam *Param) []*NestedInsertionPoint {
	decoded, err := url.QueryUnescape(parentParam.Value())
	if err != nil {
		return nil
	}

	nestedParams, err := ParseURLEncodedBody([]byte(decoded), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(decoded) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := newParameterInsertionPointShared(shared, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(decoded),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&URLEncoder{},
			nil,
			INS_PARAM_URL,
		)

		nestedIP := newNestedInsertionPointShared(shared, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromBase64Shared uses shared base request for the parent insertion point.
func createNestedFromBase64Shared(shared *sharedBaseRequest, parentParam *Param) []*NestedInsertionPoint {
	decoded, err := base64.StdEncoding.DecodeString(parentParam.Value())
	if err != nil {
		return nil
	}

	innerFormat := DetectParameterFormat(string(decoded))
	if innerFormat == FormatNone {
		return nil
	}

	var innerParams []*Param

	switch innerFormat {
	case FormatJSON:
		innerParams, _ = ParseJSONBody(decoded, 0)
	case FormatXML:
		innerParams, _ = ParseXMLBody(decoded, 0)
	case FormatURLEncoded:
		innerParams, _ = ParseURLEncodedBody(decoded, 0)
	}

	if len(innerParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, innerParam := range innerParams {
		if innerParam.ValueStart() < 0 ||
			innerParam.ValueEnd() < 0 ||
			innerParam.ValueEnd() > len(decoded) ||
			innerParam.ValueStart() > innerParam.ValueEnd() {
			continue
		}

		parentIP := newParameterInsertionPointShared(shared, parentParam)

		var innerEncoder Encoder
		var ipType InsertionPointType

		switch innerFormat {
		case FormatJSON:
			innerEncoder = &JSONEscapeEncoder{}
			ipType = INS_PARAM_JSON
		case FormatXML:
			innerEncoder = &NoopEncoder{}
			ipType = INS_PARAM_XML
		case FormatURLEncoded:
			innerEncoder = &URLEncoder{}
			ipType = INS_PARAM_URL
		default:
			innerEncoder = &NoopEncoder{}
			ipType = INS_PARAM_JSON
		}

		childIP := NewEncodedInsertionPoint(
			innerParam.Name(),
			decoded,
			innerParam.ValueStart(),
			innerParam.ValueEnd(),
			innerEncoder,
			nil,
			ipType,
		)

		nestedIP := newNestedInsertionPointShared(shared, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromJSON uses the existing ParseJSONBody parser to find nested parameters.
func createNestedFromJSON(request []byte, parentParam *Param) []*NestedInsertionPoint {
	nestedParams, err := ParseJSONBody([]byte(parentParam.Value()), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(parentParam.Value()) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := NewParameterInsertionPoint(request, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(parentParam.Value()),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&JSONEscapeEncoder{},
			nil,
			INS_PARAM_JSON,
		)

		nestedIP := NewNestedInsertionPoint(request, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromXML uses the existing ParseXMLBody parser to find nested parameters.
func createNestedFromXML(request []byte, parentParam *Param) []*NestedInsertionPoint {
	nestedParams, err := ParseXMLBody([]byte(parentParam.Value()), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(parentParam.Value()) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := NewParameterInsertionPoint(request, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(parentParam.Value()),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&NoopEncoder{},
			nil,
			INS_PARAM_XML,
		)

		nestedIP := NewNestedInsertionPoint(request, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromURLEncoded uses ParseURLEncodedBody to find nested parameters.
func createNestedFromURLEncoded(request []byte, parentParam *Param) []*NestedInsertionPoint {
	decoded, err := url.QueryUnescape(parentParam.Value())
	if err != nil {
		return nil
	}

	nestedParams, err := ParseURLEncodedBody([]byte(decoded), 0)
	if err != nil || len(nestedParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, nestedParam := range nestedParams {
		if nestedParam.ValueStart() < 0 ||
			nestedParam.ValueEnd() < 0 ||
			nestedParam.ValueEnd() > len(decoded) ||
			nestedParam.ValueStart() > nestedParam.ValueEnd() {
			continue
		}

		parentIP := NewParameterInsertionPoint(request, parentParam)

		childIP := NewEncodedInsertionPoint(
			nestedParam.Name(),
			[]byte(decoded),
			nestedParam.ValueStart(),
			nestedParam.ValueEnd(),
			&URLEncoder{},
			nil,
			INS_PARAM_URL,
		)

		nestedIP := NewNestedInsertionPoint(request, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}

// createNestedFromBase64 handles Base64-encoded content that contains other formats.
func createNestedFromBase64(request []byte, parentParam *Param) []*NestedInsertionPoint {
	decoded, err := base64.StdEncoding.DecodeString(parentParam.Value())
	if err != nil {
		return nil
	}

	innerFormat := DetectParameterFormat(string(decoded))
	if innerFormat == FormatNone {
		return nil
	}

	var innerParams []*Param

	switch innerFormat {
	case FormatJSON:
		innerParams, _ = ParseJSONBody(decoded, 0)
	case FormatXML:
		innerParams, _ = ParseXMLBody(decoded, 0)
	case FormatURLEncoded:
		innerParams, _ = ParseURLEncodedBody(decoded, 0)
	}

	if len(innerParams) == 0 {
		return nil
	}

	nestedIPs := make([]*NestedInsertionPoint, 0)

	for _, innerParam := range innerParams {
		if innerParam.ValueStart() < 0 ||
			innerParam.ValueEnd() < 0 ||
			innerParam.ValueEnd() > len(decoded) ||
			innerParam.ValueStart() > innerParam.ValueEnd() {
			continue
		}

		parentIP := NewParameterInsertionPoint(request, parentParam)

		var innerEncoder Encoder
		var ipType InsertionPointType

		switch innerFormat {
		case FormatJSON:
			innerEncoder = &JSONEscapeEncoder{}
			ipType = INS_PARAM_JSON
		case FormatXML:
			innerEncoder = &NoopEncoder{}
			ipType = INS_PARAM_XML
		case FormatURLEncoded:
			innerEncoder = &URLEncoder{}
			ipType = INS_PARAM_URL
		default:
			innerEncoder = &NoopEncoder{}
			ipType = INS_PARAM_JSON
		}

		childIP := NewEncodedInsertionPoint(
			innerParam.Name(),
			decoded,
			innerParam.ValueStart(),
			innerParam.ValueEnd(),
			innerEncoder,
			nil,
			ipType,
		)

		nestedIP := NewNestedInsertionPoint(request, parentIP, childIP)
		nestedIPs = append(nestedIPs, nestedIP)
	}

	return nestedIPs
}
