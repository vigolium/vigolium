// Package modkit provides type definitions for module scanning.
// This package is separate to avoid import cycles between modules package and module implementations.
package modkit

import "github.com/vigolium/vigolium/pkg/httpmsg"

// ScanScope defines the granularity at which a module is invoked during scanning.
// Uses bitmask for efficient combination of multiple scopes.
type ScanScope uint8

const (
	// ScanScopeInsertionPoint - called for each insertion point.
	// Use cases: XSS, SQLi, command injection, SSTI, etc.
	ScanScopeInsertionPoint ScanScope = 1 << iota

	// ScanScopeRequest - called once per unique request.
	// Use cases: missing headers, auth bypass, HTTP method manipulation.
	ScanScopeRequest

	// ScanScopeHost - called once per unique host.
	// Use cases: server fingerprinting, TLS checks, common path discovery.
	ScanScopeHost
)

// String returns a human-readable name for the scan scope.
func (s ScanScope) String() string {
	switch s {
	case ScanScopeInsertionPoint:
		return "PER_INSERTION_POINT"
	case ScanScopeRequest:
		return "PER_REQUEST"
	case ScanScopeHost:
		return "PER_HOST"
	default:
		return "ALL"
	}
}

// Has returns true if the scan scope includes the given scope.
func (s ScanScope) Has(check ScanScope) bool {
	return s&check != 0
}

// InsertionPointTypeSet is a set of allowed insertion point types.
// Uses bitmask for efficient storage and lookup.
type InsertionPointTypeSet uint32

// AllInsertionPointTypes includes all insertion point types.
const AllInsertionPointTypes InsertionPointTypeSet = 0xFFFFFFFF

// NewInsertionPointTypeSet creates a new set from the given types.
func NewInsertionPointTypeSet(types ...httpmsg.InsertionPointType) InsertionPointTypeSet {
	var set InsertionPointTypeSet
	for _, t := range types {
		set |= InsertionPointTypeSet(1 << t)
	}
	return set
}

// Contains returns true if the set contains the given type.
func (s InsertionPointTypeSet) Contains(t httpmsg.InsertionPointType) bool {
	return s&InsertionPointTypeSet(1<<t) != 0
}

// Common insertion point type presets.
var (
	// URLParamTypes includes URL-related parameter types.
	URLParamTypes = NewInsertionPointTypeSet(
		httpmsg.INS_PARAM_URL,
		httpmsg.INS_PARAM_NAME_URL,
		httpmsg.INS_URL_PATH_FOLDER,
		httpmsg.INS_URL_PATH_FILENAME,
	)

	// BodyParamTypes includes body-related parameter types.
	BodyParamTypes = NewInsertionPointTypeSet(
		httpmsg.INS_PARAM_BODY,
		httpmsg.INS_PARAM_NAME_BODY,
		httpmsg.INS_PARAM_JSON,
		httpmsg.INS_PARAM_XML,
		httpmsg.INS_PARAM_XML_ATTR,
		httpmsg.INS_PARAM_MULTIPART_ATTR,
		httpmsg.INS_ENTIRE_BODY,
	)

	// CookieTypes includes cookie-related parameter types.
	CookieTypes = NewInsertionPointTypeSet(
		httpmsg.INS_PARAM_COOKIE,
	)

	// HeaderTypes includes header-related parameter types.
	HeaderTypes = NewInsertionPointTypeSet(
		httpmsg.INS_HEADER,
	)

	// AllParamTypes includes all parameter types (URL, Body, Cookie, Header).
	AllParamTypes = URLParamTypes | BodyParamTypes | CookieTypes | HeaderTypes
)

// PassiveScanScope defines what parts of HTTP transaction to analyze.
type PassiveScanScope uint8

const (
	// PassiveScanScopeRequest analyzes request only.
	PassiveScanScopeRequest PassiveScanScope = 1 << iota

	// PassiveScanScopeResponse analyzes response only.
	PassiveScanScopeResponse

	// PassiveScanScopeBoth analyzes both request and response.
	PassiveScanScopeBoth = PassiveScanScopeRequest | PassiveScanScopeResponse
)

// String returns a human-readable name for the scope.
func (s PassiveScanScope) String() string {
	switch s {
	case PassiveScanScopeRequest:
		return "REQUEST"
	case PassiveScanScopeResponse:
		return "RESPONSE"
	case PassiveScanScopeBoth:
		return "BOTH"
	default:
		return "UNKNOWN"
	}
}

// HasRequest returns true if the scope includes request analysis.
func (s PassiveScanScope) HasRequest() bool {
	return s&PassiveScanScopeRequest != 0
}

// HasResponse returns true if the scope includes response analysis.
func (s PassiveScanScope) HasResponse() bool {
	return s&PassiveScanScopeResponse != 0
}
