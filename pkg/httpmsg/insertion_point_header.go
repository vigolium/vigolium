package httpmsg

// insertion_point_header.go - Header-based insertion points for HTTP header fuzzing
//
// Generates InsertionPoint instances for HTTP headers, enabling modules to test
// header injection vectors (SQLi via X-Forwarded-For, SSRF via Referer, etc.).
//
// Two categories of header IPs are created:
// 1. Existing injectable headers: Headers already present in the request (minus protocol headers)
// 2. Synthetic headers: Common attack-surface headers injected when not already present

// protocolHeaders contains headers that should NOT be fuzzed because they are
// protocol-level and modifying them would break HTTP semantics or cause false positives.
var protocolHeaders = map[string]bool{
	"host":              true,
	"content-type":      true,
	"content-length":    true,
	"cookie":            true,
	"connection":        true,
	"accept-encoding":   true,
	"transfer-encoding": true,
	"te":                true,
	"upgrade":           true,
}

// syntheticHeader defines a header to inject when not already present in the request.
type syntheticHeader struct {
	name         string
	defaultValue string
}

// syntheticHeaders are common attack-surface headers injected when missing.
// Each has a realistic default value that modules can replace with payloads.
var syntheticHeaders = []syntheticHeader{
	{name: "X-Forwarded-For", defaultValue: "127.0.0.1"},
	{name: "X-Forwarded-Host", defaultValue: ""}, // filled from Host header at runtime
	{name: "Referer", defaultValue: ""},          // filled from request URL at runtime
	{name: "True-Client-IP", defaultValue: "127.0.0.1"},
	{name: "X-Real-IP", defaultValue: "127.0.0.1"},
}

// HeaderInsertionPoint implements InsertionPoint for HTTP header value injection.
//
// BuildRequest uses a precomputed-offset splice (a single allocation, no header
// re-parse) when the layout is eligible, mirroring the ParameterInsertionPoint
// fast path. It falls back to AddOrReplaceHeader otherwise (and when the IP is
// constructed directly without precomputed offsets). The splice keeps an existing
// header in its original position instead of moving it to the end as
// AddOrReplaceHeader (RemoveHeader+AddHeader) does — an HTTP-semantically
// irrelevant difference, the same trade-off buildWithContentLength makes.
type HeaderInsertionPoint struct {
	headerName  string
	baseValue   string
	baseRequest []byte // shared reference from sharedBaseRequest

	// Precomputed splice layout (set in createHeaderInsertionPoints). At most one
	// of fastValue/fastInsert is set when eligible.
	fastValue  bool   // existing unique header: splice payload into [valueStart:valueEnd]
	fastInsert bool   // absent header: splice "Name: payload\r\n" at insertPos
	valueStart int    // value region start (fastValue)
	valueEnd   int    // value region end (fastValue)
	insertPos  int    // header/body separator position (fastInsert)
	linePrefix string // "Name: " (fastInsert)
}

// Name returns the header name.
func (h *HeaderInsertionPoint) Name() string {
	return h.headerName
}

// BaseValue returns the original header value.
func (h *HeaderInsertionPoint) BaseValue() string {
	return h.baseValue
}

// Type returns INS_HEADER.
func (h *HeaderInsertionPoint) Type() InsertionPointType {
	return INS_HEADER
}

// BuildRequest creates a new request with the payload injected as the header value.
// Works for both existing and synthetic headers.
func (h *HeaderInsertionPoint) BuildRequest(payload []byte) []byte {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	// Fast path: single-allocation splice using the layout precomputed at
	// construction, avoiding the two full re-parses + rebuilds that
	// AddOrReplaceHeader (RemoveHeader+AddHeader) performs per payload.
	if h.fastValue {
		return spliceBytes(h.baseRequest, h.valueStart, h.valueEnd, payload)
	}
	if h.fastInsert {
		// Insert "Name: <payload>\r\n" before the header/body separator.
		base := h.baseRequest
		result := make([]byte, 0, len(base)+len(h.linePrefix)+len(payload)+2)
		result = append(result, base[:h.insertPos]...)
		result = append(result, h.linePrefix...)
		result = append(result, payload...)
		result = append(result, CR, LF)
		result = append(result, base[h.insertPos:]...)
		return result
	}

	// Fallback (e.g. directly-constructed IP, duplicate header, or malformed
	// request): full rebuild via AddOrReplaceHeader.
	result, err := AddOrReplaceHeader(h.baseRequest, h.headerName, string(payload))
	if err != nil {
		// Fallback: return base request unchanged
		return h.baseRequest
	}
	return result
}

// PayloadOffsets returns the byte offsets of the payload in the built request.
// Builds the request first, then uses GetHeaderOffsets to locate the value.
func (h *HeaderInsertionPoint) PayloadOffsets(payload []byte) []int {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	built := h.BuildRequest(payload)
	offsets := GetHeaderOffsets(built, h.headerName)
	if offsets == nil {
		return []int{-1, -1}
	}
	// offsets = [lineStart, valueStart, valueEnd]
	return []int{offsets[1], offsets[2]}
}

// createHeaderInsertionPoints generates header insertion points from a request.
// It creates IPs for:
// 1. Existing injectable headers (skipping protocol headers)
// 2. Synthetic headers not already present in the request
func createHeaderInsertionPoints(shared *sharedBaseRequest, headers []string) []InsertionPoint {
	var points []InsertionPoint
	seen := make(map[string]bool)

	// Count header occurrences so the fast-path splice is only enabled for
	// unique headers — a duplicate header must go through AddOrReplaceHeader,
	// which collapses all occurrences into one, whereas an in-place splice would
	// leave the duplicate behind.
	nameCounts := make(map[string]int)
	for i := 1; i < len(headers); i++ {
		if c := FindColonIndex(headers[i]); c > 0 {
			nameCounts[ToLowerString(headers[i][:c])]++
		}
	}

	// Separator position for synthetic-header inserts, computed once.
	separatorPos := findHeaderEndPosition(shared.raw, 0)

	// Parse existing headers (skip request line at index 0)
	for i := 1; i < len(headers); i++ {
		colonIdx := FindColonIndex(headers[i])
		if colonIdx <= 0 {
			continue
		}

		name := headers[i][:colonIdx]
		nameLower := ToLowerString(name)

		// Skip protocol headers
		if protocolHeaders[nameLower] {
			continue
		}

		// Skip duplicates
		if seen[nameLower] {
			continue
		}
		seen[nameLower] = true

		// Extract value (after ": ")
		value := ""
		valueStart := colonIdx + 1
		if valueStart < len(headers[i]) {
			value = TrimSpace(headers[i][valueStart:])
		}

		hip := &HeaderInsertionPoint{
			headerName:  name,
			baseValue:   value,
			baseRequest: shared.raw,
		}
		// Precompute the value-splice layout for unique headers.
		if nameCounts[nameLower] == 1 {
			if offs := GetHeaderOffsets(shared.raw, name); offs != nil {
				hip.fastValue = true
				hip.valueStart = offs[1]
				hip.valueEnd = offs[2]
			}
		}
		points = append(points, hip)
	}

	// Determine dynamic defaults for synthetic headers
	hostValue := Header(headers, "Host")

	// Build full URL for Referer default
	refererValue := ""
	if len(headers) > 0 {
		_, url, _ := parseRequestLine(headers[0])
		if url != "" && hostValue != "" {
			refererValue = "http://" + hostValue + url
		}
	}

	// Add synthetic headers not already present
	for _, sh := range syntheticHeaders {
		nameLower := ToLowerString(sh.name)
		if seen[nameLower] {
			continue
		}
		seen[nameLower] = true

		defaultVal := sh.defaultValue
		// Fill dynamic defaults
		switch nameLower {
		case "x-forwarded-host":
			if defaultVal == "" {
				defaultVal = hostValue
			}
		case "referer":
			if defaultVal == "" {
				defaultVal = refererValue
			}
		}

		// If we still have no default, use a placeholder
		if defaultVal == "" {
			defaultVal = "127.0.0.1"
		}

		hip := &HeaderInsertionPoint{
			headerName:  sh.name,
			baseValue:   defaultVal,
			baseRequest: shared.raw,
		}
		// Precompute the insert layout (header absent → splice a new line before
		// the separator, mirroring AddHeader).
		if separatorPos >= 0 {
			hip.fastInsert = true
			hip.insertPos = separatorPos
			hip.linePrefix = sh.name + ": "
		}
		points = append(points, hip)
	}

	return points
}
