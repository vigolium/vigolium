package httpmsg

// insertion_point_impl.go - InsertionPoint implementations
//
// This file consolidates all InsertionPoint implementations:
// - ParameterInsertionPoint: Parameter-aware insertion point with encoding
// - EncodedInsertionPoint: Insertion point with custom encoder support
// - NestedInsertionPoint: Multi-layer encoding for nested parameters
// - Batch operations: BuildRequestWithPayloads, BuildRequestWithSamePayload

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
)

// sharedBaseRequest holds a read-only request buffer shared across insertion points
// from a single CreateAllInsertionPoints call. BuildRequest() never mutates baseRequest
// (it allocates a new result slice), so sharing without synchronization is safe.
type sharedBaseRequest struct {
	raw []byte
}

// ==================== PARAMETER INSERTION POINT ====================

// ParameterInsertionPoint implements parameter-aware insertion point with encoding.
// Ported from: ggd.java (lines 3-109)
//
// This insertion point is aware of parameter types and applies appropriate encoding:
// - URL parameters: URL-encode special characters
// - Body parameters: URL-encode for application/x-www-form-urlencoded
// - JSON parameters: No encoding (raw injection)
// - XML parameters: No encoding (raw injection)
// - Cookie parameters: URL-encode
type ParameterInsertionPoint struct {
	parameter     *Param             // b: parameter object
	baseRequest   []byte             // original request (for rebuilding)
	insertionType InsertionPointType // cached insertion point type
}

// NewParameterInsertionPoint creates a new parameter-aware insertion point.
// Ported from: ggd.a() factory method (lines 7-9) and constructor (lines 11-13)
func NewParameterInsertionPoint(request []byte, param *Param) *ParameterInsertionPoint {
	if param == nil {
		panic("Parameter cannot be nil")
	}
	if request == nil {
		panic("Request cannot be nil")
	}

	// Clone request
	requestCopy := make([]byte, len(request))
	copy(requestCopy, request)

	// Map parameter type to insertion point type (ggd.java lines 68-108)
	ipType := param.ToInsertionPointType()

	return &ParameterInsertionPoint{
		parameter:     param,
		baseRequest:   requestCopy,
		insertionType: ipType,
	}
}

// newParameterInsertionPointShared creates a ParameterInsertionPoint using a shared
// base request reference instead of cloning.
func newParameterInsertionPointShared(shared *sharedBaseRequest, param *Param) *ParameterInsertionPoint {
	if param == nil {
		panic("Parameter cannot be nil")
	}
	ipType := param.ToInsertionPointType()
	return &ParameterInsertionPoint{
		parameter:     param,
		baseRequest:   shared.raw, // shared reference, no copy
		insertionType: ipType,
	}
}

// Name returns the parameter name.
func (p *ParameterInsertionPoint) Name() string {
	return p.parameter.Name()
}

// BaseValue returns the parameter's original value.
func (p *ParameterInsertionPoint) BaseValue() string {
	return p.parameter.Value()
}

// Type returns the insertion point type.
func (p *ParameterInsertionPoint) Type() InsertionPointType {
	return p.insertionType
}

// BuildRequest creates a new request with payload injected and properly encoded.
// Ported from: ggd.buildRequest() (lines 25-33)
func (p *ParameterInsertionPoint) BuildRequest(payload []byte) []byte {
	// Validate payload (ggd.java lines 27-29)
	if payload == nil {
		panic("Payload cannot be nil")
	}

	// Encode payload based on parameter type
	encoded := p.encodePayload(payload)

	// Build request by replacing parameter value
	startOffset := p.parameter.ValueStart()
	endOffset := p.parameter.ValueEnd()

	// Calculate result size
	resultSize := len(p.baseRequest) - (endOffset - startOffset) + len(encoded)
	result := make([]byte, resultSize)

	// Copy prefix
	copy(result[0:], p.baseRequest[0:startOffset])

	// Copy encoded payload
	copy(result[startOffset:], encoded)

	// Copy suffix
	copy(result[startOffset+len(encoded):], p.baseRequest[endOffset:])

	// Update Content-Length if parameter type requires it
	if p.parameter.RequiresContentLengthUpdate() {
		updated, err := UpdateContentLength(result)
		if err != nil {
			return result
		}
		result = updated
	}

	return result
}

// requestBufPool pools request buffers to reduce allocation pressure during fuzzing.
var requestBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 8*1024) // 8 KiB initial
		return &b
	},
}

// GetRequestBuffer returns a pooled buffer of at least size n.
// Caller must call PutRequestBuffer when done.
func GetRequestBuffer(n int) []byte {
	bp := requestBufPool.Get().(*[]byte)
	b := *bp
	if cap(b) >= n {
		return b[:n]
	}
	// Buffer too small — let it be GC'd and allocate a new one
	return make([]byte, n)
}

// PutRequestBuffer returns a buffer to the pool.
// Buffers larger than 1 MiB are not pooled to avoid holding excessive memory.
func PutRequestBuffer(buf []byte) {
	if cap(buf) > 1<<20 {
		return
	}
	buf = buf[:0]
	requestBufPool.Put(&buf)
}

// BuildRequestPooled creates a new request with payload injected, using a pooled buffer.
// The caller MUST call PutRequestBuffer(result) when the returned slice is no longer needed.
// This avoids per-call allocations in tight fuzzing loops.
func (p *ParameterInsertionPoint) BuildRequestPooled(payload []byte) []byte {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	encoded := p.encodePayload(payload)

	startOffset := p.parameter.ValueStart()
	endOffset := p.parameter.ValueEnd()

	resultSize := len(p.baseRequest) - (endOffset - startOffset) + len(encoded)
	result := GetRequestBuffer(resultSize)

	copy(result[0:], p.baseRequest[0:startOffset])
	copy(result[startOffset:], encoded)
	copy(result[startOffset+len(encoded):], p.baseRequest[endOffset:])

	if p.parameter.RequiresContentLengthUpdate() {
		updated, err := UpdateContentLength(result)
		if err != nil {
			return result
		}
		// If UpdateContentLength returned a new slice, put the old one back
		if &updated[0] != &result[0] {
			PutRequestBuffer(result)
		}
		result = updated
	}

	return result
}

// PayloadOffsets returns the byte offsets of the payload in the built request.
func (p *ParameterInsertionPoint) PayloadOffsets(payload []byte) []int {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	// Encode payload to get actual injected bytes
	encoded := p.encodePayload(payload)

	// Calculate offsets
	startOffset := p.parameter.ValueStart()
	endOffset := startOffset + len(encoded)

	return []int{startOffset, endOffset}
}

// encodePayload applies appropriate encoding based on parameter type.
func (p *ParameterInsertionPoint) encodePayload(payload []byte) []byte {
	// Use path-specific encoding for path parameters (RFC 3986)
	// Path encoding: space → %20 (not +), literal + preserved
	if p.parameter.Type() == ParamPathFolder || p.parameter.Type() == ParamPathFilename {
		encoded := EncodePathValue(string(payload))
		return []byte(encoded)
	}

	if p.parameter.CanURLEncode() {
		encoded := EncodeQueryValue(string(payload))
		return []byte(encoded)
	}

	// Apply type-aware encoding for JSON parameters
	if p.parameter.Type() == ParamJSON {
		return p.encodeJSONPayload(payload)
	}

	// No encoding needed (XML, etc.)
	return payload
}

// encodeJSONPayload applies type-aware encoding for JSON parameters.
func (p *ParameterInsertionPoint) encodeJSONPayload(payload []byte) []byte {
	originalType := p.parameter.JSONType()

	// Case 1: Original was STRING → always escape the payload
	if originalType == JSONTypeString {
		return escapeJSONStringContent(payload)
	}

	// Case 2: Original was non-string (bool/number/null/unknown)
	if isValidJSONPrimitive(payload) {
		return payload
	}

	// Case 3: Payload is a string that needs to be wrapped with quotes and escaped
	return wrapAsJSONString(payload)
}

// isValidJSONPrimitive checks if payload is a valid JSON primitive value.
func isValidJSONPrimitive(payload []byte) bool {
	s := string(payload)
	trimmed := s
	for len(trimmed) > 0 && trimmed[0] == ' ' {
		trimmed = trimmed[1:]
	}
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == ' ' {
		trimmed = trimmed[:len(trimmed)-1]
	}

	if trimmed == "true" || trimmed == "false" || trimmed == "null" {
		return true
	}
	return isJSONNumber(trimmed)
}

// escapeJSONStringContent escapes special characters for JSON string content.
func escapeJSONStringContent(payload []byte) []byte {
	var buf bytes.Buffer
	for _, b := range payload {
		switch b {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if b < 32 {
				fmt.Fprintf(&buf, `\u%04x`, b)
			} else {
				buf.WriteByte(b)
			}
		}
	}
	return buf.Bytes()
}

// wrapAsJSONString escapes content and wraps with quotes.
func wrapAsJSONString(payload []byte) []byte {
	escaped := escapeJSONStringContent(payload)
	result := make([]byte, len(escaped)+2)
	result[0] = '"'
	copy(result[1:], escaped)
	result[len(result)-1] = '"'
	return result
}

// ==================== ENCODED INSERTION POINT ====================

// EncodedInsertionPoint implements insertion point with custom encoding.
// Ported from: ia8.java (lines 5-135)
//
// This insertion point extends the base functionality with:
// 1. Custom encoder support (URL encoding, Base64, etc.)
// 2. Prefix/suffix handling
// 3. Context-aware encoding
type EncodedInsertionPoint struct {
	name          string             // insertion point name
	baseRequest   []byte             // b: original request bytes (cloned)
	startOffset   int                // q: start of replacement range
	endOffset     int                // r: end of replacement range
	baseValue     string             // f: original value at insertion point
	prefix        []byte             // l: prefix bytes to prepend to encoded payload
	encoder       Encoder            // p: encoder for payload transformation
	insertionType InsertionPointType // h: insertion point type
}

// NewEncodedInsertionPoint creates a new encoded insertion point.
// Ported from: ia8 constructor (lines 12-19)
func NewEncodedInsertionPoint(name string, request []byte, startOffset, endOffset int, encoder Encoder, prefix []byte, ipType InsertionPointType) *EncodedInsertionPoint {
	if name == "" {
		panic("Name cannot be empty")
	}
	if request == nil {
		panic("Base request cannot be nil")
	}
	if startOffset < 0 || endOffset > len(request) || endOffset < startOffset {
		panic("Invalid offsets")
	}
	if encoder == nil {
		panic("Encoder cannot be nil")
	}

	// Clone request to ensure thread safety
	requestCopy := make([]byte, len(request))
	copy(requestCopy, request)

	// Extract and decode base value (ia8.java line 13)
	baseBytes := request[startOffset:endOffset]
	decodedBaseValue := encoder.Decode(baseBytes)

	// Clone prefix if provided
	var prefixCopy []byte
	if prefix != nil {
		prefixCopy = make([]byte, len(prefix))
		copy(prefixCopy, prefix)
	}

	return &EncodedInsertionPoint{
		name:          name,
		baseRequest:   requestCopy,
		startOffset:   startOffset,
		endOffset:     endOffset,
		baseValue:     string(decodedBaseValue),
		prefix:        prefixCopy,
		encoder:       encoder,
		insertionType: ipType,
	}
}

// Name returns the insertion point name.
func (e *EncodedInsertionPoint) Name() string {
	return e.name
}

// BaseValue returns the encoded base value.
func (e *EncodedInsertionPoint) BaseValue() string {
	return e.baseValue
}

// Type returns the type constant.
func (e *EncodedInsertionPoint) Type() InsertionPointType {
	return e.insertionType
}

// BuildRequest creates a new request with payload injected and encoded.
// Ported from: ia8.b() method (lines 22-50)
func (e *EncodedInsertionPoint) BuildRequest(payload []byte) []byte {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	// Build payload with prefix if present
	payloadWithPrefix := e.buildPayload(payload)

	// Encode the payload
	offsets := []int{0, len(payloadWithPrefix)}
	encodedPayload := e.encoder.Encode(payloadWithPrefix, offsets)

	// Build request by replacing [startOffset:endOffset] with encoded payload
	result := e.buildRequestWithPayload(encodedPayload)

	// Update Content-Length if insertion type requires it
	if InsertionPointRequiresContentLengthUpdate(e.insertionType) {
		updated, err := UpdateContentLength(result)
		if err != nil {
			return result
		}
		result = updated
	}

	return result
}

// PayloadOffsets returns the byte offsets of the payload in the built request.
func (e *EncodedInsertionPoint) PayloadOffsets(payload []byte) []int {
	if payload == nil {
		panic("Payload cannot be nil")
	}

	// Build payload with prefix if present
	payloadWithPrefix := e.buildPayload(payload)

	// Encode payload with offset tracking
	offsets := []int{0, len(payloadWithPrefix)}
	e.encoder.Encode(payloadWithPrefix, offsets)

	// Adjust offsets for startOffset
	offsets[0] += e.startOffset
	offsets[1] += e.startOffset

	return offsets
}

// buildPayload prepends prefix to payload if present.
func (e *EncodedInsertionPoint) buildPayload(payload []byte) []byte {
	if len(e.prefix) == 0 {
		return payload
	}

	result := make([]byte, len(e.prefix)+len(payload))
	copy(result[0:], e.prefix)
	copy(result[len(e.prefix):], payload)

	return result
}

// buildRequestWithPayload builds request by replacing [startOffset:endOffset] with encoded payload.
func (e *EncodedInsertionPoint) buildRequestWithPayload(encodedPayload []byte) []byte {
	resultSize := e.startOffset + len(encodedPayload) + (len(e.baseRequest) - e.endOffset)
	result := make([]byte, resultSize)

	// Copy prefix: request[0:startOffset]
	copy(result[0:], e.baseRequest[0:e.startOffset])

	// Copy encoded payload
	copy(result[e.startOffset:], encodedPayload)

	// Copy suffix: request[endOffset:]
	copy(result[e.startOffset+len(encodedPayload):], e.baseRequest[e.endOffset:])

	return result
}

// GetEncoder returns the current encoder.
func (e *EncodedInsertionPoint) GetEncoder() Encoder {
	return e.encoder
}

// SetEncoder sets a new encoder.
func (e *EncodedInsertionPoint) SetEncoder(encoder Encoder) {
	if encoder == nil {
		panic("Encoder cannot be nil")
	}
	e.encoder = encoder
}

// ==================== NESTED INSERTION POINT ====================

// NestedInsertionPoint implements insertion point for nested parameters with multi-layer encoding.
// Ported from: burp/ia3.java (lines 7-73)
//
// This handles parameters containing embedded parameters in different formats
// (e.g., URL parameter containing JSON, Cookie containing URL-encoded data).
//
// The critical feature is the inner-to-outer encoding chain:
//  1. Apply encoding to child parameter (innermost) → get encoded1
//  2. Apply encoding to parent parameter with encoded1 as input → get encoded2
//  3. Return encoded2 (double-encoded result)
type NestedInsertionPoint struct {
	parentParam  InsertionPoint        // p: outer insertion point
	parentNested *NestedInsertionPoint // parent nested IP if multi-level chain
	childParam   InsertionPoint        // n: inner insertion point
	buildState   int                   // o: depth counter for nested traversal
	baseRequest  []byte                // base request bytes
}

// NewNestedInsertionPoint creates a new nested insertion point.
// Ported from: ia3.java constructor (lines 12-17)
func NewNestedInsertionPoint(request []byte, parentParam, childParam InsertionPoint) *NestedInsertionPoint {
	requestCopy := make([]byte, len(request))
	copy(requestCopy, request)

	return &NestedInsertionPoint{
		parentParam:  parentParam,
		parentNested: nil,
		childParam:   childParam,
		buildState:   0,
		baseRequest:  requestCopy,
	}
}

// NewNestedInsertionPointFromIP creates a nested insertion point where the parent is another nested IP.
func NewNestedInsertionPointFromIP(request []byte, parentNested *NestedInsertionPoint, childParam InsertionPoint) *NestedInsertionPoint {
	requestCopy := make([]byte, len(request))
	copy(requestCopy, request)

	return &NestedInsertionPoint{
		parentParam:  parentNested.childParam,
		parentNested: parentNested,
		childParam:   childParam,
		buildState:   0,
		baseRequest:  requestCopy,
	}
}

// newNestedInsertionPointShared creates a NestedInsertionPoint using a shared
// base request reference instead of cloning.
func newNestedInsertionPointShared(shared *sharedBaseRequest, parentParam, childParam InsertionPoint) *NestedInsertionPoint {
	return &NestedInsertionPoint{
		parentParam:  parentParam,
		parentNested: nil,
		childParam:   childParam,
		buildState:   0,
		baseRequest:  shared.raw,
	}
}

// Name returns the child parameter name (the innermost parameter being tested).
func (n *NestedInsertionPoint) Name() string {
	return n.childParam.Name()
}

// BaseValue returns the child parameter's original value.
func (n *NestedInsertionPoint) BaseValue() string {
	return n.childParam.BaseValue()
}

// Type returns the child parameter's insertion point type.
func (n *NestedInsertionPoint) Type() InsertionPointType {
	return n.childParam.Type()
}

// BuildRequest creates request with payload injected through nested encoding chain.
// Ported from: ia3.java b() method (lines 28-32)
func (n *NestedInsertionPoint) BuildRequest(payload []byte) []byte {
	// Step 1: Apply child encoding to get the child's encoded value
	childEncodedValue := n.getChildEncodedValue(payload)

	// Step 2: Apply parent encoding with the child's encoded value as payload
	return n.parentParam.BuildRequest(childEncodedValue)
}

// PayloadOffsets returns the byte offsets of the payload in the built request.
func (n *NestedInsertionPoint) PayloadOffsets(payload []byte) []int {
	childEncodedValue := n.getChildEncodedValue(payload)
	return n.parentParam.PayloadOffsets(childEncodedValue)
}

// getChildEncodedValue gets the encoded value from the child insertion point.
func (n *NestedInsertionPoint) getChildEncodedValue(payload []byte) []byte {
	return n.childParam.BuildRequest(payload)
}

// EncodingChain returns the list of encoding transformations applied.
func (n *NestedInsertionPoint) EncodingChain() string {
	parentName := "parent"
	childName := "child"

	switch p := n.parentParam.(type) {
	case *ParameterInsertionPoint:
		parentName = p.parameter.Type().String()
	case *EncodedInsertionPoint:
		parentName = "Encoded"
	case *NestedInsertionPoint:
		parentName = p.EncodingChain()
	}

	switch c := n.childParam.(type) {
	case *ParameterInsertionPoint:
		childName = c.parameter.Type().String()
	case *EncodedInsertionPoint:
		childName = "Encoded"
	case *NestedInsertionPoint:
		childName = c.EncodingChain()
	}

	return parentName + " → " + childName
}

// SetBuildState sets the build state (depth counter for stack traversal).
func (n *NestedInsertionPoint) SetBuildState(state int) {
	n.buildState = state
}

// BuildState returns the current build state.
func (n *NestedInsertionPoint) BuildState() int {
	return n.buildState
}

// UnwrapChain unwraps a nested insertion point chain to find the root parent.
// Ported from: ia3.java a(bno) static method (lines 60-72)
func UnwrapChain(ip InsertionPoint) InsertionPoint {
	current := ip

	for {
		if nested, ok := current.(*NestedInsertionPoint); ok {
			if nested.parentNested != nil {
				current = UnwrapChain(nested.parentNested)
			} else {
				current = nested.parentParam
			}
		} else {
			break
		}
	}

	return current
}

// ==================== BATCH OPERATIONS ====================

// PayloadMap maps insertion points to their payloads.
type PayloadMap map[InsertionPoint][]byte

// injectionSpec holds the data needed to perform a single injection.
type injectionSpec struct {
	ip          InsertionPoint
	payload     []byte
	startOffset int
	endOffset   int
	encoded     []byte
	isNested    bool
	needsCL     bool
}

// offsetDelta tracks how much offsets shift at each position after a replacement.
type offsetDelta struct {
	position int
	delta    int
}

// BuildRequestWithPayloads injects custom payloads into multiple params simultaneously.
// Each insertion point applies its own encoding automatically based on parameter type.
//
// If conflicting IPs exist (e.g., nested IP and its parent both in payloads),
// automatically splits into multiple requests - one per non-conflicting group.
func BuildRequestWithPayloads(request []byte, payloads PayloadMap) ([][]byte, error) {
	if len(payloads) == 0 {
		return [][]byte{request}, nil
	}

	groups := splitIntoNonConflictingGroups(payloads)

	results := make([][]byte, 0, len(groups))
	for _, group := range groups {
		result, err := buildSingleRequest(request, group)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// conflictPair represents a conflict between a nested IP and its parent.
type conflictPair struct {
	parent InsertionPoint
	nested *NestedInsertionPoint
}

// splitIntoNonConflictingGroups splits payloads into groups where each group has no internal conflicts.
func splitIntoNonConflictingGroups(payloads PayloadMap) []PayloadMap {
	var conflicts []conflictPair
	for ip := range payloads {
		if nested, ok := ip.(*NestedInsertionPoint); ok {
			if _, exists := payloads[nested.parentParam]; exists {
				conflicts = append(conflicts, conflictPair{nested.parentParam, nested})
			}
		}
	}

	nestedByParent := make(map[InsertionPoint][]*NestedInsertionPoint)
	for ip := range payloads {
		if nested, ok := ip.(*NestedInsertionPoint); ok {
			nestedByParent[nested.parentParam] = append(nestedByParent[nested.parentParam], nested)
		}
	}

	var sameParentConflicts [][]*NestedInsertionPoint
	for _, nestedList := range nestedByParent {
		if len(nestedList) > 1 {
			sameParentConflicts = append(sameParentConflicts, nestedList)
		}
	}

	if len(conflicts) == 0 && len(sameParentConflicts) > 0 {
		return splitBySameParentConflicts(payloads, sameParentConflicts)
	}

	if len(conflicts) == 0 {
		return []PayloadMap{payloads}
	}

	conflictingIPs := make(map[InsertionPoint]bool)
	for _, c := range conflicts {
		conflictingIPs[c.parent] = true
		conflictingIPs[c.nested] = true
	}

	nonConflicting := PayloadMap{}
	for ip, payload := range payloads {
		if !conflictingIPs[ip] {
			nonConflicting[ip] = payload
		}
	}

	var groups []PayloadMap
	numCombinations := 1 << len(conflicts)
	for i := 0; i < numCombinations; i++ {
		group := PayloadMap{}
		for ip, payload := range nonConflicting {
			group[ip] = payload
		}
		for j, c := range conflicts {
			if (i>>j)&1 == 0 {
				group[c.parent] = payloads[c.parent]
			} else {
				group[c.nested] = payloads[c.nested]
			}
		}
		groups = append(groups, group)
	}

	if len(sameParentConflicts) > 0 {
		var finalGroups []PayloadMap
		for _, group := range groups {
			nestedByParentInGroup := make(map[InsertionPoint][]*NestedInsertionPoint)
			for ip := range group {
				if nested, ok := ip.(*NestedInsertionPoint); ok {
					nestedByParentInGroup[nested.parentParam] = append(nestedByParentInGroup[nested.parentParam], nested)
				}
			}
			var conflictsInGroup [][]*NestedInsertionPoint
			for _, nestedList := range nestedByParentInGroup {
				if len(nestedList) > 1 {
					conflictsInGroup = append(conflictsInGroup, nestedList)
				}
			}
			if len(conflictsInGroup) > 0 {
				splitGroups := splitBySameParentConflicts(group, conflictsInGroup)
				finalGroups = append(finalGroups, splitGroups...)
			} else {
				finalGroups = append(finalGroups, group)
			}
		}
		return finalGroups
	}

	return groups
}

// splitBySameParentConflicts handles the case where multiple nested IPs share the same parent.
func splitBySameParentConflicts(payloads PayloadMap, conflicts [][]*NestedInsertionPoint) []PayloadMap {
	conflictingIPs := make(map[InsertionPoint]bool)
	for _, nestedList := range conflicts {
		for _, nested := range nestedList {
			conflictingIPs[nested] = true
		}
	}

	nonConflicting := PayloadMap{}
	for ip, payload := range payloads {
		if !conflictingIPs[ip] {
			nonConflicting[ip] = payload
		}
	}

	var groups []PayloadMap
	generateCombinations(conflicts, 0, nonConflicting, payloads, &groups)

	return groups
}

// generateCombinations recursively generates all combinations of nested IPs.
func generateCombinations(conflicts [][]*NestedInsertionPoint, idx int, current PayloadMap, payloads PayloadMap, groups *[]PayloadMap) {
	if idx >= len(conflicts) {
		group := PayloadMap{}
		for ip, payload := range current {
			group[ip] = payload
		}
		*groups = append(*groups, group)
		return
	}

	for _, nested := range conflicts[idx] {
		current[nested] = payloads[nested]
		generateCombinations(conflicts, idx+1, current, payloads, groups)
		delete(current, nested)
	}
}

// buildSingleRequest builds a single request with non-conflicting payloads.
func buildSingleRequest(request []byte, payloads PayloadMap) ([]byte, error) {
	if len(payloads) == 0 {
		return request, nil
	}

	var nestedSpecs []injectionSpec
	var simpleSpecs []injectionSpec

	for ip, payload := range payloads {
		spec := injectionSpec{
			ip:      ip,
			payload: payload,
		}

		if _, ok := ip.(*NestedInsertionPoint); ok {
			spec.isNested = true
			nestedSpecs = append(nestedSpecs, spec)
		} else {
			start, end := getInsertionPointOffsets(ip)
			if start < 0 || end < 0 {
				continue
			}

			spec.startOffset = start
			spec.endOffset = end
			spec.encoded = encodePayloadForIP(ip, payload)
			spec.needsCL = InsertionPointRequiresContentLengthUpdate(ip.Type())

			simpleSpecs = append(simpleSpecs, spec)
		}
	}

	result, deltas := batchReplaceByOffset(request, simpleSpecs)

	for _, spec := range nestedSpecs {
		result, deltas = rebuildNestedRequest(result, spec.ip.(*NestedInsertionPoint), spec.payload, deltas)
	}

	return result, nil
}

// getInsertionPointOffsets extracts start and end offsets from an insertion point.
func getInsertionPointOffsets(ip InsertionPoint) (start, end int) {
	switch v := ip.(type) {
	case *ParameterInsertionPoint:
		return v.parameter.ValueStart(), v.parameter.ValueEnd()
	case *EncodedInsertionPoint:
		return v.startOffset, v.endOffset
	case *HeaderInsertionPoint:
		// Header IPs use AddOrReplaceHeader instead of offset-based replacement,
		// so return (-1, -1) to skip them in batch operations.
		_ = v
		return -1, -1
	default:
		return -1, -1
	}
}

// encodePayloadForIP encodes a payload according to the insertion point's encoding rules.
func encodePayloadForIP(ip InsertionPoint, payload []byte) []byte {
	switch v := ip.(type) {
	case *ParameterInsertionPoint:
		if v.parameter.CanURLEncode() {
			return []byte(EncodeQueryValue(string(payload)))
		}
		return payload
	case *EncodedInsertionPoint:
		payloadWithPrefix := payload
		if len(v.prefix) > 0 {
			payloadWithPrefix = make([]byte, len(v.prefix)+len(payload))
			copy(payloadWithPrefix[0:], v.prefix)
			copy(payloadWithPrefix[len(v.prefix):], payload)
		}
		offsets := []int{0, len(payloadWithPrefix)}
		return v.encoder.Encode(payloadWithPrefix, offsets)
	default:
		return payload
	}
}

// batchReplaceByOffset performs batch replacement on a request.
func batchReplaceByOffset(request []byte, specs []injectionSpec) ([]byte, []offsetDelta) {
	if len(specs) == 0 {
		return request, nil
	}

	sort.Slice(specs, func(i, j int) bool {
		return specs[i].startOffset > specs[j].startOffset
	})

	result := make([]byte, len(request))
	copy(result, request)

	needsContentLengthUpdate := false
	var deltas []offsetDelta

	for _, spec := range specs {
		if spec.startOffset < 0 || spec.endOffset > len(result) || spec.startOffset > spec.endOffset {
			continue
		}

		oldLen := spec.endOffset - spec.startOffset
		newLen := len(spec.encoded)
		sizeDiff := newLen - oldLen

		if sizeDiff != 0 {
			deltas = append(deltas, offsetDelta{
				position: spec.startOffset,
				delta:    sizeDiff,
			})
		}

		newResult := make([]byte, len(result)+sizeDiff)
		copy(newResult[0:spec.startOffset], result[0:spec.startOffset])
		copy(newResult[spec.startOffset:spec.startOffset+newLen], spec.encoded)
		copy(newResult[spec.startOffset+newLen:], result[spec.endOffset:])

		result = newResult

		if spec.needsCL {
			needsContentLengthUpdate = true
		}
	}

	if needsContentLengthUpdate {
		updated, err := UpdateContentLength(result)
		if err == nil {
			result = updated
		}
	}

	return result, deltas
}

// adjustOffset calculates the adjusted offset after applying offset deltas.
func adjustOffset(originalOffset int, deltas []offsetDelta) int {
	adjusted := originalOffset
	for _, d := range deltas {
		if d.position < originalOffset {
			adjusted += d.delta
		}
	}
	return adjusted
}

// rebuildNestedRequest applies a nested insertion point's payload to a request.
func rebuildNestedRequest(currentRequest []byte, nestedIP *NestedInsertionPoint, payload []byte, deltas []offsetDelta) ([]byte, []offsetDelta) {
	childEncoded := nestedIP.getChildEncodedValue(payload)

	parentStart, parentEnd := getInsertionPointOffsets(nestedIP.parentParam)
	if parentStart < 0 || parentEnd < 0 {
		return currentRequest, deltas
	}

	adjustedStart := adjustOffset(parentStart, deltas)
	adjustedEnd := adjustOffset(parentEnd, deltas)

	parentEncoded := encodePayloadForIP(nestedIP.parentParam, childEncoded)

	spec := injectionSpec{
		startOffset: adjustedStart,
		endOffset:   adjustedEnd,
		encoded:     parentEncoded,
		needsCL:     InsertionPointRequiresContentLengthUpdate(nestedIP.parentParam.Type()),
	}

	result, _ := batchReplaceByOffset(currentRequest, []injectionSpec{spec})

	mergedDeltas := append(deltas, offsetDelta{
		position: parentStart,
		delta:    len(parentEncoded) - (parentEnd - parentStart),
	})

	return result, mergedDeltas
}

// BuildRequestWithSamePayload injects the same payload into all insertion points.
func BuildRequestWithSamePayload(request []byte, insertionPoints []InsertionPoint, payload []byte) ([][]byte, error) {
	payloads := make(PayloadMap, len(insertionPoints))
	for _, ip := range insertionPoints {
		payloads[ip] = payload
	}
	return BuildRequestWithPayloads(request, payloads)
}
