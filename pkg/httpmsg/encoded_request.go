package httpmsg

// encoded_request.go - Encoded request with synchronized caching
//
// This file implements an encoded HTTP request that lazily builds the request
// and payload offsets only when first accessed, then caches the results.
//
// Key features:
// - Lazy computation: buildPayload() and computeOffsets() called only on first access
// - Thread-safe caching: synchronized methods ensure single computation
// - Delegates to insertion point: uses abstract methods from base insertion point

import (
	"sync"
)

// EncodedRequest interface defines access to an encoded HTTP request.
//
// The interface allows callers to get encoded request data without knowing
// the implementation details of how encoding is performed.
type EncodedRequest interface {
	// EncodingType returns the encoding type identifier.
	EncodingType() byte

	// EncodedBytes returns the complete encoded HTTP request.
	// Lazily computed and cached on first access.
	EncodedBytes() []byte

	// Markers returns list of payload position markers.
	Markers() [][]int

	// PayloadOffsets returns byte offsets of payload in encoded request.
	// Lazily computed and cached on first access.
	PayloadOffsets() []int
}

// EncodedRequestImpl implements EncodedRequest with thread-safe caching.
//
// This implementation provides:
// - Synchronized access to cached values
// - Lazy computation via insertion point methods
// - Thread-safe single computation guarantee
type EncodedRequestImpl struct {
	mu             sync.Mutex
	cachedBytes    []byte
	cachedOffsets  []int
	insertionPoint BaseInsertionPointInterface
	wrapper        *PayloadWrapper
}

// BaseInsertionPointInterface defines the abstract methods that insertion points must implement.
// This interface allows EncodedRequestImpl to call buildPayload/computeOffsets
// without depending on the concrete BaseInsertionPoint type.
type BaseInsertionPointInterface interface {
	// BuildPayload creates the encoded request with payload injected.
	BuildPayload(payloadBytes []byte, encodingType byte, offsetsIn []int) []byte

	// ComputeOffsets calculates payload offsets in encoded request.
	ComputeOffsets(payloadBytes []byte, encodingType byte, offsetsOut []int) []int
}

// NewEncodedRequest creates a new EncodedRequest implementation.
//
// Parameters:
//   - wrapper: Payload wrapper with payload bytes and encoding type
//   - insertionPoint: Base insertion point with abstract methods
//
// Returns:
//   - New EncodedRequest instance
func NewEncodedRequest(wrapper *PayloadWrapper, insertionPoint BaseInsertionPointInterface) EncodedRequest {
	return &EncodedRequestImpl{
		wrapper:        wrapper,
		insertionPoint: insertionPoint,
		cachedBytes:    nil,
		cachedOffsets:  nil,
	}
}

// EncodingType returns the encoding type identifier.
func (e *EncodedRequestImpl) EncodingType() byte {
	return e.wrapper.EncodingType
}

// EncodedBytes returns the encoded request bytes with thread-safe caching.
// Lazily computed on first access via insertionPoint.BuildPayload().
func (e *EncodedRequestImpl) EncodedBytes() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cachedBytes == nil {
		e.cachedBytes = e.insertionPoint.BuildPayload(
			e.wrapper.PayloadBytes,
			e.wrapper.EncodingType,
			e.wrapper.OffsetsIn,
		)
	}

	return e.cachedBytes
}

// PayloadOffsets returns the payload offsets with thread-safe caching.
// Lazily computed on first access via insertionPoint.ComputeOffsets().
func (e *EncodedRequestImpl) PayloadOffsets() []int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cachedOffsets == nil {
		e.cachedOffsets = e.insertionPoint.ComputeOffsets(
			e.wrapper.PayloadBytes,
			e.wrapper.EncodingType,
			e.wrapper.OffsetsOut,
		)
	}

	return e.cachedOffsets
}

// Markers returns list of payload position markers.
// Returns a single marker derived from PayloadOffsets().
func (e *EncodedRequestImpl) Markers() [][]int {
	offsets := e.PayloadOffsets()
	return [][]int{offsets}
}
