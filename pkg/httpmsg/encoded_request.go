package httpmsg

// encoded_request.go - Encoded request with synchronized caching
// Ported from: burp/f54.java (interface, lines 1-17)
//              burp/fad.java (implementation, lines 1-46)
//
// This file implements an encoded HTTP request that lazily builds the request
// and payload offsets only when first accessed, then caches the results.
//
// Key features:
// - Lazy computation: buildPayload() and computeOffsets() called only on first access
// - Thread-safe caching: synchronized methods ensure single computation
// - Delegates to insertion point: uses abstract methods from base insertion point
//
// Field mapping from fad.java:
//   - c (byte[]): cachedBytes - cached encoded request bytes
//   - b (int[]): cachedOffsets - cached payload offsets
//   - d (iav): insertionPoint - the base insertion point
//   - a (du8): wrapper - the payload wrapper

import (
	"sync"
)

// EncodedRequest interface defines access to an encoded HTTP request.
// Ported from: burp/f54.java interface (lines 5-16)
//
// This interface provides:
// - EncodingType(): Returns the encoding type byte
// - EncodedBytes(): Returns the complete encoded request bytes
// - Markers(): Returns list of payload markers (not fully implemented)
// - PayloadOffsets(): Returns byte offsets of payload in request
//
// The interface allows callers to get encoded request data without knowing
// the implementation details of how encoding is performed.
type EncodedRequest interface {
	// EncodingType returns the encoding type identifier.
	// Ported from: f54.java a() method (line 6)
	//
	// Returns:
	//   - Encoding type byte (from PayloadWrapper)
	EncodingType() byte

	// EncodedBytes returns the complete encoded HTTP request.
	// Ported from: f54.java d() method (line 8)
	//
	// This is lazily computed and cached. The first call will:
	// 1. Call insertionPoint.buildPayload()
	// 2. Cache the result
	// 3. Return cached result on subsequent calls
	//
	// Returns:
	//   - Complete HTTP request bytes with payload encoded
	EncodedBytes() []byte

	// Markers returns list of payload position markers.
	// Ported from: f54.java b() method (line 10)
	//
	// Note: This is a simplified implementation that returns a single marker.
	// The full Burp implementation uses a List<gn0> type.
	//
	// Returns:
	//   - List of marker objects (simplified as [][]int)
	Markers() [][]int

	// PayloadOffsets returns byte offsets of payload in encoded request.
	// Ported from: f54.java c() method (line 12)
	//
	// This is lazily computed and cached. The first call will:
	// 1. Call insertionPoint.computeOffsets()
	// 2. Cache the result
	// 3. Return cached result on subsequent calls
	//
	// Returns:
	//   - Array of [start, end] byte offsets
	PayloadOffsets() []int
}

// EncodedRequestImpl implements EncodedRequest with thread-safe caching.
// Ported from: burp/fad.java class (lines 6-46)
//
// This implementation provides:
// - Synchronized access to cached values
// - Lazy computation via insertion point methods
// - Thread-safe single computation guarantee
//
// Algorithm (from fad.java):
//  1. On first EncodedBytes() call (lines 24-30):
//     a. Check if cached (line 26)
//     b. If not cached: call insertionPoint.buildPayload() (line 27)
//     c. Store result in cache (line 27)
//     d. Return cached value (line 29)
//  2. On first PayloadOffsets() call (lines 33-39):
//     a. Check if cached (line 35)
//     b. If not cached: call insertionPoint.computeOffsets() (line 36)
//     c. Store result in cache (line 36)
//     d. Return cached value (line 38)
//
// Field mapping from fad.java:
//   - c: cachedBytes - cached encoded request
//   - b: cachedOffsets - cached payload offsets
//   - d: insertionPoint - base insertion point with abstract methods
//   - a: wrapper - payload wrapper with payload bytes and encoding type
type EncodedRequestImpl struct {
	// Mutex for thread-safe access to cached values
	// Java uses synchronized methods; Go uses explicit mutex
	mu sync.Mutex

	// c: cached encoded request bytes from fad.java
	cachedBytes []byte

	// b: cached payload offsets from fad.java
	cachedOffsets []int

	// d: insertion point from fad.java
	// This is the BaseInsertionPoint that implements buildPayload/computeOffsets
	insertionPoint BaseInsertionPointInterface

	// a: payload wrapper from fad.java
	wrapper *PayloadWrapper
}

// BaseInsertionPointInterface defines the abstract methods that insertion points must implement.
// This interface allows EncodedRequestImpl to call buildPayload/computeOffsets
// without depending on the concrete BaseInsertionPoint type.
type BaseInsertionPointInterface interface {
	// BuildPayload creates the encoded request with payload injected.
	// Ported from: iav.java b(byte[], byte, int[]) abstract method (line 139)
	//
	// Parameters:
	//   - payloadBytes: Payload to inject
	//   - encodingType: Encoding type identifier
	//   - offsetsIn: Input offsets for encoding
	//
	// Returns:
	//   - Complete HTTP request with payload injected and encoded
	BuildPayload(payloadBytes []byte, encodingType byte, offsetsIn []int) []byte

	// ComputeOffsets calculates payload offsets in encoded request.
	// Ported from: iav.java a(byte[], byte, int[]) abstract method (line 137)
	//
	// Parameters:
	//   - payloadBytes: Payload that was injected
	//   - encodingType: Encoding type identifier
	//   - offsetsOut: Output offsets for encoding
	//
	// Returns:
	//   - Array of [start, end] byte offsets in encoded request
	ComputeOffsets(payloadBytes []byte, encodingType byte, offsetsOut []int) []int
}

// NewEncodedRequest creates a new EncodedRequest implementation.
// Ported from: fad.java constructor (lines 12-17) and du8.a() factory (lines 20-22)
//
// Algorithm (from fad.java constructor lines 12-17):
// 1. Store wrapper reference (line 13)
// 2. Store insertion point reference (line 14)
// 3. Initialize cached values to nil (lines 15-16)
//
// Parameters:
//   - wrapper: Payload wrapper with payload bytes and encoding type
//   - insertionPoint: Base insertion point with abstract methods
//
// Returns:
//   - New EncodedRequest instance
func NewEncodedRequest(wrapper *PayloadWrapper, insertionPoint BaseInsertionPointInterface) EncodedRequest {
	return &EncodedRequestImpl{
		// fad.java line 13: this.a = var1
		wrapper: wrapper,
		// fad.java line 14: this.d = var2
		insertionPoint: insertionPoint,
		// fad.java lines 15-16: this.c = null, this.b = null
		cachedBytes:   nil,
		cachedOffsets: nil,
	}
}

// EncodingType returns the encoding type identifier.
// Ported from: fad.java a() method (lines 19-22)
//
// Returns:
//   - Encoding type byte from wrapper
func (e *EncodedRequestImpl) EncodingType() byte {
	// fad.java line 21: return this.a.a
	return e.wrapper.EncodingType
}

// EncodedBytes returns the encoded request bytes with thread-safe caching.
// Ported from: fad.java synchronized d() method (lines 24-30)
//
// Algorithm (from fad.java lines 24-30):
// 1. Method is synchronized (line 25)
// 2. Check if cached (line 26)
// 3. If not cached: compute via insertionPoint.buildPayload() (line 27)
// 4. Return cached value (line 29)
//
// The Java synchronized keyword ensures only one thread computes the value.
// Go uses sync.Mutex to achieve the same thread safety.
//
// Returns:
//   - Complete HTTP request bytes with payload encoded
func (e *EncodedRequestImpl) EncodedBytes() []byte {
	// Java: synchronized method (line 25)
	// Go: use explicit mutex
	e.mu.Lock()
	defer e.mu.Unlock()

	// fad.java line 26: if (this.c == null)
	if e.cachedBytes == nil {
		// fad.java line 27: this.c = this.d.b(this.a.d, this.a.a, du8.b(this.a))
		// this.d.b() -> insertionPoint.buildPayload()
		// this.a.d -> wrapper.PayloadBytes
		// this.a.a -> wrapper.EncodingType
		// du8.b(this.a) -> wrapper.OffsetsIn() (static accessor)
		e.cachedBytes = e.insertionPoint.BuildPayload(
			e.wrapper.PayloadBytes,
			e.wrapper.EncodingType,
			e.wrapper.OffsetsIn,
		)
	}

	// fad.java line 29: return this.c
	return e.cachedBytes
}

// PayloadOffsets returns the payload offsets with thread-safe caching.
// Ported from: fad.java synchronized c() method (lines 33-39)
//
// Algorithm (from fad.java lines 33-39):
// 1. Method is synchronized (line 34)
// 2. Check if cached (line 35)
// 3. If not cached: compute via insertionPoint.computeOffsets() (line 36)
// 4. Return cached value (line 38)
//
// The Java synchronized keyword ensures only one thread computes the value.
// Go uses sync.Mutex to achieve the same thread safety.
//
// Returns:
//   - Array of [start, end] byte offsets
func (e *EncodedRequestImpl) PayloadOffsets() []int {
	// Java: synchronized method (line 34)
	// Go: use explicit mutex
	e.mu.Lock()
	defer e.mu.Unlock()

	// fad.java line 35: if (this.b == null)
	if e.cachedOffsets == nil {
		// fad.java line 36: this.b = this.d.a(this.a.d, this.a.a, du8.a(this.a))
		// this.d.a() -> insertionPoint.computeOffsets()
		// this.a.d -> wrapper.PayloadBytes
		// this.a.a -> wrapper.EncodingType
		// du8.a(this.a) -> wrapper.OffsetsOut() (static accessor)
		e.cachedOffsets = e.insertionPoint.ComputeOffsets(
			e.wrapper.PayloadBytes,
			e.wrapper.EncodingType,
			e.wrapper.OffsetsOut,
		)
	}

	// fad.java line 38: return this.b
	return e.cachedOffsets
}

// Markers returns list of payload position markers.
// Ported from: fad.java b() method (lines 42-45)
//
// Algorithm (from fad.java lines 42-45):
// 1. Create single marker from PayloadOffsets() (line 44)
// 2. Return as singleton list (line 44)
//
// Note: The Java implementation uses Collections.singletonList(ct.a(this.c()))
// where ct.a() converts int[] offsets to a marker object.
// We simplify this to return [][]int directly.
//
// Returns:
//   - List containing single marker (payload offsets)
func (e *EncodedRequestImpl) Markers() [][]int {
	// fad.java line 44: return Collections.singletonList(ct.a(this.c()))
	// this.c() -> PayloadOffsets()
	// ct.a() -> creates marker from offsets
	// We simplify to return the offsets directly
	offsets := e.PayloadOffsets()
	return [][]int{offsets}
}
