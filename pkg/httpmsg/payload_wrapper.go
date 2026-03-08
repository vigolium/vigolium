package httpmsg

// payload_wrapper.go - Payload wrapper for insertion point encoding
// Ported from: burp/du8.java (lines 1-31)
//              burp/duv.java (parent class, not shown)
//
// This file implements a wrapper around payload bytes that tracks encoding type
// and offset information. It provides the data needed to build encoded requests.
//
// Key features:
// - Stores payload bytes and encoding type
// - Tracks input/output offsets for encoding
// - Creates EncodedRequest via Apply() method
// - Provides static accessor methods for offset arrays
//
// Field mapping from du8.java:
//   - d (byte[]): PayloadBytes - raw payload bytes
//   - a (byte): EncodingType - encoding type identifier
//   - b (int[]): OffsetsIn - input offsets for encoding
//   - c (int[]): OffsetsOut - output offsets for encoding

// PayloadWrapper wraps a payload with encoding metadata.
// Ported from: burp/du8.java class (lines 3-31)
//
// Algorithm (from du8.java):
// 1. Store payload bytes and encoding type (constructor lines 9-18)
// 2. Store input/output offsets (constructor line 13)
// 3. Create EncodedRequest via Apply() method (lines 20-22)
// 4. Provide static accessors for offsets (lines 24-30)
//
// The wrapper acts as a data container that insertion points use to build
// encoded requests with proper offset tracking.
//
// Example:
//
//	wrapper := NewPayloadWrapper([]byte("test"), 0)
//	encoded := wrapper.Apply(insertionPoint)
//	bytes := encoded.EncodedBytes()
type PayloadWrapper struct {
	// d: payload bytes from du8.java
	PayloadBytes []byte

	// a: encoding type from du8.java
	EncodingType byte

	// b: input offsets from du8.java
	OffsetsIn []int

	// c: output offsets from du8.java
	OffsetsOut []int
}

// NewPayloadWrapper creates a new PayloadWrapper with default offsets.
// Ported from: du8.java constructor (lines 9-11)
//
// Algorithm (from du8.java lines 9-11):
// 1. Call extended constructor with default offsets (line 10)
// 2. Default offsets are [0, payloadLength] for both input and output
//
// Parameters:
//   - payloadBytes: Raw payload bytes to wrap
//   - encodingType: Encoding type identifier
//
// Returns:
//   - New PayloadWrapper instance
func NewPayloadWrapper(payloadBytes []byte, encodingType byte) *PayloadWrapper {
	// du8.java line 10: this(var1, var2, new int[]{0, var1.length}, new int[]{0, var1.length})
	return NewPayloadWrapperWithOffsets(
		payloadBytes,
		encodingType,
		[]int{0, len(payloadBytes)},
		[]int{0, len(payloadBytes)},
	)
}

// NewPayloadWrapperWithOffsets creates a PayloadWrapper with custom offsets.
// Ported from: du8.java constructor (lines 13-18)
//
// Algorithm (from du8.java lines 13-18):
// 1. Store payload bytes (line 14)
// 2. Store encoding type (line 15)
// 3. Store input offsets (line 16)
// 4. Store output offsets (line 17)
//
// Parameters:
//   - payloadBytes: Raw payload bytes to wrap
//   - encodingType: Encoding type identifier
//   - offsetsIn: Input offsets for encoding
//   - offsetsOut: Output offsets for encoding
//
// Returns:
//   - New PayloadWrapper instance
func NewPayloadWrapperWithOffsets(payloadBytes []byte, encodingType byte, offsetsIn, offsetsOut []int) *PayloadWrapper {
	return &PayloadWrapper{
		// du8.java line 14: this.d = var1
		PayloadBytes: payloadBytes,
		// du8.java line 15: this.a = var2
		EncodingType: encodingType,
		// du8.java line 16: this.b = var3
		OffsetsIn: offsetsIn,
		// du8.java line 17: this.c = var4
		OffsetsOut: offsetsOut,
	}
}

// Apply creates an EncodedRequest using this wrapper and an insertion point.
// Ported from: du8.java a(iav) method (lines 20-22)
//
// Algorithm (from du8.java lines 20-22):
// 1. Create new fad instance (line 21)
// 2. Pass this wrapper and insertion point to constructor
//
// The returned EncodedRequest will lazily build the encoded request when
// EncodedBytes() or PayloadOffsets() is first called.
//
// Parameters:
//   - insertionPoint: Base insertion point that implements buildPayload/computeOffsets
//
// Returns:
//   - New EncodedRequest instance
func (w *PayloadWrapper) Apply(insertionPoint BaseInsertionPointInterface) EncodedRequest {
	// du8.java line 21: return new fad(this, var1)
	return NewEncodedRequest(w, insertionPoint)
}
