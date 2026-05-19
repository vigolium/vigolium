package httpmsg

// payload_wrapper.go - Payload wrapper for insertion point encoding
//
// This file implements a wrapper around payload bytes that tracks encoding type
// and offset information. It provides the data needed to build encoded requests.
//
// Key features:
// - Stores payload bytes and encoding type
// - Tracks input/output offsets for encoding
// - Creates EncodedRequest via Apply() method
// - Provides static accessor methods for offset arrays

// PayloadWrapper wraps a payload with encoding metadata.
// The wrapper acts as a data container that insertion points use to build
// encoded requests with proper offset tracking.
//
// Example:
//
//	wrapper := NewPayloadWrapper([]byte("test"), 0)
//	encoded := wrapper.Apply(insertionPoint)
//	bytes := encoded.EncodedBytes()
type PayloadWrapper struct {
	PayloadBytes []byte
	EncodingType byte
	OffsetsIn    []int
	OffsetsOut   []int
}

// NewPayloadWrapper creates a new PayloadWrapper with default offsets.
// Default offsets are [0, payloadLength] for both input and output.
//
// Parameters:
//   - payloadBytes: Raw payload bytes to wrap
//   - encodingType: Encoding type identifier
//
// Returns:
//   - New PayloadWrapper instance
func NewPayloadWrapper(payloadBytes []byte, encodingType byte) *PayloadWrapper {
	return NewPayloadWrapperWithOffsets(
		payloadBytes,
		encodingType,
		[]int{0, len(payloadBytes)},
		[]int{0, len(payloadBytes)},
	)
}

// NewPayloadWrapperWithOffsets creates a PayloadWrapper with custom offsets.
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
		PayloadBytes: payloadBytes,
		EncodingType: encodingType,
		OffsetsIn:    offsetsIn,
		OffsetsOut:   offsetsOut,
	}
}

// Apply creates an EncodedRequest using this wrapper and an insertion point.
// The returned EncodedRequest will lazily build the encoded request when
// EncodedBytes() or PayloadOffsets() is first called.
//
// Parameters:
//   - insertionPoint: Base insertion point that implements buildPayload/computeOffsets
//
// Returns:
//   - New EncodedRequest instance
func (w *PayloadWrapper) Apply(insertionPoint BaseInsertionPointInterface) EncodedRequest {
	return NewEncodedRequest(w, insertionPoint)
}
