package httpmsg

// payload_wrapper_test.go - Tests for PayloadWrapper
// Tests wrapper creation, field access, and Apply method

import (
	"testing"
)

// MockInsertionPoint implements BaseInsertionPointInterface for testing.
type MockInsertionPoint struct {
	buildPayloadCalled   bool
	computeOffsetsCalled bool
	lastPayloadBytes     []byte
	lastEncodingType     byte
	lastOffsetsIn        []int
	lastOffsetsOut       []int
	returnBytes          []byte
	returnOffsets        []int
}

func (m *MockInsertionPoint) BuildPayload(payloadBytes []byte, encodingType byte, offsetsIn []int) []byte {
	m.buildPayloadCalled = true
	m.lastPayloadBytes = payloadBytes
	m.lastEncodingType = encodingType
	m.lastOffsetsIn = offsetsIn
	return m.returnBytes
}

func (m *MockInsertionPoint) ComputeOffsets(payloadBytes []byte, encodingType byte, offsetsOut []int) []int {
	m.computeOffsetsCalled = true
	m.lastPayloadBytes = payloadBytes
	m.lastEncodingType = encodingType
	m.lastOffsetsOut = offsetsOut
	return m.returnOffsets
}

// TestNewPayloadWrapper tests creating a wrapper with default offsets.
func TestNewPayloadWrapper(t *testing.T) {
	payload := []byte("test payload")
	encodingType := byte(5)

	wrapper := NewPayloadWrapper(payload, encodingType)

	// Verify fields
	if string(wrapper.PayloadBytes) != string(payload) {
		t.Errorf("PayloadBytes: expected %q, got %q", payload, wrapper.PayloadBytes)
	}
	if wrapper.EncodingType != encodingType {
		t.Errorf("EncodingType: expected %d, got %d", encodingType, wrapper.EncodingType)
	}

	// Verify default offsets are [0, len(payload)]
	expectedOffsets := []int{0, len(payload)}
	if len(wrapper.OffsetsIn) != 2 || wrapper.OffsetsIn[0] != expectedOffsets[0] || wrapper.OffsetsIn[1] != expectedOffsets[1] {
		t.Errorf("OffsetsIn: expected %v, got %v", expectedOffsets, wrapper.OffsetsIn)
	}
	if len(wrapper.OffsetsOut) != 2 || wrapper.OffsetsOut[0] != expectedOffsets[0] || wrapper.OffsetsOut[1] != expectedOffsets[1] {
		t.Errorf("OffsetsOut: expected %v, got %v", expectedOffsets, wrapper.OffsetsOut)
	}
}

// TestNewPayloadWrapperWithOffsets tests creating a wrapper with custom offsets.
func TestNewPayloadWrapperWithOffsets(t *testing.T) {
	payload := []byte("test")
	encodingType := byte(3)
	offsetsIn := []int{0, 2}
	offsetsOut := []int{1, 3}

	wrapper := NewPayloadWrapperWithOffsets(payload, encodingType, offsetsIn, offsetsOut)

	// Verify fields
	if string(wrapper.PayloadBytes) != string(payload) {
		t.Errorf("PayloadBytes: expected %q, got %q", payload, wrapper.PayloadBytes)
	}
	if wrapper.EncodingType != encodingType {
		t.Errorf("EncodingType: expected %d, got %d", encodingType, wrapper.EncodingType)
	}

	// Verify custom offsets
	if len(wrapper.OffsetsIn) != 2 || wrapper.OffsetsIn[0] != offsetsIn[0] || wrapper.OffsetsIn[1] != offsetsIn[1] {
		t.Errorf("OffsetsIn: expected %v, got %v", offsetsIn, wrapper.OffsetsIn)
	}
	if len(wrapper.OffsetsOut) != 2 || wrapper.OffsetsOut[0] != offsetsOut[0] || wrapper.OffsetsOut[1] != offsetsOut[1] {
		t.Errorf("OffsetsOut: expected %v, got %v", offsetsOut, wrapper.OffsetsOut)
	}
}

// TestPayloadWrapperApply tests the Apply method creates an EncodedRequest.
func TestPayloadWrapperApply(t *testing.T) {
	payload := []byte("test payload")
	encodingType := byte(7)
	wrapper := NewPayloadWrapper(payload, encodingType)

	// Create mock insertion point
	mock := &MockInsertionPoint{
		returnBytes:   []byte("encoded request"),
		returnOffsets: []int{10, 22},
	}

	// Apply wrapper to create EncodedRequest
	encoded := wrapper.Apply(mock)

	// Verify EncodedRequest was created
	if encoded == nil {
		t.Fatal("Apply() returned nil")
	}

	// Verify EncodingType
	if encoded.EncodingType() != encodingType {
		t.Errorf("EncodingType: expected %d, got %d", encodingType, encoded.EncodingType())
	}

	// Verify EncodedBytes calls BuildPayload
	bytes := encoded.EncodedBytes()
	if !mock.buildPayloadCalled {
		t.Error("BuildPayload was not called")
	}
	if string(bytes) != string(mock.returnBytes) {
		t.Errorf("EncodedBytes: expected %q, got %q", mock.returnBytes, bytes)
	}
	if string(mock.lastPayloadBytes) != string(payload) {
		t.Errorf("BuildPayload received wrong payload: expected %q, got %q", payload, mock.lastPayloadBytes)
	}
	if mock.lastEncodingType != encodingType {
		t.Errorf("BuildPayload received wrong encodingType: expected %d, got %d", encodingType, mock.lastEncodingType)
	}

	// Verify PayloadOffsets calls ComputeOffsets
	offsets := encoded.PayloadOffsets()
	if !mock.computeOffsetsCalled {
		t.Error("ComputeOffsets was not called")
	}
	if len(offsets) != len(mock.returnOffsets) || offsets[0] != mock.returnOffsets[0] || offsets[1] != mock.returnOffsets[1] {
		t.Errorf("PayloadOffsets: expected %v, got %v", mock.returnOffsets, offsets)
	}
}

// TestPayloadWrapperGetOffsets tests the offset accessor methods.
func TestPayloadWrapperGetOffsets(t *testing.T) {
	offsetsIn := []int{5, 10}
	offsetsOut := []int{15, 20}
	wrapper := NewPayloadWrapperWithOffsets([]byte("test"), 0, offsetsIn, offsetsOut)

	// Test GetOffsetsIn
	in := wrapper.OffsetsIn
	if len(in) != 2 || in[0] != offsetsIn[0] || in[1] != offsetsIn[1] {
		t.Errorf("GetOffsetsIn: expected %v, got %v", offsetsIn, in)
	}

	// Test GetOffsetsOut
	out := wrapper.OffsetsOut
	if len(out) != 2 || out[0] != offsetsOut[0] || out[1] != offsetsOut[1] {
		t.Errorf("GetOffsetsOut: expected %v, got %v", offsetsOut, out)
	}
}

// TestPayloadWrapperEmptyPayload tests wrapper with empty payload.
func TestPayloadWrapperEmptyPayload(t *testing.T) {
	payload := []byte("")
	wrapper := NewPayloadWrapper(payload, 0)

	// Verify empty payload
	if len(wrapper.PayloadBytes) != 0 {
		t.Errorf("Expected empty payload, got length %d", len(wrapper.PayloadBytes))
	}

	// Verify offsets are [0, 0]
	expectedOffsets := []int{0, 0}
	if len(wrapper.OffsetsIn) != 2 || wrapper.OffsetsIn[0] != 0 || wrapper.OffsetsIn[1] != 0 {
		t.Errorf("OffsetsIn: expected %v, got %v", expectedOffsets, wrapper.OffsetsIn)
	}
}

// TestPayloadWrapperOffsetTracking tests that offsets are properly passed through.
func TestPayloadWrapperOffsetTracking(t *testing.T) {
	payload := []byte("payload")
	offsetsIn := []int{2, 5}
	offsetsOut := []int{10, 15}
	wrapper := NewPayloadWrapperWithOffsets(payload, 1, offsetsIn, offsetsOut)

	mock := &MockInsertionPoint{
		returnBytes:   []byte("result"),
		returnOffsets: []int{10, 15},
	}

	encoded := wrapper.Apply(mock)

	// Trigger BuildPayload
	_ = encoded.EncodedBytes()

	// Verify offsetsIn were passed correctly
	if len(mock.lastOffsetsIn) != 2 || mock.lastOffsetsIn[0] != 2 || mock.lastOffsetsIn[1] != 5 {
		t.Errorf("BuildPayload received wrong offsetsIn: expected %v, got %v", offsetsIn, mock.lastOffsetsIn)
	}

	// Trigger ComputeOffsets
	_ = encoded.PayloadOffsets()

	// Verify offsetsOut were passed correctly
	if len(mock.lastOffsetsOut) != 2 || mock.lastOffsetsOut[0] != 10 || mock.lastOffsetsOut[1] != 15 {
		t.Errorf("ComputeOffsets received wrong offsetsOut: expected %v, got %v", offsetsOut, mock.lastOffsetsOut)
	}
}
