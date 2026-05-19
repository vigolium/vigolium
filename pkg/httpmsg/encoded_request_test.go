package httpmsg

// encoded_request_test.go - Tests for EncodedRequest with thread safety
// Tests synchronized caching, lazy computation, and concurrent access

import (
	"sync"
	"testing"
	"time"
)

// CountingInsertionPoint tracks how many times methods are called.
type CountingInsertionPoint struct {
	buildPayloadCount   int
	computeOffsetsCount int
	mu                  sync.Mutex
	returnBytes         []byte
	returnOffsets       []int
	// Delay to simulate expensive computation
	delay time.Duration
}

func (c *CountingInsertionPoint) BuildPayload(payloadBytes []byte, encodingType byte, offsetsIn []int) []byte {
	c.mu.Lock()
	c.buildPayloadCount++
	c.mu.Unlock()

	if c.delay > 0 {
		time.Sleep(c.delay)
	}

	return c.returnBytes
}

func (c *CountingInsertionPoint) ComputeOffsets(payloadBytes []byte, encodingType byte, offsetsOut []int) []int {
	c.mu.Lock()
	c.computeOffsetsCount++
	c.mu.Unlock()

	if c.delay > 0 {
		time.Sleep(c.delay)
	}

	return c.returnOffsets
}

func (c *CountingInsertionPoint) GetBuildPayloadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildPayloadCount
}

func (c *CountingInsertionPoint) GetComputeOffsetsCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.computeOffsetsCount
}

// TestEncodedRequestLazyCaching tests that values are computed once and cached.
func TestEncodedRequestLazyCaching(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("encoded request"),
		returnOffsets: []int{5, 15},
	}

	wrapper := NewPayloadWrapper([]byte("payload"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// First call should compute
	bytes1 := encoded.EncodedBytes()
	if counter.GetBuildPayloadCount() != 1 {
		t.Errorf("Expected BuildPayload to be called once, got %d", counter.GetBuildPayloadCount())
	}

	// Second call should use cache
	bytes2 := encoded.EncodedBytes()
	if counter.GetBuildPayloadCount() != 1 {
		t.Errorf("Expected BuildPayload to still be called once (cached), got %d", counter.GetBuildPayloadCount())
	}

	// Verify same bytes returned
	if string(bytes1) != string(bytes2) {
		t.Errorf("Cached bytes differ: %q vs %q", bytes1, bytes2)
	}

	// Test offsets caching
	offsets1 := encoded.PayloadOffsets()
	if counter.GetComputeOffsetsCount() != 1 {
		t.Errorf("Expected ComputeOffsets to be called once, got %d", counter.GetComputeOffsetsCount())
	}

	offsets2 := encoded.PayloadOffsets()
	if counter.GetComputeOffsetsCount() != 1 {
		t.Errorf("Expected ComputeOffsets to still be called once (cached), got %d", counter.GetComputeOffsetsCount())
	}

	// Verify same offsets returned
	if len(offsets1) != len(offsets2) || offsets1[0] != offsets2[0] || offsets1[1] != offsets2[1] {
		t.Errorf("Cached offsets differ: %v vs %v", offsets1, offsets2)
	}
}

// TestEncodedRequestConcurrentAccess tests thread-safe access to cached values.
func TestEncodedRequestConcurrentAccess(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("concurrent test"),
		returnOffsets: []int{10, 20},
		delay:         10 * time.Millisecond, // Simulate expensive computation
	}

	wrapper := NewPayloadWrapper([]byte("test"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// Launch multiple goroutines to access EncodedBytes concurrently
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make([][]byte, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			results[index] = encoded.EncodedBytes()
		}(i)
	}

	wg.Wait()

	// Verify BuildPayload was called exactly once (thread-safe caching)
	count := counter.GetBuildPayloadCount()
	if count != 1 {
		t.Errorf("Expected BuildPayload to be called once despite concurrent access, got %d", count)
	}

	// Verify all goroutines got the same result
	for i := 1; i < numGoroutines; i++ {
		if string(results[i]) != string(results[0]) {
			t.Errorf("Goroutine %d got different result: %q vs %q", i, results[i], results[0])
		}
	}
}

// TestEncodedRequestConcurrentOffsets tests thread-safe access to offset computation.
func TestEncodedRequestConcurrentOffsets(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("test"),
		returnOffsets: []int{15, 25},
		delay:         5 * time.Millisecond,
	}

	wrapper := NewPayloadWrapper([]byte("payload"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// Launch multiple goroutines to access PayloadOffsets concurrently
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make([][]int, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			results[index] = encoded.PayloadOffsets()
		}(i)
	}

	wg.Wait()

	// Verify ComputeOffsets was called exactly once
	count := counter.GetComputeOffsetsCount()
	if count != 1 {
		t.Errorf("Expected ComputeOffsets to be called once despite concurrent access, got %d", count)
	}

	// Verify all goroutines got the same result
	for i := 1; i < numGoroutines; i++ {
		if len(results[i]) != len(results[0]) || results[i][0] != results[0][0] || results[i][1] != results[0][1] {
			t.Errorf("Goroutine %d got different result: %v vs %v", i, results[i], results[0])
		}
	}
}

// TestEncodedRequestMixedConcurrentAccess tests concurrent access to both methods.
func TestEncodedRequestMixedConcurrentAccess(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("mixed access test"),
		returnOffsets: []int{0, 17},
		delay:         5 * time.Millisecond,
	}

	wrapper := NewPayloadWrapper([]byte("test"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// Launch goroutines accessing both methods
	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	bytesResults := make([][]byte, numGoroutines/2)
	offsetsResults := make([][]int, numGoroutines/2)

	for i := 0; i < numGoroutines; i++ {
		if i%2 == 0 {
			// Access EncodedBytes
			go func(index int) {
				defer wg.Done()
				bytesResults[index/2] = encoded.EncodedBytes()
			}(i)
		} else {
			// Access PayloadOffsets
			go func(index int) {
				defer wg.Done()
				offsetsResults[index/2] = encoded.PayloadOffsets()
			}(i)
		}
	}

	wg.Wait()

	// Verify each method was called exactly once
	if counter.GetBuildPayloadCount() != 1 {
		t.Errorf("Expected BuildPayload to be called once, got %d", counter.GetBuildPayloadCount())
	}
	if counter.GetComputeOffsetsCount() != 1 {
		t.Errorf("Expected ComputeOffsets to be called once, got %d", counter.GetComputeOffsetsCount())
	}

	// Verify consistency of results
	for i := 1; i < len(bytesResults); i++ {
		if string(bytesResults[i]) != string(bytesResults[0]) {
			t.Errorf("Bytes result %d differs: %q vs %q", i, bytesResults[i], bytesResults[0])
		}
	}
	for i := 1; i < len(offsetsResults); i++ {
		if len(offsetsResults[i]) != len(offsetsResults[0]) || offsetsResults[i][0] != offsetsResults[0][0] {
			t.Errorf("Offsets result %d differs: %v vs %v", i, offsetsResults[i], offsetsResults[0])
		}
	}
}

// TestEncodedRequestEncodingType tests EncodingType method.
func TestEncodedRequestEncodingType(t *testing.T) {
	encodingType := byte(42)
	wrapper := NewPayloadWrapper([]byte("test"), encodingType)
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("test"),
		returnOffsets: []int{0, 4},
	}
	encoded := NewEncodedRequest(wrapper, counter)

	result := encoded.EncodingType()
	if result != encodingType {
		t.Errorf("EncodingType: expected %d, got %d", encodingType, result)
	}

	// Verify this doesn't trigger computation
	if counter.GetBuildPayloadCount() != 0 {
		t.Error("EncodingType should not trigger BuildPayload")
	}
}

// TestEncodedRequestMarkers tests Markers method.
func TestEncodedRequestMarkers(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("test"),
		returnOffsets: []int{5, 15},
	}

	wrapper := NewPayloadWrapper([]byte("payload"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	markers := encoded.Markers()

	// Verify markers contain the payload offsets
	if len(markers) != 1 {
		t.Errorf("Expected 1 marker, got %d", len(markers))
	}
	if len(markers[0]) != 2 || markers[0][0] != 5 || markers[0][1] != 15 {
		t.Errorf("Expected marker [5, 15], got %v", markers[0])
	}

	// Verify this triggered ComputeOffsets once
	if counter.GetComputeOffsetsCount() != 1 {
		t.Errorf("Expected ComputeOffsets to be called once, got %d", counter.GetComputeOffsetsCount())
	}
}

// TestEncodedRequestIndependentCaches tests that bytes and offsets are cached independently.
func TestEncodedRequestIndependentCaches(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("independent"),
		returnOffsets: []int{0, 11},
	}

	wrapper := NewPayloadWrapper([]byte("test"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// Access bytes first
	_ = encoded.EncodedBytes()
	if counter.GetBuildPayloadCount() != 1 || counter.GetComputeOffsetsCount() != 0 {
		t.Error("EncodedBytes should only trigger BuildPayload")
	}

	// Then access offsets
	_ = encoded.PayloadOffsets()
	if counter.GetBuildPayloadCount() != 1 || counter.GetComputeOffsetsCount() != 1 {
		t.Error("PayloadOffsets should only trigger ComputeOffsets")
	}

	// Access bytes again - should still be cached
	_ = encoded.EncodedBytes()
	if counter.GetBuildPayloadCount() != 1 {
		t.Error("EncodedBytes should remain cached")
	}

	// Access offsets again - should still be cached
	_ = encoded.PayloadOffsets()
	if counter.GetComputeOffsetsCount() != 1 {
		t.Error("PayloadOffsets should remain cached")
	}
}

// TestEncodedRequestRaceCondition tests for race conditions with go test -race.
func TestEncodedRequestRaceCondition(t *testing.T) {
	counter := &CountingInsertionPoint{
		returnBytes:   []byte("race test"),
		returnOffsets: []int{0, 9},
		delay:         1 * time.Millisecond,
	}

	wrapper := NewPayloadWrapper([]byte("test"), 0)
	encoded := NewEncodedRequest(wrapper, counter)

	// Launch many goroutines rapidly
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 methods per goroutine

	for i := 0; i < numGoroutines; i++ {
		// Access EncodedBytes
		go func() {
			defer wg.Done()
			_ = encoded.EncodedBytes()
		}()

		// Access PayloadOffsets
		go func() {
			defer wg.Done()
			_ = encoded.PayloadOffsets()
		}()

		// Access Markers
		go func() {
			defer wg.Done()
			_ = encoded.Markers()
		}()
	}

	wg.Wait()

	// Verify methods were called exactly once each
	if counter.GetBuildPayloadCount() != 1 {
		t.Errorf("BuildPayload called %d times (expected 1)", counter.GetBuildPayloadCount())
	}
	if counter.GetComputeOffsetsCount() != 1 {
		t.Errorf("ComputeOffsets called %d times (expected 1)", counter.GetComputeOffsetsCount())
	}
}
