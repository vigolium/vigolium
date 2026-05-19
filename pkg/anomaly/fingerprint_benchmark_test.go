package anomaly

import (
	"testing"
)

/*
BenchmarkFingerprint_Update_TwoFingerprints
BenchmarkFingerprint_Update_TwoFingerprints-24
 4150537	       279.3 ns/op	     320 B/op	       4 allocs/op
BenchmarkFingerprint_Update_ThreeFingerprints
BenchmarkFingerprint_Update_ThreeFingerprints-24
 3272282	       372.9 ns/op	     320 B/op	       4 allocs/op
BenchmarkFingerprint_Update_TwoFingerprints_DifferentData
BenchmarkFingerprint_Update_TwoFingerprints_DifferentData-24
 3868497	       307.9 ns/op	     320 B/op	       4 allocs/op

--------------------------------------------------------------------------

# Benchmark Results Explained
The benchmark results you've provided give insights into the performance characteristics of your update() method under different conditions. Here's a breakdown of each line and what it means:

### Benchmark Results Explained

1. **BenchmarkFingerprint_Update_TwoFingerprints**
   - **4150537**: This is the number of iterations the benchmark loop ran.
   - **279.3 ns/op**: This indicates that each operation (a single update cycle with two fingerprints) took an average of 279.3 nanoseconds.
   - **320 B/op**: This shows that each operation required 320 bytes of memory allocation.
   - **4 allocs/op**: This indicates that there were 4 memory allocations per operation.

2. **BenchmarkFingerprint_Update_ThreeFingerprints**
   - **3272282**: Number of iterations for the benchmark loop.
   - **372.9 ns/op**: Each operation (a single update cycle with three fingerprints) took an average of 372.9 nanoseconds.
   - **320 B/op**: Each operation required the same 320 bytes of memory allocation as the two fingerprint updates.
   - **4 allocs/op**: Same number of memory allocations per operation as the two fingerprint updates.

3. **BenchmarkFingerprint_Update_TwoFingerprints_DifferentData**
   - **3868497**: Number of iterations for the benchmark loop.
   - **307.9 ns/op**: Each operation (a single update cycle with two different sets of fingerprint data) took an average of 307.9 nanoseconds.
   - **320 B/op**: Each operation required 320 bytes of memory allocation.
   - **4 allocs/op**: There were 4 memory allocations per operation.

### Analysis

- **Performance**: The update() method is quite fast, with operations taking between 279.3 and 372.9 nanoseconds. The addition of a third fingerprint increases the time per operation, as expected due to the additional processing required.
- **Memory Usage**: Memory allocation is consistent across different tests (320 B/op), which suggests that your method handles memory in a consistent manner regardless of the input complexity.
- **Allocations**: The consistent number of allocations (4 allocs/op) across different scenarios indicates that your method's memory allocation behavior does not change with different data inputs or numbers of updates.

### Is It Okay for Your Code Functionality?

- **Efficiency**: The benchmarks suggest that the update() method is efficient in terms of both time and space. The execution time and memory usage are quite reasonable for typical web server operations.
- **Consistency**: The consistent memory usage and allocation count across different test scenarios suggest that the method behaves predictably under varying conditions, which is good for reliability.
- **Areas for Improvement**: If performance is critical, you might explore ways to reduce the number of allocations per operation, potentially by reusing objects or optimizing data structures.

Overall, the benchmark results indicate that your update() method performs well. If these performance metrics are within acceptable limits for your application's requirements, then the method is likely okay for your code functionality. If you have specific performance targets or are operating in a resource-constrained environment, further optimizations might be necessary.
*/

func BenchmarkFingerprint_Update_TwoFingerprints(b *testing.B) {
	data1 := map[Type]uint32{
		STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 999,
	}
	data2 := map[Type]uint32{
		STATUS_CODE: 200, ETAG_HEADER: 101, SERVER_HEADER: 124, SET_COOKIE_NAMES: 998,
	}
	fingerprintTypes := []Type{STATUS_CODE, ETAG_HEADER, SERVER_HEADER, SET_COOKIE_NAMES}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := NewFingerprint(fingerprintTypes)
		f.update(data1)
		f.update(data2)
	}
}

func BenchmarkFingerprint_Update_ThreeFingerprints(b *testing.B) {
	data1 := map[Type]uint32{
		STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 999,
	}
	data2 := map[Type]uint32{
		STATUS_CODE: 200, ETAG_HEADER: 101, SERVER_HEADER: 124, SET_COOKIE_NAMES: 998,
	}
	data3 := map[Type]uint32{
		STATUS_CODE: 201, ETAG_HEADER: 102, SERVER_HEADER: 125, SET_COOKIE_NAMES: 997,
	}
	fingerprintTypes := []Type{STATUS_CODE, ETAG_HEADER, SERVER_HEADER, SET_COOKIE_NAMES}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := NewFingerprint(fingerprintTypes)
		f.update(data1)
		f.update(data2)
		f.update(data3)
	}
}

func BenchmarkFingerprint_Update_TwoFingerprints_DifferentData(b *testing.B) {
	data1 := map[Type]uint32{
		STATUS_CODE: 202, ETAG_HEADER: 103, SERVER_HEADER: 126, SET_COOKIE_NAMES: 996,
	}
	data2 := map[Type]uint32{
		STATUS_CODE: 203, ETAG_HEADER: 104, SERVER_HEADER: 127, SET_COOKIE_NAMES: 995,
	}
	fingerprintTypes := []Type{STATUS_CODE, ETAG_HEADER, SERVER_HEADER, SET_COOKIE_NAMES}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := NewFingerprint(fingerprintTypes)
		f.update(data1)
		f.update(data2)
	}
}

func BenchmarkFingerprint_Update_AllTypes(b *testing.B) {
	data1 := map[Type]uint32{
		STATUS_CODE:                 200,
		LINE_COUNT:                  10,
		WORD_COUNT:                  100,
		WHOLE_BODY_CONTENT:          12345,
		LIMITED_BODY_CONTENT:        123,
		INITIAL_BODY_CONTENT:        456,
		CONTENT_TYPE:                1,
		CONTENT_LENGTH:              5000,
		CONTENT_LOCATION:            2,
		ETAG_HEADER:                 100,
		SERVER_HEADER:               123,
		STATUS_CODE_TEXT:            3,
		LAST_MODIFIED_HEADER:        4,
		LOCATION:                    5,
		SET_COOKIE_NAMES:            999,
		PAGE_TITLE:                  6,
		COMMENTS:                    7,
		CSS_CLASSES:                 8,
		CANONICAL_LINK:              9,
		FIRST_HEADER_TAG:            10,
		HEADER_TAGS:                 11,
		DIV_IDS:                     12,
		TAG_IDS:                     13,
		TAG_NAMES:                   14,
		VISIBLE_TEXT:                15,
		VISIBLE_WORD_COUNT:          16,
		OUTBOUND_EDGE_TAG_NAMES:     17,
		OUTBOUND_EDGE_COUNT:         18,
		ANCHOR_LABELS:               19,
		INPUT_IMAGE_LABELS:          20,
		INPUT_SUBMIT_LABELS:         21,
		BUTTON_SUBMIT_LABELS:        22,
		NON_HIDDEN_FORM_INPUT_TYPES: 23,
	}
	data2 := map[Type]uint32{
		STATUS_CODE:                 201,
		LINE_COUNT:                  11,
		WORD_COUNT:                  101,
		WHOLE_BODY_CONTENT:          12346,
		LIMITED_BODY_CONTENT:        124,
		INITIAL_BODY_CONTENT:        457,
		CONTENT_TYPE:                2,
		CONTENT_LENGTH:              5001,
		CONTENT_LOCATION:            3,
		ETAG_HEADER:                 101,
		SERVER_HEADER:               124,
		STATUS_CODE_TEXT:            4,
		LAST_MODIFIED_HEADER:        5,
		LOCATION:                    6,
		SET_COOKIE_NAMES:            998,
		PAGE_TITLE:                  7,
		COMMENTS:                    8,
		CSS_CLASSES:                 9,
		CANONICAL_LINK:              10,
		FIRST_HEADER_TAG:            11,
		HEADER_TAGS:                 12,
		DIV_IDS:                     13,
		TAG_IDS:                     14,
		TAG_NAMES:                   15,
		VISIBLE_TEXT:                16,
		VISIBLE_WORD_COUNT:          17,
		OUTBOUND_EDGE_TAG_NAMES:     18,
		OUTBOUND_EDGE_COUNT:         19,
		ANCHOR_LABELS:               20,
		INPUT_IMAGE_LABELS:          21,
		INPUT_SUBMIT_LABELS:         22,
		BUTTON_SUBMIT_LABELS:        23,
		NON_HIDDEN_FORM_INPUT_TYPES: 24,
	}
	fingerprintTypes := AllFingerprintAttributes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := NewFingerprint(fingerprintTypes)
		f.update(data1)
		f.update(data2)
	}
}
