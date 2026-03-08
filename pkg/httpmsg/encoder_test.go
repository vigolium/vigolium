package httpmsg

// Standalone test file that can be run independently to verify encoder implementations
// This file tests the new encoders without dependencies on the rest of the package

import (
	"bytes"
	"testing"
)

// TestURLEncoderStandalone tests URL encoder in isolation
func TestURLEncoderStandalone(t *testing.T) {
	encoder := NewURLEncoder()

	// Test basic encoding
	input := []byte("hello world")
	offsets := []int{0, 0}
	result := encoder.Encode(input, offsets)
	expected := "hello%20world"

	if string(result) != expected {
		t.Errorf("URL encoding failed: got %q, expected %q", string(result), expected)
	}

	// Test decoding
	decoded := encoder.Decode(result)
	if string(decoded) != string(input) {
		t.Errorf("URL decoding failed: got %q, expected %q", string(decoded), string(input))
	}
}

// TestURLEncoderExtendedStandalone tests extended URL encoder in isolation
func TestURLEncoderExtendedStandalone(t *testing.T) {
	encoder := NewURLEncoderExtended()

	// Set a character mapping: replace 'a' with "XXX"
	encoder.SetCharMapping('a', []byte("XXX"))

	input := []byte("bar")
	offsets := []int{0, 0}
	result := encoder.Encode(input, offsets)
	expected := "bXXXr"

	if string(result) != expected {
		t.Errorf("Extended URL encoding failed: got %q, expected %q", string(result), expected)
	}

	// Test that special chars are still encoded
	input = []byte("a=b")
	offsets = []int{0, 0}
	result = encoder.Encode(input, offsets)
	// 'a' -> "XXX", '=' -> "%3D", 'b' -> "b"
	expected = "XXX%3Db"

	if string(result) != expected {
		t.Errorf("Extended URL encoding with special chars: got %q, expected %q", string(result), expected)
	}
}

// TestBase64EncoderStandalone tests Base64 encoder in isolation
func TestBase64EncoderStandalone(t *testing.T) {
	encoder := NewBase64Encoder()

	// Test encoding
	input := []byte("hello")
	offsets := []int{0, 0}
	result := encoder.Encode(input, offsets)
	expected := "aGVsbG8="

	if string(result) != expected {
		t.Errorf("Base64 encoding failed: got %q, expected %q", string(result), expected)
	}

	// Test decoding
	decoded := encoder.Decode(result)
	if string(decoded) != string(input) {
		t.Errorf("Base64 decoding failed: got %q, expected %q", string(decoded), string(input))
	}

	// Test binary data
	binaryInput := []byte{0x01, 0x02, 0x03}
	offsets = []int{0, 0}
	encoded := encoder.Encode(binaryInput, offsets)
	decodedBinary := encoder.Decode(encoded)

	if !bytes.Equal(decodedBinary, binaryInput) {
		t.Errorf("Base64 binary round-trip failed: got %v, expected %v", decodedBinary, binaryInput)
	}
}

// TestGzipEncoderStandalone tests Gzip encoder in isolation
func TestGzipEncoderStandalone(t *testing.T) {
	encoder := NewGzipEncoder()

	// Test compression
	input := []byte("hello world hello world hello world")
	offsets := []int{0, 0}
	compressed := encoder.Encode(input, offsets)

	// Compressed should be different from input
	if bytes.Equal(compressed, input) {
		t.Errorf("Gzip compression did not change the data")
	}

	// Test decompression
	decompressed := encoder.Decode(compressed)
	if string(decompressed) != string(input) {
		t.Errorf("Gzip decompression failed: got %q, expected %q", string(decompressed), string(input))
	}

	// Verify offsets are reset
	if offsets[0] != 0 || offsets[1] != len(compressed) {
		t.Errorf("Gzip offset tracking failed: got [%d, %d], expected [0, %d]", offsets[0], offsets[1], len(compressed))
	}
}

// TestAllEncodersRoundTrip tests that all encoders can round-trip data
func TestAllEncodersRoundTrip(t *testing.T) {
	testData := []byte("The quick brown fox jumps over the lazy dog")

	encoders := []struct {
		name    string
		encoder interface {
			Encode([]byte, []int) []byte
			Decode([]byte) []byte
		}
	}{
		{"URLEncoder", NewURLEncoder()},
		{"URLEncoderExtended", NewURLEncoderExtended()},
		{"Base64Encoder", NewBase64Encoder()},
		{"GzipEncoder", NewGzipEncoder()},
	}

	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			offsets := []int{0, 0}
			encoded := enc.encoder.Encode(testData, offsets)
			decoded := enc.encoder.Decode(encoded)

			if !bytes.Equal(decoded, testData) {
				t.Errorf("%s round-trip failed: got %q, expected %q", enc.name, string(decoded), string(testData))
			}
		})
	}
}

// TestURLEncoderOffsetTracking tests offset tracking in URL encoder
func TestURLEncoderOffsetTracking(t *testing.T) {
	encoder := NewURLEncoder()

	// "a=b" -> "a%3Db"
	// Position 1 (the '=') becomes position 1
	// Position 2 (end) becomes position 4
	input := []byte("a=b")
	offsets := []int{1, 2}
	result := encoder.Encode(input, offsets)

	expected := "a%3Db"
	if string(result) != expected {
		t.Errorf("Encoding failed: got %q, expected %q", string(result), expected)
	}

	// Offset 1 should stay at 1 (before the '=')
	// Offset 2 should move to 4 (after the encoded '=')
	if offsets[0] != 1 {
		t.Errorf("Start offset: got %d, expected 1", offsets[0])
	}
	if offsets[1] != 4 {
		t.Errorf("End offset: got %d, expected 4", offsets[1])
	}
}

// TestURLEncoderAllowedChars tests custom allowed characters
func TestURLEncoderAllowedChars(t *testing.T) {
	encoder := NewURLEncoder()

	// Without allowing '/', it should be encoded
	input := []byte("/path")
	offsets := []int{0, 0}
	result := encoder.Encode(input, offsets)
	if string(result) != "%2Fpath" {
		t.Errorf("Without allowed '/': got %q, expected %q", string(result), "%2Fpath")
	}

	// Add '/' to allowed set
	encoder.AddAllowedChar('/')
	offsets = []int{0, 0}
	result = encoder.Encode(input, offsets)
	if string(result) != "/path" {
		t.Errorf("With allowed '/': got %q, expected %q", string(result), "/path")
	}

	// Remove '/' from allowed set
	encoder.RemoveAllowedChar('/')
	offsets = []int{0, 0}
	result = encoder.Encode(input, offsets)
	if string(result) != "%2Fpath" {
		t.Errorf("After removing '/': got %q, expected %q", string(result), "%2Fpath")
	}
}

// TestBase64MIMEMode tests MIME mode with line breaks
func TestBase64MIMEMode(t *testing.T) {
	encoder := NewBase64MIMEEncoder()

	// Create long input that will trigger line breaks
	input := bytes.Repeat([]byte("a"), 100)
	offsets := []int{0, 0}
	result := encoder.Encode(input, offsets)

	// MIME mode should have line breaks for long input
	if len(result) > 76 && !bytes.Contains(result, []byte("\n")) {
		t.Errorf("MIME encoding should contain line breaks for long input")
	}

	// Should still decode correctly
	decoded := encoder.Decode(result)
	if !bytes.Equal(decoded, input) {
		t.Errorf("MIME decoding failed")
	}
}

// TestGzipConvenienceFunctions tests the standalone compress/decompress functions
func TestGzipConvenienceFunctions(t *testing.T) {
	input := []byte("test data for compression")

	compressed := CompressBytes(input)
	if bytes.Equal(compressed, input) {
		t.Errorf("CompressBytes did not compress the data")
	}

	decompressed := DecompressBytes(compressed)
	if !bytes.Equal(decompressed, input) {
		t.Errorf("DecompressBytes failed: got %q, expected %q", string(decompressed), string(input))
	}
}

// TestEncoderNilHandling tests nil input handling across all encoders
func TestEncoderNilHandling(t *testing.T) {
	t.Run("URLEncoder", func(t *testing.T) {
		encoder := NewURLEncoder()
		offsets := []int{0, 0}
		result := encoder.Encode(nil, offsets)
		if result != nil {
			t.Errorf("Encode(nil) should return nil")
		}
		result = encoder.Decode(nil)
		if result != nil {
			t.Errorf("Decode(nil) should return nil")
		}
	})

	t.Run("URLEncoderExtended", func(t *testing.T) {
		encoder := NewURLEncoderExtended()
		offsets := []int{0, 0}
		result := encoder.Encode(nil, offsets)
		if result != nil {
			t.Errorf("Encode(nil) should return nil")
		}
		result = encoder.Decode(nil)
		if result != nil {
			t.Errorf("Decode(nil) should return nil")
		}
	})

	t.Run("Base64Encoder", func(t *testing.T) {
		encoder := NewBase64Encoder()
		offsets := []int{0, 0}
		result := encoder.Encode(nil, offsets)
		if result != nil {
			t.Errorf("Encode(nil) should return nil")
		}
		result = encoder.Decode(nil)
		if result != nil {
			t.Errorf("Decode(nil) should return nil")
		}
	})

	t.Run("GzipEncoder", func(t *testing.T) {
		encoder := NewGzipEncoder()
		offsets := []int{0, 0}
		result := encoder.Encode(nil, offsets)
		if result != nil {
			t.Errorf("Encode(nil) should return nil")
		}
		result = encoder.Decode(nil)
		if result != nil {
			t.Errorf("Decode(nil) should return nil")
		}
	})
}
