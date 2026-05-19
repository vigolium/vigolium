package wordlist

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

// JSONPreprocessor extracts string keys and values from JSON.
type JSONPreprocessor struct{}

// Process extracts string keys and string values from JSON.
// Numbers, booleans, and nulls are skipped.
func (p *JSONPreprocessor) Process(_ context.Context, reader io.Reader) (io.Reader, error) {
	decoder := json.NewDecoder(reader)
	var output bytes.Buffer

	// Track nesting to determine if we're reading a key or value
	expectingKey := false
	var parseErr error

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// On parse error, save it and return what we have so far
			parseErr = err
			break
		}

		switch v := token.(type) {
		case json.Delim:
			switch v {
			case '{':
				expectingKey = true
			case '}':
				expectingKey = false
			case '[':
				expectingKey = false
			case ']':
				expectingKey = false
			}

		case string:
			// Output the string (whether key or value)
			if len(v) > 0 {
				output.WriteString(v)
				output.WriteByte(' ')
			}
			// After a key, we expect a value (not a key)
			if expectingKey {
				expectingKey = false
			}

		case float64:
			// Skip numbers, but toggle key expectation
			if !expectingKey {
				expectingKey = true
			}

		case bool:
			// Skip booleans
			if !expectingKey {
				expectingKey = true
			}

		case nil:
			// Skip nulls
			if !expectingKey {
				expectingKey = true
			}
		}
	}

	return bytes.NewReader(output.Bytes()), parseErr
}

// ContentTypes returns the MIME types handled by this preprocessor.
func (p *JSONPreprocessor) ContentTypes() []string {
	return []string{
		"json", // Matches application/json, text/json, application/vnd.api+json, etc.
	}
}
