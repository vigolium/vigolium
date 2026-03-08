package payload

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// BuiltInListType identifies which wordlist type.
type BuiltInListType int

const (
	ShortFileList BuiltInListType = iota
	LongFileList
	ShortDirList
	LongDirList
)

// String returns the string representation of the list type.
func (t BuiltInListType) String() string {
	switch t {
	case ShortFileList:
		return "short-files"
	case LongFileList:
		return "long-files"
	case ShortDirList:
		return "short-dirs"
	case LongDirList:
		return "long-dirs"
	case CustomListType:
		return "custom"
	default:
		return "unknown"
	}
}

// normalizeAndDedup converts all payloads to lowercase and removes duplicates.
// Done ONCE at load time, not on every Next() call.
func normalizeAndDedup(payloads [][]byte) [][]byte {
	seen := make(map[string]struct{}, len(payloads))
	result := make([][]byte, 0, len(payloads))

	for _, p := range payloads {
		normalized := strings.ToLower(string(p))
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, []byte(normalized))
	}

	return result
}

// loadWordlist reads a wordlist file line by line.
// Format: one payload per line (not bytes).
// Trims whitespace and skips empty lines.
func loadWordlist(filePath string) ([][]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var payloads [][]byte
	scanner := bufio.NewScanner(file)
	// Set max line size to 1MB to handle large payloads
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		// Get line as string (NOT bytes)
		line := scanner.Text()

		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Convert string to bytes
		payload := []byte(line)
		payloads = append(payloads, payload)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist at line %d: %w", lineNum, err)
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("wordlist is empty: %s", filePath)
	}

	return payloads, nil
}
