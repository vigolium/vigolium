package authzutil

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// GenerateNeighborIDs produces candidate neighbor IDs for a given base value
// based on its detected IDType. Returns nil for unpredictable types (UUIDv4, Hex, Unknown).
func GenerateNeighborIDs(baseValue string, idType IDType, count int) []string {
	if baseValue == "" || count <= 0 {
		return nil
	}

	switch idType {
	case SequentialInt:
		return neighborSequentialInt(baseValue, count)
	case StructuredCode:
		return neighborStructuredCode(baseValue, count)
	case Base64Int:
		return neighborBase64Int(baseValue, count)
	case UUIDv1:
		return neighborUUIDv1(baseValue, count)
	case Email:
		return neighborEmail(baseValue, count)
	default:
		// UUIDv4, Hex, Unknown, ShortNumeric, Slug — unpredictable
		return nil
	}
}

// neighborSequentialInt generates ±1, ±10, and 1 neighbors for integer IDs.
// Preserves zero-padding (e.g., "0042" → "0041", "0043").
func neighborSequentialInt(value string, count int) []string {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil
	}

	padding := 0
	if len(value) > 1 && value[0] == '0' {
		padding = len(value)
	}

	offsets := []int64{1, -1, 10, -10}
	seen := make(map[string]struct{})
	var results []string

	for _, off := range offsets {
		candidate := n + off
		if candidate < 0 {
			continue
		}
		var s string
		if padding > 0 {
			s = fmt.Sprintf("%0*d", padding, candidate)
		} else {
			s = strconv.FormatInt(candidate, 10)
		}
		if s == value {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		results = append(results, s)
		if len(results) >= count {
			return results
		}
	}

	// Add "1" as a common ID if not already the original
	if _, ok := seen["1"]; !ok && value != "1" && len(results) < count {
		if padding > 0 {
			s := fmt.Sprintf("%0*d", padding, 1)
			if s != value {
				results = append(results, s)
			}
		} else {
			results = append(results, "1")
		}
	}

	return results
}

// neighborStructuredCode increments/decrements the last numeric segment of a structured code.
// E.g., "ORD-00042" → ["ORD-00041", "ORD-00043"].
func neighborStructuredCode(value string, count int) []string {
	// Find the last hyphen to isolate the numeric suffix
	lastDash := strings.LastIndex(value, "-")
	if lastDash < 0 || lastDash >= len(value)-1 {
		return nil
	}

	prefix := value[:lastDash+1]
	suffix := value[lastDash+1:]

	n, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil {
		return nil
	}

	padding := 0
	if len(suffix) > 1 && suffix[0] == '0' {
		padding = len(suffix)
	}

	offsets := []int64{-1, 1}
	var results []string

	for _, off := range offsets {
		candidate := n + off
		if candidate < 0 {
			continue
		}
		var s string
		if padding > 0 {
			s = prefix + fmt.Sprintf("%0*d", padding, candidate)
		} else {
			s = prefix + strconv.FormatInt(candidate, 10)
		}
		if s == value {
			continue
		}
		results = append(results, s)
		if len(results) >= count {
			return results
		}
	}

	return results
}

// neighborBase64Int decodes a base64-encoded integer, generates ±1 neighbors,
// and re-encodes with the same encoding variant.
func neighborBase64Int(value string, count int) []string {
	type encodingVariant struct {
		enc  *base64.Encoding
		name string
	}
	variants := []encodingVariant{
		{base64.StdEncoding, "std"},
		{base64.RawStdEncoding, "raw-std"},
		{base64.URLEncoding, "url"},
		{base64.RawURLEncoding, "raw-url"},
	}

	for _, v := range variants {
		decoded, err := v.enc.DecodeString(value)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(decoded))
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			continue
		}

		offsets := []int64{1, -1}
		var results []string
		for _, off := range offsets {
			candidate := n + off
			if candidate < 0 {
				continue
			}
			encoded := v.enc.EncodeToString([]byte(strconv.FormatInt(candidate, 10)))
			if encoded == value {
				continue
			}
			results = append(results, encoded)
			if len(results) >= count {
				return results
			}
		}
		return results
	}

	return nil
}

// neighborUUIDv1 flips the last byte of the node section ±1.
// E.g., "...-ee01" → "...-ee02", "...-ee00".
func neighborUUIDv1(value string, count int) []string {
	if len(value) != 36 {
		return nil
	}

	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// Node section is the last 12 hex chars (positions 24-35 after removing hyphens)
	// Last byte = last 2 hex chars of the UUID string
	lastTwo := value[34:36]
	b, err := strconv.ParseUint(lastTwo, 16, 8)
	if err != nil {
		return nil
	}

	var results []string
	offsets := []int{1, -1}
	for _, off := range offsets {
		candidate := int(b) + off
		if candidate < 0 || candidate > 255 {
			continue
		}
		newUUID := value[:34] + fmt.Sprintf("%02x", candidate)
		if newUUID == value {
			continue
		}
		results = append(results, newUUID)
		if len(results) >= count {
			return results
		}
	}

	return results
}

// neighborEmail replaces the local part with common usernames, keeping the domain.
func neighborEmail(value string, count int) []string {
	atIdx := strings.LastIndex(value, "@")
	if atIdx < 0 {
		return nil
	}

	localPart := value[:atIdx]
	domain := value[atIdx:]

	candidates := []string{"admin", "test", "user", "bob", "alice"}

	var results []string
	for _, c := range candidates {
		if c == localPart {
			continue
		}
		results = append(results, c+domain)
		if len(results) >= count {
			return results
		}
	}

	return results
}
