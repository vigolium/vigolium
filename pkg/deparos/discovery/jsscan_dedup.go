package discovery

import (
	"encoding/json"
	"hash/fnv"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// HashExtractedRequest computes FNV-1a 64-bit hash for deduplication.
// Dedup key = URL + Method + normalized Params + normalized Body
func HashExtractedRequest(req *jstangle.ExtractedRequest) string {
	h := fnv.New64a()

	// URL (normalized - lowercase, strip fragment)
	h.Write([]byte(normalizeRequestURL(req.URL)))
	h.Write([]byte{0})

	// Method (uppercase)
	h.Write([]byte(strings.ToUpper(req.Method)))
	h.Write([]byte{0})

	// Normalized params
	h.Write([]byte(normalizeParams(req.Params)))
	h.Write([]byte{0})

	// Normalized body
	h.Write([]byte(normalizeBody(req.Body)))

	return strconv.FormatUint(h.Sum64(), 16)
}

// normalizeRequestURL normalizes URL for consistent hashing.
func normalizeRequestURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	// Handle relative URLs - keep as-is but lowercase
	if !strings.Contains(rawURL, "://") {
		return strings.ToLower(rawURL)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}

	u.Fragment = ""
	return strings.ToLower(u.String())
}

// normalizeParams normalizes query params for deduplication.
// - Parse as key=value&key2=value2
// - Sort by param name
// - Include param names always
// - Skip values containing ${ (template variables)
func normalizeParams(params string) string {
	if params == "" {
		return ""
	}

	values, err := url.ParseQuery(params)
	if err != nil {
		// Fallback: return as-is if unparseable
		return params
	}

	// Collect and sort keys
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build normalized string: sorted_keys + non-template_values
	var parts []string
	for _, k := range keys {
		parts = append(parts, k) // Always include key name
		for _, v := range values[k] {
			if !ContainsTemplateVar(v) {
				parts = append(parts, v) // Include non-template values
			}
		}
	}

	return strings.Join(parts, "|")
}

// normalizeBody normalizes request body for deduplication.
// - Detect format: JSON or form-urlencoded
// - JSON: sort keys recursively, skip template values
// - Form: same as params normalization
func normalizeBody(body string) string {
	if body == "" {
		return ""
	}

	trimmed := strings.TrimSpace(body)

	// Try JSON first
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return normalizeJSONBody(body)
	}

	// Try form-urlencoded
	return normalizeParams(body)
}

// normalizeJSONBody normalizes JSON body by sorting keys and filtering template values.
func normalizeJSONBody(body string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return body // Return as-is if invalid JSON
	}

	normalized := normalizeJSONValue(data)
	result, err := json.Marshal(normalized)
	if err != nil {
		return body
	}
	return string(result)
}

// normalizeJSONValue recursively processes JSON, skipping template values.
func normalizeJSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range val {
			normalized := normalizeJSONValue(v)
			if normalized != nil {
				result[k] = normalized
			}
		}
		return result
	case []interface{}:
		var result []interface{}
		for _, item := range val {
			normalized := normalizeJSONValue(item)
			if normalized != nil {
				result = append(result, normalized)
			}
		}
		return result
	case string:
		if ContainsTemplateVar(val) {
			return nil // Skip template variables
		}
		return val
	default:
		return val
	}
}
