package agenttypes

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// flexInt coerces a JSON value (float64, string, json.Number) to int.
// Returns 0 if the value cannot be converted.
func flexInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return int(i)
		}
	case string:
		val = strings.TrimSpace(val)
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
		// Try parsing as float then truncate (e.g. "200.0")
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return int(f)
		}
	}
	return 0
}

// flexIntSlice coerces a JSON value to []int. Accepts:
//   - []interface{} with int/float/string elements
//   - a single int/float/string (wraps in slice)
func flexIntSlice(v interface{}) []int {
	switch val := v.(type) {
	case []interface{}:
		out := make([]int, 0, len(val))
		for _, elem := range val {
			if n := flexInt(elem); n != 0 {
				out = append(out, n)
			}
		}
		return out
	default:
		// Single value
		if n := flexInt(v); n != 0 {
			return []int{n}
		}
	}
	return nil
}

// flexStringSlice coerces a JSON value to []string. Accepts:
//   - []interface{} with string elements
//   - a single string (wraps in slice)
func flexStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, elem := range val {
			out = append(out, fmt.Sprint(elem))
		}
		return out
	case string:
		if val != "" {
			return []string{val}
		}
	}
	return nil
}
