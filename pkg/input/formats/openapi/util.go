package openapi

import (
	"encoding/json"
	"fmt"
	"strings"
)

// toString converts any value to string.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		if val == float64(int(val)) {
			return fmt.Sprintf("%d", int(val))
		}
		return fmt.Sprintf("%f", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// marshalJSON marshals a value to JSON.
func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// marshalXML marshals a map to simple XML.
func marshalXML(v interface{}) ([]byte, error) {
	values, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cannot marshal non-map to XML")
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString("\n<root>\n")

	if err := marshalXMLMap(&sb, values, 1); err != nil {
		return nil, err
	}

	sb.WriteString("</root>")
	return []byte(sb.String()), nil
}

func marshalXMLMap(sb *strings.Builder, values map[string]interface{}, indent int) error {
	indentStr := strings.Repeat("  ", indent)

	for k, v := range values {
		switch val := v.(type) {
		case map[string]interface{}:
			sb.WriteString(indentStr)
			sb.WriteString("<")
			sb.WriteString(k)
			sb.WriteString(">\n")
			if err := marshalXMLMap(sb, val, indent+1); err != nil {
				return err
			}
			sb.WriteString(indentStr)
			sb.WriteString("</")
			sb.WriteString(k)
			sb.WriteString(">\n")
		case []interface{}:
			for _, item := range val {
				sb.WriteString(indentStr)
				sb.WriteString("<")
				sb.WriteString(k)
				sb.WriteString(">")
				if nested, ok := item.(map[string]interface{}); ok {
					sb.WriteString("\n")
					if err := marshalXMLMap(sb, nested, indent+1); err != nil {
						return err
					}
					sb.WriteString(indentStr)
				} else {
					writeXMLValue(sb, item)
				}
				sb.WriteString("</")
				sb.WriteString(k)
				sb.WriteString(">\n")
			}
		default:
			sb.WriteString(indentStr)
			sb.WriteString("<")
			sb.WriteString(k)
			sb.WriteString(">")
			writeXMLValue(sb, val)
			sb.WriteString("</")
			sb.WriteString(k)
			sb.WriteString(">\n")
		}
	}
	return nil
}

func writeXMLValue(sb *strings.Builder, v interface{}) {
	str := toString(v)
	// Escape XML special characters
	escaped := strings.ReplaceAll(str, "&", "&amp;")
	escaped = strings.ReplaceAll(escaped, "<", "&lt;")
	escaped = strings.ReplaceAll(escaped, ">", "&gt;")
	escaped = strings.ReplaceAll(escaped, "'", "&apos;")
	escaped = strings.ReplaceAll(escaped, "\"", "&quot;")
	sb.WriteString(escaped)
}

// stringFormatExample returns an example string based on the format.
// If fieldTypeDefaults is provided, it checks config values first (returns the first entry),
// then falls back to hardcoded values.
func stringFormatExample(format string, fieldTypeDefaults map[string][]string) string {
	// Check config defaults first
	if len(fieldTypeDefaults) > 0 {
		if vals, ok := fieldTypeDefaults[format]; ok && len(vals) > 0 {
			return vals[0]
		}
	}

	// Hardcoded fallbacks
	switch format {
	case "date":
		return "2024-01-15"
	case "date-time":
		return "2024-01-15T10:30:00Z"
	case "time":
		return "10:30:00Z"
	case "email":
		return "user@example.com"
	case "hostname":
		return "example.com"
	case "ipv4":
		return "192.0.2.1"
	case "ipv6":
		return "2001:db8::1"
	case "uri", "url":
		return "https://example.com/path"
	case "uri-template":
		return "https://example.com/{id}"
	case "uuid":
		return "550e8400-e29b-41d4-a716-446655440000"
	case "password":
		return "********"
	case "binary":
		return "binary-data"
	case "byte":
		return "dGVzdA==" // base64 encoded "test"
	}
	return ""
}
