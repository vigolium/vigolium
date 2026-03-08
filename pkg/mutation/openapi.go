package mutation

import (
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// BuildSchemaHint extracts mutation-relevant hints from an OpenAPI schema and parameter name.
func BuildSchemaHint(paramName string, schema *openapi3.Schema) *SchemaHint {
	if schema == nil {
		return &SchemaHint{ParamName: paramName}
	}

	hint := &SchemaHint{
		ParamName: paramName,
		Format:    schema.Format,
		Pattern:   schema.Pattern,
	}

	// Extract type (openapi3.Types is a slice)
	types := schema.Type.Slice()
	if len(types) > 0 {
		hint.Type = types[0]
	}

	// Extract enum values
	if len(schema.Enum) > 0 {
		for _, e := range schema.Enum {
			if s, ok := e.(string); ok {
				hint.Enum = append(hint.Enum, s)
			}
		}
	}

	// Extract numeric constraints
	if schema.Min != nil {
		min := *schema.Min
		hint.Minimum = &min
	}
	if schema.Max != nil {
		max := *schema.Max
		hint.Maximum = &max
	}

	// Extract string length constraints
	if schema.MinLength != 0 {
		minLen := int(schema.MinLength)
		hint.MinLength = &minLen
	}
	if schema.MaxLength != nil {
		maxLen := int(*schema.MaxLength)
		hint.MaxLength = &maxLen
	}

	return hint
}

// SchemaHintToValueType converts a SchemaHint's format/type to a ValueType.
// This is useful when you have a hint but no observed value.
func SchemaHintToValueType(hint *SchemaHint) ValueType {
	if hint == nil {
		return TypeUnknown
	}

	// Format takes priority
	switch strings.ToLower(hint.Format) {
	case "uuid":
		return TypeUUID
	case "email":
		return TypeEmail
	case "date-time", "datetime":
		return TypeTimestamp
	case "date":
		return TypeDate
	case "uri", "url":
		return TypeURL
	case "ipv4":
		return TypeIPv4
	case "ipv6":
		return TypeIPv6
	case "byte":
		return TypeBase64
	case "password":
		return TypeUnknown
	}

	// Enum
	if len(hint.Enum) > 0 {
		return TypeEnum
	}

	// Type fallback
	switch strings.ToLower(hint.Type) {
	case "integer":
		if isIDParamName(hint.ParamName) {
			return TypeSequentialID
		}
		return TypeInteger
	case "number":
		return TypeFloat
	case "boolean":
		return TypeBoolean
	case "string":
		// Check param name for hints
		return valueTypeFromParamName(hint.ParamName)
	}

	return TypeUnknown
}

// valueTypeFromParamName infers a ValueType from the parameter name alone.
func valueTypeFromParamName(name string) ValueType {
	if name == "" {
		return TypeUnknown
	}
	lower := strings.ToLower(name)

	if isIDParamName(name) {
		return TypeSequentialID
	}

	switch {
	case strings.Contains(lower, "email") || strings.Contains(lower, "mail"):
		return TypeEmail
	case strings.Contains(lower, "token") || strings.Contains(lower, "jwt") || lower == "access_token":
		return TypeJWT
	case lower == "ip" || lower == "ip_address" || lower == "host":
		return TypeIPv4
	case strings.Contains(lower, "date") || strings.HasSuffix(lower, "_at") || strings.HasSuffix(lower, "At"):
		return TypeDate
	case lower == "price" || lower == "amount" || lower == "total" || lower == "rate":
		return TypeFloat
	case lower == "count" || lower == "page" || lower == "limit" || lower == "offset":
		return TypeInteger
	case lower == "url" || lower == "callback" || lower == "redirect" || lower == "redirect_uri":
		return TypeURL
	}

	if isEnumParamName(name) {
		return TypeEnum
	}

	return TypeUnknown
}
