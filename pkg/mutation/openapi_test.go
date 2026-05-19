package mutation

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestBuildSchemaHint_NilSchema(t *testing.T) {
	hint := BuildSchemaHint("user_id", nil)
	if hint.ParamName != "user_id" {
		t.Errorf("ParamName = %q, want 'user_id'", hint.ParamName)
	}
	if hint.Type != "" {
		t.Errorf("Type = %q, want empty", hint.Type)
	}
}

func TestBuildSchemaHint_FullSchema(t *testing.T) {
	min := 0.0
	max := 100.0
	maxLen := uint64(50)
	schema := &openapi3.Schema{
		Type:      &openapi3.Types{"integer"},
		Format:    "int32",
		Min:       &min,
		Max:       &max,
		MinLength: 1,
		MaxLength: &maxLen,
		Pattern:   `^\d+$`,
		Enum:      []any{"1", "2", "3"},
	}

	hint := BuildSchemaHint("count", schema)

	if hint.Type != "integer" {
		t.Errorf("Type = %q, want 'integer'", hint.Type)
	}
	if hint.Format != "int32" {
		t.Errorf("Format = %q, want 'int32'", hint.Format)
	}
	if hint.Minimum == nil || *hint.Minimum != 0 {
		t.Error("Minimum not set correctly")
	}
	if hint.Maximum == nil || *hint.Maximum != 100 {
		t.Error("Maximum not set correctly")
	}
	if hint.MinLength == nil || *hint.MinLength != 1 {
		t.Error("MinLength not set correctly")
	}
	if hint.MaxLength == nil || *hint.MaxLength != 50 {
		t.Error("MaxLength not set correctly")
	}
	if hint.Pattern != `^\d+$` {
		t.Errorf("Pattern = %q, want '^\\d+$'", hint.Pattern)
	}
	if len(hint.Enum) != 3 {
		t.Errorf("Enum len = %d, want 3", len(hint.Enum))
	}
}

func TestBuildSchemaHint_EnumValues(t *testing.T) {
	schema := &openapi3.Schema{
		Type: &openapi3.Types{"string"},
		Enum: []any{"low", "medium", "high"},
	}
	hint := BuildSchemaHint("priority", schema)
	if len(hint.Enum) != 3 {
		t.Fatalf("Enum len = %d, want 3", len(hint.Enum))
	}
	if hint.Enum[0] != "low" || hint.Enum[1] != "medium" || hint.Enum[2] != "high" {
		t.Errorf("Enum = %v, want [low medium high]", hint.Enum)
	}
}

func TestSchemaHintToValueType(t *testing.T) {
	tests := []struct {
		name string
		hint *SchemaHint
		want ValueType
	}{
		{"nil hint", nil, TypeUnknown},
		{"uuid format", &SchemaHint{Format: "uuid"}, TypeUUID},
		{"email format", &SchemaHint{Format: "email"}, TypeEmail},
		{"date-time format", &SchemaHint{Format: "date-time"}, TypeTimestamp},
		{"date format", &SchemaHint{Format: "date"}, TypeDate},
		{"uri format", &SchemaHint{Format: "uri"}, TypeURL},
		{"integer type", &SchemaHint{Type: "integer"}, TypeInteger},
		{"integer type with id name", &SchemaHint{Type: "integer", ParamName: "user_id"}, TypeSequentialID},
		{"number type", &SchemaHint{Type: "number"}, TypeFloat},
		{"boolean type", &SchemaHint{Type: "boolean"}, TypeBoolean},
		{"enum", &SchemaHint{Enum: []string{"a", "b"}}, TypeEnum},
		{"string with email param", &SchemaHint{Type: "string", ParamName: "email"}, TypeEmail},
		{"string with url param", &SchemaHint{Type: "string", ParamName: "callback"}, TypeURL},
		{"string with role param", &SchemaHint{Type: "string", ParamName: "role"}, TypeEnum},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SchemaHintToValueType(tt.hint)
			if got != tt.want {
				t.Errorf("SchemaHintToValueType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValueTypeFromParamName(t *testing.T) {
	tests := []struct {
		name string
		want ValueType
	}{
		{"user_id", TypeSequentialID},
		{"email", TypeEmail},
		{"ip", TypeIPv4},
		{"created_at", TypeDate},
		{"price", TypeFloat},
		{"page", TypeInteger},
		{"url", TypeURL},
		{"role", TypeEnum},
		{"status", TypeEnum},
		{"random", TypeUnknown},
		{"", TypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valueTypeFromParamName(tt.name)
			if got != tt.want {
				t.Errorf("valueTypeFromParamName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
