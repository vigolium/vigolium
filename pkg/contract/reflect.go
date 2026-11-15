package contract

import (
	"encoding/json"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// Schema is a JSON Schema node (draft 2020-12).
type Schema = jsonschema.Schema

// builder reflects Go types into one schema document, collecting every named
// type under a shared $defs.
type builder struct {
	defs jsonschema.Definitions
	r    *jsonschema.Reflector
}

var (
	errorCodeType  = reflect.TypeOf(apicontract.ErrorCode(""))
	timeType       = reflect.TypeOf(time.Time{})
	rawMessageType = reflect.TypeOf(json.RawMessage{})
)

func newBuilder() *builder {
	b := &builder{defs: jsonschema.Definitions{}}
	b.r = &jsonschema.Reflector{
		Anonymous: true,
		// A definition per named type, keyed package.Type so two packages'
		// Budgets cannot collide.
		Namer: func(t reflect.Type) string {
			if t.Name() == "" || t.PkgPath() == "" {
				return ""
			}
			return path.Base(t.PkgPath()) + "." + t.Name()
		},
		// The error-code vocabulary is a closed set: enumerate it wherever an
		// ErrorCode field appears.
		Mapper: func(t reflect.Type) *Schema {
			if t == errorCodeType {
				return errorCodeSchema()
			}
			return nil
		},
	}
	return b
}

// errorCodeSchema is the closed ErrorCode vocabulary as a string enum.
func errorCodeSchema() *Schema {
	codes := apicontract.ErrorCodes()
	enum := make([]any, len(codes))
	for i, c := range codes {
		enum[i] = string(c)
	}
	return &Schema{Type: "string", Enum: enum}
}

// schemaFor reflects v and returns the schema for its type: a $ref for a named
// struct, an inline schema otherwise. Definitions land in b.defs.
func (b *builder) schemaFor(v any) *Schema {
	t := reflect.TypeOf(v)
	s := b.r.ReflectFromType(t)
	for name, def := range s.Definitions {
		b.defs[name] = def
	}
	s.Definitions = nil
	s.Version = ""
	b.markNullable(s, t, map[string]bool{})
	return s
}

// objectFor reflects a struct value and returns its own object schema (not a
// $ref), for a type whose properties are merged into another object. Its
// definition is dropped from $defs: nothing else refers to it.
func (b *builder) objectFor(v any) *Schema {
	s := b.schemaFor(v)
	if name := strings.TrimPrefix(s.Ref, "#/$defs/"); s.Ref != "" {
		obj := b.defs[name]
		delete(b.defs, name)
		return obj
	}
	return s
}

// resolve follows a local $ref.
func (b *builder) resolve(s *Schema) *Schema {
	for s != nil && s.Ref != "" {
		s = b.defs[strings.TrimPrefix(s.Ref, "#/$defs/")]
	}
	return s
}

// markNullable fixes what the reflector cannot see: a pointer, slice or map
// field WITHOUT omitempty marshals a nil value as JSON null. The reflector
// types it as the element alone, so a document carrying the null would fail
// its own schema. Such properties become anyOf [schema, null].
func (b *builder) markNullable(s *Schema, t reflect.Type, seen map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if s == nil {
		return
	}
	if s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, "#/$defs/")
		if seen[name] {
			return
		}
		seen[name] = true
		s = b.defs[name]
		if s == nil {
			return
		}
	}
	switch t.Kind() {
	case reflect.Struct:
		if t == timeType || s.Properties == nil {
			return
		}
		forEachJSONField(t, func(f reflect.StructField, name string, omitempty bool) {
			prop, ok := s.Properties.Get(name)
			if !ok || prop == nil {
				return
			}
			b.markNullable(prop, f.Type, seen)
			if !omitempty && nilable(f.Type) {
				s.Properties.Set(name, &Schema{AnyOf: []*Schema{prop, {Type: "null"}}})
			}
		})
	case reflect.Slice, reflect.Array:
		if t == rawMessageType || s.Items == nil {
			return
		}
		b.markNullable(s.Items, t.Elem(), seen)
	case reflect.Map:
		if s.AdditionalProperties != nil {
			b.markNullable(s.AdditionalProperties, t.Elem(), seen)
		}
	}
}

// nilable reports whether a value of t can marshal as null.
func nilable(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		return t != rawMessageType
	}
	return false
}

// forEachJSONField visits t's fields the way encoding/json names them:
// exported, not "-", embedded untagged structs flattened.
func forEachJSONField(t reflect.Type, fn func(f reflect.StructField, name string, omitempty bool)) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				forEachJSONField(ft, fn)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fn(f, name, strings.Contains(","+opts+",", ",omitempty,"))
	}
}

// JSONFieldNames returns the JSON keys a value of v's struct type can carry,
// in field order. For drift tests that compare a mirror with the real type.
func JSONFieldNames(v any) []string {
	var out []string
	forEachJSONField(reflect.TypeOf(v), func(_ reflect.StructField, name string, _ bool) {
		out = append(out, name)
	})
	return out
}

// RequiredNullableJSONFields returns the keys of v's struct type that are
// required (no omitempty) and may be null (a pointer, slice or map): the keys a
// shaped document can empty by setting them to null without failing its
// schema.
func RequiredNullableJSONFields(v any) []string {
	var out []string
	forEachJSONField(reflect.TypeOf(v), func(f reflect.StructField, name string, omitempty bool) {
		if !omitempty && nilable(f.Type) {
			out = append(out, name)
		}
	})
	return out
}

// root wraps a top-level object schema with the dialect and the collected
// definitions.
func (b *builder) root(s *Schema, title, description string) *Schema {
	s.Version = jsonschema.Version
	s.Title = title
	if description != "" {
		s.Description = description
	}
	if defs := b.reachableDefs(s); len(defs) > 0 {
		s.Definitions = defs
	}
	return s
}

var refPattern = regexp.MustCompile(`"\$ref":"#/\$defs/([^"]+)"`)

// reachableDefs returns the definitions s refers to, directly or through
// another definition. Reflection collects every type it walked; a document
// that never references one should not ship it.
func (b *builder) reachableDefs(s *Schema) jsonschema.Definitions {
	out := jsonschema.Definitions{}
	queue := []*Schema{s}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		raw, err := json.Marshal(cur)
		if err != nil {
			continue
		}
		for _, m := range refPattern.FindAllSubmatch(raw, -1) {
			name := string(m[1])
			if _, done := out[name]; done {
				continue
			}
			if def, ok := b.defs[name]; ok {
				out[name] = def
				queue = append(queue, def)
			}
		}
	}
	return out
}

// constSchema is a schema pinning one value.
func constSchema(typ string, v any) *Schema {
	return &Schema{Type: typ, Const: v}
}

// propertyNames lists s's properties in order.
func propertyNames(s *Schema) []string {
	if s == nil || s.Properties == nil {
		return nil
	}
	var out []string
	for p := s.Properties.Oldest(); p != nil; p = p.Next() {
		out = append(out, p.Key)
	}
	return out
}

// mergeProperties copies src's properties (and required list) onto dst,
// replacing any of the same name.
func mergeProperties(dst, src *Schema) {
	if src == nil || src.Properties == nil {
		return
	}
	if dst.Properties == nil {
		dst.Properties = jsonschema.NewProperties()
	}
	for p := src.Properties.Oldest(); p != nil; p = p.Next() {
		dst.Properties.Set(p.Key, p.Value)
		dst.Required = removeString(dst.Required, p.Key)
	}
	for _, r := range src.Required {
		dst.Required = appendUnique(dst.Required, r)
	}
}

func removeString(list []string, s string) []string {
	out := list[:0:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
