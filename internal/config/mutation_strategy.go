package config

// MutationStrategyConfig holds mutation strategy configuration
type MutationStrategyConfig struct {
	DefaultModes      []string                 `yaml:"default_modes"`
	FieldTypeDefaults FieldTypeDefaults        `yaml:"field_type_defaults"`
	ValueAware        ValueAwareMutationConfig `yaml:"value_aware"`
}

// ValueAwareMutationConfig controls value-aware mutation generation.
type ValueAwareMutationConfig struct {
	Enabled        bool                `yaml:"enabled"`          // Default: true
	MaxPerIntent   int                 `yaml:"max_per_intent"`   // Default: 5
	DefaultIntents []string            `yaml:"default_intents"`  // Default: ["neighbor", "boundary", "escalation"]
	EnumMappings   map[string][]string `yaml:"enum_mappings"`    // Custom enum escalation pairs
	ParamSynonyms  map[string][]string `yaml:"param_synonyms"`   // Custom param name synonyms
}

// FieldTypeDefaults holds default example values per field type.
// Used by OpenAPI parser when specs lack examples.
type FieldTypeDefaults struct {
	String      []string `yaml:"string"`
	Slug        []string `yaml:"slug"`
	JSON        []string `yaml:"json"`
	Null        []string `yaml:"null"`
	Date        []string `yaml:"date"`
	DateTime    []string `yaml:"datetime"`
	Number      []string `yaml:"number"`
	Float       []string `yaml:"float"`
	Integer     []string `yaml:"integer"`
	Long        []string `yaml:"long"`
	Boolean     []string `yaml:"boolean"`
	UUID        []string `yaml:"uuid"`
	Path        []string `yaml:"path"`
	CreditCard  []string `yaml:"credit_card"`
	Email       []string `yaml:"email"`
	Username    []string `yaml:"username"`
	Password    []string `yaml:"password"`
	PhoneNumber []string `yaml:"phone_number"`
	Country     []string `yaml:"country"`
	URI         []string `yaml:"uri"`
	FileUpload  []string `yaml:"file_upload"`
}

// ToMap converts FieldTypeDefaults to a flat map keyed by field type name.
// This allows pkg/ code to consume defaults without importing internal/config.
func (f *FieldTypeDefaults) ToMap() map[string][]string {
	return map[string][]string{
		"string":       f.String,
		"slug":         f.Slug,
		"json":         f.JSON,
		"null":         f.Null,
		"date":         f.Date,
		"datetime":     f.DateTime,
		"number":       f.Number,
		"float":        f.Float,
		"integer":      f.Integer,
		"long":         f.Long,
		"boolean":      f.Boolean,
		"uuid":         f.UUID,
		"path":         f.Path,
		"credit_card":  f.CreditCard,
		"email":        f.Email,
		"username":     f.Username,
		"password":     f.Password,
		"phone_number": f.PhoneNumber,
		"country":      f.Country,
		"uri":          f.URI,
		"file_upload":  f.FileUpload,
	}
}

// DefaultMutationStrategyConfig returns default mutation strategy configuration
func DefaultMutationStrategyConfig() *MutationStrategyConfig {
	return &MutationStrategyConfig{
		DefaultModes: []string{"append"},
		ValueAware: ValueAwareMutationConfig{
			Enabled:        true,
			MaxPerIntent:   5,
			DefaultIntents: []string{"neighbor", "boundary", "escalation"},
		},
		FieldTypeDefaults: FieldTypeDefaults{
			String:      []string{"test", "example", "sample"},
			Slug:        []string{"test-slug", "example-item", "sample-post"},
			JSON:        []string{`{"key":"value"}`, `{"test":true}`, `{"id":123}`},
			Null:        []string{"null", "", "nil"},
			Date:        []string{"2026-02-16", "2026-01-01", "2025-12-31"},
			DateTime:    []string{"2026-02-16T03:00:00Z", "2026-01-01T00:00:00Z", "2025-12-31T23:59:59Z"},
			Number:      []string{"123", "456.789", "0"},
			Float:       []string{"123.45", "0.001", "999.99"},
			Integer:     []string{"1", "100", "999"},
			Long:        []string{"9223372036854775807", "1000000", "42"},
			Boolean:     []string{"true", "false", "1"},
			UUID:        []string{"550e8400-e29b-41d4-a716-446655440000", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
			Path:        []string{"/api/v1/resource", "/test/path", "/example"},
			CreditCard:  []string{"4532015112830366", "5425233430109903", "374245455400126"},
			Email:       []string{"test@example.com", "user@test.org", "admin@localhost"},
			Username:    []string{"testuser", "admin", "user123"},
			Password:    []string{"P@ssw0rd123!", "Test1234!", "S3cur3P@ss!"},
			PhoneNumber: []string{"+1-555-123-4567", "+44-20-7946-0958", "+81-3-1234-5678"},
			Country:     []string{"US", "GB", "JP"},
			URI:         []string{"https://example.com/path", "http://test.local/api", "https://api.example.org/v1"},
			FileUpload:  []string{"test.pdf", "image.jpg", "document.docx"},
		},
	}
}
