package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttribute_GetMetadata(t *testing.T) {
	attr := StatusCode
	meta, ok := attr.GetMetadata()

	assert.True(t, ok)
	assert.Equal(t, 1, meta.ID)
	assert.Equal(t, "status_code", meta.Name)
	assert.False(t, meta.IsMaskable)
	assert.True(t, meta.IsActive)
}

func TestAttribute_GetMetadata_Invalid(t *testing.T) {
	attr := Attribute(99)
	_, ok := attr.GetMetadata()
	assert.False(t, ok)
}

func TestAttribute_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		attr     Attribute
		expected bool
	}{
		{"StatusCode_active", StatusCode, true},
		{"ContentType_active", ContentType, true},
		{"Invalid", Attribute(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attr.IsActive()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttribute_IsMaskable(t *testing.T) {
	tests := []struct {
		name     string
		attr     Attribute
		expected bool
	}{
		{"StatusCode_non_maskable", StatusCode, false},
		{"ContentType_non_maskable", ContentType, false},
		{"ETagHeader_maskable", ETagHeader, true},
		{"PageTitle_maskable", PageTitle, true},
		{"Invalid", Attribute(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attr.IsMaskable()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttribute_String(t *testing.T) {
	tests := []struct {
		attr     Attribute
		expected string
	}{
		{StatusCode, "status_code"},
		{ContentType, "content_type"},
		{PageTitle, "page_title"},
		{Attribute(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.attr.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAllActiveAttributes(t *testing.T) {
	attrs := AllActiveAttributes()

	assert.NotEmpty(t, attrs)
	assert.Len(t, attrs, 32, "should have 32 active attributes")

	// All returned attributes should be active
	for _, attr := range attrs {
		assert.True(t, attr.IsActive(), "attribute %s should be active", attr.String())
	}
}

func TestGetAttributesByCategory(t *testing.T) {
	tests := []struct {
		name          string
		category      Category
		expectNonZero bool
	}{
		{"status", CategoryStatus, true},
		{"headers", CategoryHeaders, true},
		{"html", CategoryHTML, true},
		{"content", CategoryContent, true},
		{"forms", CategoryForms, true},
		{"navigation", CategoryNavigation, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := GetAttributesByCategory(tt.category)

			if tt.expectNonZero {
				assert.NotEmpty(t, attrs, "category %s should have attributes", tt.category)
			}

			// All returned attributes should belong to the category
			for _, attr := range attrs {
				meta, ok := attr.GetMetadata()
				assert.True(t, ok)
				assert.Equal(t, tt.category, meta.Category)
				assert.True(t, meta.IsActive, "should only return active attributes")
			}
		})
	}
}

func TestAttributeRegistry_Complete(t *testing.T) {
	// Verify all 32 attributes are in registry
	for i := Attribute(1); i <= 32; i++ {
		meta, ok := AttributeRegistry[i]
		assert.True(t, ok, "attribute %d should be in registry", i)
		assert.Equal(t, int(i), meta.ID, "attribute ID should match")
		assert.NotEmpty(t, meta.Name, "attribute should have a name")
	}
}

func TestAttributeMetadata_Categories(t *testing.T) {
	categories := map[Category]bool{
		CategoryStatus:     false,
		CategoryHeaders:    false,
		CategoryHTML:       false,
		CategoryContent:    false,
		CategoryForms:      false,
		CategoryNavigation: false,
	}

	// Check each category has at least one attribute
	for _, meta := range AttributeRegistry {
		if meta.IsActive {
			categories[meta.Category] = true
		}
	}

	for cat, found := range categories {
		assert.True(t, found, "category %s should have at least one active attribute", cat)
	}
}

func TestAttributeMetadata_CriticalAttributes(t *testing.T) {
	// Critical attributes should not be maskable
	criticalAttrs := []Attribute{StatusCode, ContentType}

	for _, attr := range criticalAttrs {
		meta, ok := AttributeRegistry[attr]
		assert.True(t, ok)
		assert.False(t, meta.IsMaskable, "critical attribute %s should not be maskable", meta.Name)
		assert.True(t, meta.IsActive, "critical attribute %s should be active", meta.Name)
	}
}
