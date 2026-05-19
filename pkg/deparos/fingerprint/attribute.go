package fingerprint

// Attribute represents a fingerprint attribute type
// 32 total attributes for response fingerprinting
type Attribute uint8

// Attribute constants (1-32)
const (
	StatusCode              Attribute = 1  // HTTP status code
	ETagHeader              Attribute = 2  // ETag header value (hashed)
	LastModifiedHeader      Attribute = 3  // Last-Modified header (hashed)
	ContentType             Attribute = 4  // Content-Type without charset
	ContentLength           Attribute = 5  // Content-Length value
	CookieNames             Attribute = 6  // Set-Cookie header names (CRC32)
	TagNames                Attribute = 7  // All HTML tag names (CRC32)
	TagIDs                  Attribute = 8  // All id attributes (CRC32)
	DivIDs                  Attribute = 9  // Div id attributes (CRC32)
	BodyContent             Attribute = 10 // Full body hash
	VisibleText             Attribute = 11 // Rendered text only
	WordCount               Attribute = 12 // Total words
	VisibleWordCount        Attribute = 13 // Visible words
	Comments                Attribute = 14 // HTML comments (CRC32)
	InitialContent          Attribute = 15 // First N bytes
	LastContent             Attribute = 16 // Last N bytes
	CanonicalLink           Attribute = 17 // Canonical Link header
	PageTitle               Attribute = 18 // <title> tag content
	FirstHeaderTag          Attribute = 19 // First h1-h6 only
	HeaderTags              Attribute = 20 // All h1-h6 content (CRC32)
	AnchorLabels            Attribute = 21 // Link text (CRC32)
	InputSubmitLabels       Attribute = 22 // Submit button text (CRC32)
	ButtonSubmitLabels      Attribute = 23 // Button text (CRC32)
	CSSClasses              Attribute = 24 // Class names (CRC32)
	LineCount               Attribute = 25 // Line count
	LimitedBodyContent      Attribute = 26 // Partial body hash
	OutboundEdgeCount       Attribute = 27 // Link count
	OutboundEdgeTagNames    Attribute = 28 // Link tag types (CRC32)
	InputImageLabels        Attribute = 29 // Image input alt text (CRC32)
	ContentLocation         Attribute = 30 // Content-Location header
	Location                Attribute = 31 // Location header (hashed)
	NonHiddenFormInputTypes Attribute = 32 // Input types (CRC32)
)

// MaxAttributeID is the highest attribute ID
const MaxAttributeID Attribute = 32

// Category represents attribute grouping
type Category string

const (
	CategoryStatus     Category = "status"
	CategoryHeaders    Category = "headers"
	CategoryHTML       Category = "html"
	CategoryContent    Category = "content"
	CategoryForms      Category = "forms"
	CategoryNavigation Category = "navigation"
)

// AttributeMetadata contains metadata for each attribute
type AttributeMetadata struct {
	ID          int      // Attribute ID (1-32)
	Name        string   // Attribute name
	IsRequest   bool     // Request vs Response attribute
	IsMaskable  bool     // Can be masked in comparison
	IsActive    bool     // Included in comparison
	Category    Category // Attribute category
	Description string   // Human-readable description
}

// AttributeRegistry maps attributes to their metadata
var AttributeRegistry = map[Attribute]AttributeMetadata{
	StatusCode: {
		ID:          1,
		Name:        "status_code",
		IsRequest:   false,
		IsMaskable:  false, // Critical - always compared
		IsActive:    true,
		Category:    CategoryStatus,
		Description: "HTTP status code",
	},
	ETagHeader: {
		ID:          2,
		Name:        "etag_header",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "ETag header value (CRC32 hash)",
	},
	LastModifiedHeader: {
		ID:          3,
		Name:        "last_modified_header",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Last-Modified header (CRC32 hash)",
	},
	ContentType: {
		ID:          4,
		Name:        "content_type",
		IsRequest:   false,
		IsMaskable:  false, // Critical - always compared
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Content-Type header without charset",
	},
	ContentLength: {
		ID:          5,
		Name:        "content_length",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Content-Length value",
	},
	CookieNames: {
		ID:          6,
		Name:        "cookie_names",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Set-Cookie header names (CRC32 accumulated)",
	},
	TagNames: {
		ID:          7,
		Name:        "tag_names",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "All HTML tag names (CRC32 accumulated)",
	},
	TagIDs: {
		ID:          8,
		Name:        "tag_ids",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "All id attributes (CRC32 accumulated)",
	},
	DivIDs: {
		ID:          9,
		Name:        "div_ids",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "Div id attributes only (CRC32 accumulated)",
	},
	BodyContent: {
		ID:          10,
		Name:        "body_content",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Full body content (CRC32 hash)",
	},
	VisibleText: {
		ID:          11,
		Name:        "visible_text",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Visible text only (CRC32 hash)",
	},
	WordCount: {
		ID:          12,
		Name:        "word_count",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Total word count",
	},
	VisibleWordCount: {
		ID:          13,
		Name:        "visible_word_count",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Visible word count",
	},
	Comments: {
		ID:          14,
		Name:        "comments",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "HTML comment content (CRC32 accumulated)",
	},
	InitialContent: {
		ID:          15,
		Name:        "initial_content",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "First N bytes of content (CRC32 hash)",
	},
	LastContent: {
		ID:          16,
		Name:        "last_content",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Last N bytes of content (CRC32 hash)",
	},
	CanonicalLink: {
		ID:          17,
		Name:        "canonical_link",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Canonical Link header",
	},
	PageTitle: {
		ID:          18,
		Name:        "page_title",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "<title> tag content (CRC32 hash)",
	},
	FirstHeaderTag: {
		ID:          19,
		Name:        "first_header_tag",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "First h1-h6 tag only (CRC32 hash)",
	},
	HeaderTags: {
		ID:          20,
		Name:        "header_tags",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "All h1-h6 content (CRC32 accumulated)",
	},
	AnchorLabels: {
		ID:          21,
		Name:        "anchor_labels",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryNavigation,
		Description: "Link text content (CRC32 accumulated)",
	},
	InputSubmitLabels: {
		ID:          22,
		Name:        "input_submit_labels",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryForms,
		Description: "Submit input values (CRC32 accumulated)",
	},
	ButtonSubmitLabels: {
		ID:          23,
		Name:        "button_submit_labels",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryForms,
		Description: "Button text content (CRC32 accumulated)",
	},
	CSSClasses: {
		ID:          24,
		Name:        "css_classes",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHTML,
		Description: "CSS class names (CRC32 accumulated)",
	},
	LineCount: {
		ID:          25,
		Name:        "line_count",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Total line count",
	},
	LimitedBodyContent: {
		ID:          26,
		Name:        "limited_body_content",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryContent,
		Description: "Partial body content (CRC32 hash)",
	},
	OutboundEdgeCount: {
		ID:          27,
		Name:        "outbound_edge_count",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryNavigation,
		Description: "Total link count",
	},
	OutboundEdgeTagNames: {
		ID:          28,
		Name:        "outbound_edge_tag_names",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryNavigation,
		Description: "Link tag types (CRC32 accumulated)",
	},
	InputImageLabels: {
		ID:          29,
		Name:        "input_image_labels",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryForms,
		Description: "Image input alt text (CRC32 accumulated)",
	},
	ContentLocation: {
		ID:          30,
		Name:        "content_location",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Content-Location header",
	},
	Location: {
		ID:          31,
		Name:        "location",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryHeaders,
		Description: "Location header (CRC32 hash)",
	},
	NonHiddenFormInputTypes: {
		ID:          32,
		Name:        "non_hidden_form_input_types",
		IsRequest:   false,
		IsMaskable:  true,
		IsActive:    true,
		Category:    CategoryForms,
		Description: "Non-hidden input types (CRC32 accumulated)",
	},
}

// GetMetadata returns metadata for an attribute
func (a Attribute) GetMetadata() (AttributeMetadata, bool) {
	meta, ok := AttributeRegistry[a]
	return meta, ok
}

// IsActive returns true if the attribute is active (not deprecated)
func (a Attribute) IsActive() bool {
	meta, ok := AttributeRegistry[a]
	return ok && meta.IsActive
}

// IsMaskable returns true if the attribute can be masked
func (a Attribute) IsMaskable() bool {
	meta, ok := AttributeRegistry[a]
	return ok && meta.IsMaskable
}

// String returns the attribute name
func (a Attribute) String() string {
	meta, ok := AttributeRegistry[a]
	if !ok {
		return "unknown"
	}
	return meta.Name
}

// AllActiveAttributes returns all active (non-deprecated) attributes
func AllActiveAttributes() []Attribute {
	var active []Attribute
	for attr := Attribute(1); attr <= MaxAttributeID; attr++ {
		if attr.IsActive() {
			active = append(active, attr)
		}
	}
	return active
}

// GetAttributesByCategory returns all active attributes in a category
func GetAttributesByCategory(category Category) []Attribute {
	var attrs []Attribute
	for attr := Attribute(1); attr <= MaxAttributeID; attr++ {
		meta, ok := AttributeRegistry[attr]
		if ok && meta.IsActive && meta.Category == category {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}
