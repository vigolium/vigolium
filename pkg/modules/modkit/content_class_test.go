package modkit

import "testing"

func TestClassifyContentType(t *testing.T) {
	cases := map[string]ContentClass{
		"":                              ContentClassUnknown,
		"text/html":                     ContentClassHTML,
		"text/html; charset=utf-8":      ContentClassHTML,
		"application/xhtml+xml":         ContentClassHTML, // html wins over xml
		"application/json":              ContentClassJSON,
		"application/vnd.api+json":      ContentClassJSON,
		"application/xml":               ContentClassXML,
		"text/xml":                      ContentClassXML,
		"image/svg+xml":                 ContentClassXML,
		"text/plain":                    ContentClassText,
		"text/csv":                      ContentClassText,
		"image/png":                     ContentClassBinary,
		"application/octet-stream":      ContentClassBinary,
		"application/pdf":               ContentClassBinary,
		"application/grpc":              ContentClassUnknown,
		"font/woff2":                    ContentClassBinary,
		"video/mp4":                     ContentClassBinary,
		"APPLICATION/JSON; CHARSET=foo": ContentClassJSON,
	}
	for in, want := range cases {
		if got := ClassifyContentType(in); got != want {
			t.Errorf("ClassifyContentType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContentClassAllows(t *testing.T) {
	html := []string{"html"}
	cases := []struct {
		name     string
		required []string
		class    ContentClass
		want     bool
	}{
		{"no requirement runs everywhere", nil, ContentClassJSON, true},
		{"html module on html runs", html, ContentClassHTML, true},
		{"html module on json skips", html, ContentClassJSON, false},
		{"html module on xml skips", html, ContentClassXML, false},
		{"html module on binary skips", html, ContentClassBinary, false},
		{"html module on text fails open", html, ContentClassText, true},
		{"html module on unknown fails open", html, ContentClassUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContentClassAllows(tc.required, tc.class); got != tc.want {
				t.Fatalf("ContentClassAllows(%v, %q) = %v, want %v", tc.required, tc.class, got, tc.want)
			}
		})
	}
}

func TestContentClassRegistry(t *testing.T) {
	r := NewContentClassRegistry()
	r.Set("Example.com", ContentClassJSON)
	r.Set("", ContentClassHTML)                // no-op
	r.Set("other.com", ContentClassUnknown)    // no-op (unknown)
	if got := r.Get("example.com"); got != ContentClassJSON {
		t.Errorf("Get(example.com) = %q, want json (case-insensitive)", got)
	}
	if got := r.Get("missing.com"); got != ContentClassUnknown {
		t.Errorf("Get(missing.com) = %q, want unknown", got)
	}
	if got := r.Get("other.com"); got != ContentClassUnknown {
		t.Errorf("Get(other.com) = %q, want unknown (unknown not stored)", got)
	}
	// nil registry is safe
	var nilReg *ContentClassRegistry
	nilReg.Set("x.com", ContentClassHTML)
	if got := nilReg.Get("x.com"); got != ContentClassUnknown {
		t.Errorf("nil registry Get = %q, want unknown", got)
	}
}
