package input_behavior_probe

import "testing"

func TestExtractTags(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
		{
			name:     "no tags",
			body:     "Hello World",
			expected: "",
		},
		{
			name:     "single div",
			body:     "<div>content</div>",
			expected: "<div",
		},
		{
			name:     "multiple tags",
			body:     "<html><head><title>Test</title></head><body><div>content</div></body></html>",
			expected: "<html<head<title<body<div",
		},
		{
			name:     "case insensitive",
			body:     "<DIV><SCRIPT></SCRIPT></DIV>",
			expected: "<div<script",
		},
		{
			name:     "with script injection",
			body:     "<html><body><script>alert(1)</script></body></html>",
			expected: "<html<body<script",
		},
		{
			name:     "self closing tags",
			body:     "<img src='x'><br><input type='text'>",
			expected: "<img<br<input",
		},
		{
			name:     "nested structure",
			body:     "<div><span><a href='#'>link</a></span></div>",
			expected: "<div<span<a",
		},
		{
			name:     "with fuzz payload creating extra tag",
			body:     "<html><body>value<script>injected</script></body></html>",
			expected: "<html<body<script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractTags(tt.body)
			if result != tt.expected {
				t.Errorf("ExtractTags() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractTags_StructureChange(t *testing.T) {
	// Simulate baseline vs fuzzed response comparison
	baseline := "<html><body><div>search: test</div></body></html>"
	fuzzed := "<html><body><div>search: a'a\\'b\"c>?>%}}%%>c<script>injected</script>[[?${{%}}cake\\</div></body></html>"

	baseTags := ExtractTags(baseline)
	fuzzTags := ExtractTags(fuzzed)

	// Baseline should have: html, body, div
	expectedBase := "<html<body<div"
	if baseTags != expectedBase {
		t.Errorf("baseline tags = %q, want %q", baseTags, expectedBase)
	}

	// Fuzzed should have extra script tag
	expectedFuzz := "<html<body<div<script"
	if fuzzTags != expectedFuzz {
		t.Errorf("fuzzed tags = %q, want %q", fuzzTags, expectedFuzz)
	}

	// Tags should be different (indicates potential XSS)
	if baseTags == fuzzTags {
		t.Error("expected tags to be different after injection")
	}
}
