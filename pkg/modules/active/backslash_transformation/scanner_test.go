package backslash_transformation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, "backslash-transformation", m.ID())
	assert.Equal(t, "Backslash Transformation Detection", m.Name())
}

func TestExtractBetweenAnchors(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		leftAnchor  string
		rightAnchor string
		want        []string
	}{
		{
			name:        "simple reflection",
			body:        "Hello abc\\z1testzxyz World",
			leftAnchor:  "abc\\z1",
			rightAnchor: "zxyz",
			want:        []string{"test"},
		},
		{
			name:        "no reflection",
			body:        "Hello World",
			leftAnchor:  "abc\\z1",
			rightAnchor: "zxyz",
			want:        []string{"Reflection disappeared"},
		},
		{
			name:        "truncated reflection",
			body:        "Hello abc\\z1test",
			leftAnchor:  "abc\\z1",
			rightAnchor: "zxyz",
			want:        []string{"Truncated"},
		},
		{
			name:        "html entity unescaping",
			body:        "Hello abc\\z1&lt;script&gt;zxyz World",
			leftAnchor:  "abc\\z1",
			rightAnchor: "zxyz",
			want:        []string{"<script>"},
		},
		{
			name:        "multiple reflections same content",
			body:        "abc\\z1testzxyz and abc\\z1testzxyz again",
			leftAnchor:  "abc\\z1",
			rightAnchor: "zxyz",
			want:        []string{"test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractBetweenAnchors([]byte(tt.body), tt.leftAnchor, tt.rightAnchor)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestClassifyTransformation(t *testing.T) {
	tests := []struct {
		name                       string
		probe                      string
		received                   string
		expectBackslashConsumption bool
		wantClassification         Classification
	}{
		{
			name:                       "boring - unchanged",
			probe:                      "\\x41",
			received:                   "\\x41",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationBoring,
		},
		{
			name:                       "boring - URL encoded",
			probe:                      "\\x41",
			received:                   "%5Cx41",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationBoring,
		},
		{
			name:                       "backslash consumed",
			probe:                      "\\x41",
			received:                   "x41",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationBackslashConsumed,
		},
		{
			name:                       "backslash consumed expected - boring",
			probe:                      "\\x41",
			received:                   "x41",
			expectBackslashConsumption: true,
			wantClassification:         ClassificationBoring,
		},
		{
			name:                       "interesting - hex decoded",
			probe:                      "\\x41",
			received:                   "A",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationInteresting,
		},
		{
			name:                       "interesting - octal decoded",
			probe:                      "\\101",
			received:                   "A",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationInteresting,
		},
		{
			name:                       "interesting - unicode decoded",
			probe:                      "\\u0041",
			received:                   "A",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationInteresting,
		},
		{
			name:                       "character probe - unchanged boring",
			probe:                      "'",
			received:                   "'",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationBoring,
		},
		{
			name:                       "character probe - transformed interesting",
			probe:                      "'",
			received:                   "\\'",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationInteresting,
		},
		{
			name:                       "truncated",
			probe:                      "\\x41",
			received:                   "Truncated",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationTruncated,
		},
		{
			name:                       "reflection disappeared",
			probe:                      "\\x41",
			received:                   "Reflection disappeared",
			expectBackslashConsumption: false,
			wantClassification:         ClassificationDisappeared,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyTransformation(tt.probe, tt.received, tt.expectBackslashConsumption)
			assert.Equal(t, tt.wantClassification, result.Classification)
			assert.Equal(t, tt.probe, result.Probe)
			assert.Equal(t, tt.received, result.Received)
		})
	}
}

func TestIsBackslashConsumed(t *testing.T) {
	tests := []struct {
		name            string
		transformations []string
		want            bool
	}{
		{
			name:            "zz present - consumed",
			transformations: []string{"zz", "other"},
			want:            true,
		},
		{
			name:            "zz absent - not consumed",
			transformations: []string{"\\zz", "other"},
			want:            false,
		},
		{
			name:            "empty",
			transformations: []string{},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBackslashConsumed(tt.transformations)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnchoredPayload(t *testing.T) {
	probe := "\\x41"
	ap := NewAnchoredPayload(probe)

	// Verify structure
	assert.Len(t, ap.LeftAnchor, 3)
	assert.True(t, len(ap.MiddleAnchor) == 2 && ap.MiddleAnchor[0] == 'z')
	assert.True(t, len(ap.RightAnchor) == 4 && ap.RightAnchor[0] == 'z')
	assert.Equal(t, probe, ap.Probe)

	// Verify full payload structure
	expected := ap.LeftAnchor + "\\\\" + ap.MiddleAnchor + probe + ap.RightAnchor
	assert.Equal(t, expected, ap.FullPayload)

	// Verify search anchor (single backslash after URL round-trip)
	expectedSearch := ap.LeftAnchor + "\\" + ap.MiddleAnchor
	assert.Equal(t, expectedSearch, ap.SearchAnchor())
}

func TestBasicReflectionPayload(t *testing.T) {
	payload, searchAnchor := NewBasicReflectionPayload()

	// Should contain double backslash in payload
	assert.Contains(t, payload, "\\\\")

	// Search anchor should have single backslash
	assert.Contains(t, searchAnchor, "\\")
	assert.NotContains(t, searchAnchor, "\\\\")

	// Both should start with same left anchor
	leftAnchor := payload[:5] // First 5 chars are left anchor
	assert.True(t, strings.HasPrefix(searchAnchor, leftAnchor))
}

func TestBackslashConsumptionPayload(t *testing.T) {
	payload, leftSearch, middleAnchor, rightAnchor := NewBackslashConsumptionPayload()

	// Payload should contain \\zz pattern
	assert.Contains(t, payload, "\\\\zz")

	// Middle anchor should be z + digit
	assert.Len(t, middleAnchor, 2)
	assert.Equal(t, byte('z'), middleAnchor[0])

	// Right anchor should be z + 3 chars
	assert.Len(t, rightAnchor, 4)
	assert.Equal(t, byte('z'), rightAnchor[0])

	// Left search should contain single backslash before middle anchor
	assert.Contains(t, leftSearch, "\\"+middleAnchor[:1])
}

func TestDecodeBasedPayloads(t *testing.T) {
	expected := []string{
		"\\101",   // Octal
		"\\x41",   // Hex
		"\\u0041", // Unicode
		"\\0",     // Null
		"\\1",     // Control char
		"\\x0",    // Truncated hex
	}
	assert.Equal(t, expected, DecodeBasedPayloads)
}

func TestCharacterPayloads(t *testing.T) {
	// Verify all expected special characters are present
	expectedChars := []string{
		"'", "\"", "{", "}", "(", ")", "[", "]",
		"$", "`", "/", "@", "#", ";", "%", "&", "|", "^", "?",
	}
	assert.Equal(t, expectedChars, CharacterPayloads)
}

func TestClassificationString(t *testing.T) {
	tests := []struct {
		c    Classification
		want string
	}{
		{ClassificationBoring, "boring"},
		{ClassificationBackslashConsumed, "backslashConsumed"},
		{ClassificationInteresting, "interesting"},
		{ClassificationTruncated, "truncated"},
		{ClassificationDisappeared, "disappeared"},
		{Classification(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.c.String())
		})
	}
}

func TestFilterInteresting(t *testing.T) {
	results := []*TransformResult{
		{Classification: ClassificationBoring},
		{Classification: ClassificationInteresting},
		{Classification: ClassificationBackslashConsumed},
		{Classification: ClassificationTruncated},
		{Classification: ClassificationDisappeared},
	}

	filtered := FilterInteresting(results)
	assert.Len(t, filtered, 2)
	assert.Equal(t, ClassificationInteresting, filtered[0].Classification)
	assert.Equal(t, ClassificationBackslashConsumed, filtered[1].Classification)
}

func TestRandomLowerString(t *testing.T) {
	s1 := randomLowerString(6)
	s2 := randomLowerString(6)

	// Verify length
	assert.Len(t, s1, 6)

	// Verify lowercase
	assert.Equal(t, strings.ToLower(s1), s1)

	// Random strings should differ (probabilistically)
	// Run multiple times to ensure randomness
	different := false
	for range 10 {
		s3 := randomLowerString(6)
		if s3 != s1 {
			different = true
			break
		}
	}
	assert.True(t, different, "random strings should be different")
	_ = s2
}
