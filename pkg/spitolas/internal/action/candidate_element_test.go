// Package action provides web crawling action types and handling.
package action

import (
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// Test class for the CandidateElement class.
// Author: Stefan Lenselink <S.R.Lenselink@student.tudelft.nl>
// =============================================================================

func newTestCandidateElement(tagName string, attributes map[string]string) *CandidateElement {
	var attrParts []string
	for key, value := range attributes {
		attrParts = append(attrParts, key+"="+value)
	}
	sort.Strings(attrParts)
	attrsStr := strings.Join(attrParts, " ")

	return &CandidateElement{
		Identification: NewIdentification(HowXPath, ""), // xpath is empty in test
		RelatedFrame:   "",
		FormInputs:     make([]*FormInput, 0),
		TagName:        tagName,
		Attributes:     attrsStr,
		EventType:      EventTypeClick,
	}
}

// TestEmptyElement tests element with no attributes.
func TestEmptyElement(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{})

	// Assert.assertEquals("General String and Unique String are the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() != c.GetUniqueString() {
		t.Errorf("General String and Unique String should be the same")
		t.Errorf("GeneralString: %q", c.GetGeneralString())
		t.Errorf("UniqueString: %q", c.GetUniqueString())
	}

	// Assert.assertEquals("Expected result", "TEST:  xpath", c.getGeneralString().trim());
	expected := "TEST:  xpath"
	actual := strings.TrimSpace(c.GetGeneralString())
	if actual != expected {
		t.Errorf("GetGeneralString() = %q, want %q", actual, expected)
	}
}

// TestOneAttributeElement tests element with one attribute.
func TestOneAttributeElement(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc"})

	// Assert.assertEquals("General String and Unique String are the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() != c.GetUniqueString() {
		t.Errorf("General String and Unique String should be the same")
		t.Errorf("GeneralString: %q", c.GetGeneralString())
		t.Errorf("UniqueString: %q", c.GetUniqueString())
	}

	// Assert.assertEquals("Expected result", "TEST: id=abc xpath", c.getGeneralString().trim());
	expected := "TEST: id=abc xpath"
	actual := strings.TrimSpace(c.GetGeneralString())
	if actual != expected {
		t.Errorf("GetGeneralString() = %q, want %q", actual, expected)
	}
}

// TestTwoAttributeElement tests element with two attributes.
func TestTwoAttributeElement(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc", "class": "def"})

	// Assert.assertEquals("General String and Unique String are the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() != c.GetUniqueString() {
		t.Errorf("General String and Unique String should be the same")
		t.Errorf("GeneralString: %q", c.GetGeneralString())
		t.Errorf("UniqueString: %q", c.GetUniqueString())
	}

	// Assert.assertEquals("Expected result", "TEST: class=def id=abc xpath", c.getGeneralString().trim());
	// Note: attributes are sorted alphabetically
	expected := "TEST: class=def id=abc xpath"
	actual := strings.TrimSpace(c.GetGeneralString())
	if actual != expected {
		t.Errorf("GetGeneralString() = %q, want %q", actual, expected)
	}
}

// TestOneAttributeElementWithAtusa tests element with atusa attribute.
func TestOneAttributeElementWithAtusa(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc", "atusa": "ignore"})

	// Assert.assertNotSame("General String and Unique String are not the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() == c.GetUniqueString() {
		t.Errorf("General String and Unique String should NOT be the same when atusa is present")
		t.Errorf("GeneralString: %q", c.GetGeneralString())
		t.Errorf("UniqueString: %q", c.GetUniqueString())
	}

	// Assert.assertEquals("Expected result", "TEST: id=abc xpath", c.getGeneralString().trim());
	expectedGeneral := "TEST: id=abc xpath"
	actualGeneral := strings.TrimSpace(c.GetGeneralString())
	if actualGeneral != expectedGeneral {
		t.Errorf("GetGeneralString() = %q, want %q", actualGeneral, expectedGeneral)
	}

	// Assert.assertEquals("Expected result", "TEST: atusa=ignore id=abc xpath", c.getUniqueString().trim());
	expectedUnique := "TEST: atusa=ignore id=abc xpath"
	actualUnique := strings.TrimSpace(c.GetUniqueString())
	if actualUnique != expectedUnique {
		t.Errorf("GetUniqueString() = %q, want %q", actualUnique, expectedUnique)
	}
}

// TestTwoAttributeElementWithAtusa tests element with two attributes and atusa.
func TestTwoAttributeElementWithAtusa(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc", "atusa": "ignore", "class": "def"})

	// Assert.assertNotSame("General String and Unique String are not the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() == c.GetUniqueString() {
		t.Errorf("General String and Unique String should NOT be the same when atusa is present")
	}

	// Assert.assertEquals("Expected result", "TEST: class=def id=abc xpath", c.getGeneralString().trim());
	expectedGeneral := "TEST: class=def id=abc xpath"
	actualGeneral := strings.TrimSpace(c.GetGeneralString())
	if actualGeneral != expectedGeneral {
		t.Errorf("GetGeneralString() = %q, want %q", actualGeneral, expectedGeneral)
	}

	// Assert.assertEquals("Expected result", "TEST: atusa=ignore class=def id=abc xpath", c.getUniqueString().trim());
	expectedUnique := "TEST: atusa=ignore class=def id=abc xpath"
	actualUnique := strings.TrimSpace(c.GetUniqueString())
	if actualUnique != expectedUnique {
		t.Errorf("GetUniqueString() = %q, want %q", actualUnique, expectedUnique)
	}
}

// TestGetTypeFromStrFile tests InputTypeFile detection.
func TestGetTypeFromStrFile(t *testing.T) {
	tests := []struct {
		input string
		want  InputType
	}{
		{"file", InputTypeFile},
		{"FILE", InputTypeFile},
		{"File", InputTypeFile},
	}

	for _, tt := range tests {
		got := GetTypeFromStr(tt.input)
		if got != tt.want {
			t.Errorf("GetTypeFromStr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestMultipleAttributeElementWithAtusaOrderedAlphabetical tests attributes are sorted alphabetically.
func TestMultipleAttributeElementWithAtusaOrderedAlphabetical(t *testing.T) {
	c := newTestCandidateElement("TEST", map[string]string{
		"id":    "abc",
		"atusa": "ignore",
		"class": "def",
		"z":     "z",
		"a":     "a",
		"x":     "a",
	})

	// Assert.assertNotSame("General String and Unique String are not the same",
	//     c.getGeneralString(), c.getUniqueString());
	if c.GetGeneralString() == c.GetUniqueString() {
		t.Errorf("General String and Unique String should NOT be the same when atusa is present")
	}

	// Assert.assertEquals("Expected result", "TEST: a=a class=def id=abc x=a z=z xpath", c.getGeneralString().trim());
	expectedGeneral := "TEST: a=a class=def id=abc x=a z=z xpath"
	actualGeneral := strings.TrimSpace(c.GetGeneralString())
	if actualGeneral != expectedGeneral {
		t.Errorf("GetGeneralString() = %q, want %q", actualGeneral, expectedGeneral)
	}

	// Assert.assertEquals("Expected result", "TEST: a=a atusa=ignore class=def id=abc x=a z=z xpath", c.getUniqueString().trim());
	expectedUnique := "TEST: a=a atusa=ignore class=def id=abc x=a z=z xpath"
	actualUnique := strings.TrimSpace(c.GetUniqueString())
	if actualUnique != expectedUnique {
		t.Errorf("GetUniqueString() = %q, want %q", actualUnique, expectedUnique)
	}
}
