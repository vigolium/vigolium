// Package action provides web crawling action types and handling.
// This file ports CandidateElementTest.java from Crawljax exactly.
package action

import (
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// CRAWLJAX PARITY: CandidateElementTest.java
// Test class for the CandidateElement class.
// Author: Stefan Lenselink <S.R.Lenselink@student.tudelft.nl>
// =============================================================================

// Helper to create a CandidateElement matching Java test setup.
// Java: document = DomUtils.asDocument("");
// Java: e = document.createElement("test");
// Java: c = new CandidateElement(e, "", noFormInput);
func newTestCandidateElement(tagName string, attributes map[string]string) *CandidateElement {
	// Build attributes string in alphabetical order (matching Java's NamedNodeMap iteration)
	// Java DomUtils.getAllElementAttributes iterates attributes in order
	var attrParts []string
	for key, value := range attributes {
		attrParts = append(attrParts, key+"="+value)
	}
	// Sort alphabetically to match Java behavior
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
// Crawljax parity: CandidateElementTest.testEmptyElement()
func TestEmptyElement(t *testing.T) {
	// Java: e = document.createElement("test");
	// Java: c = new CandidateElement(e, "", noFormInput);
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
// Crawljax parity: CandidateElementTest.testOneAttributeElement()
func TestOneAttributeElement(t *testing.T) {
	// Java: e.setAttribute("id", "abc");
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
// Crawljax parity: CandidateElementTest.testTwoAttributeElement()
func TestTwoAttributeElement(t *testing.T) {
	// Java: e.setAttribute("id", "abc");
	// Java: e.setAttribute("class", "def");
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
// Crawljax parity: CandidateElementTest.testOneAttributeElementWithAtusa()
func TestOneAttributeElementWithAtusa(t *testing.T) {
	// Java: e.setAttribute("id", "abc");
	// Java: e.setAttribute("atusa", "ignore");
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
// Crawljax parity: CandidateElementTest.testTwoAttributeElementWithAtusa()
func TestTwoAttributeElementWithAtusa(t *testing.T) {
	// Java: e.setAttribute("id", "abc");
	// Java: e.setAttribute("atusa", "ignore");
	// Java: e.setAttribute("class", "def");
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
// GO EXTENSION: Not in Crawljax
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
// Crawljax parity: CandidateElementTest.testMultipleAttributeElementWithAtusaOrderedAlphabetical()
func TestMultipleAttributeElementWithAtusaOrderedAlphabetical(t *testing.T) {
	// Java: e.setAttribute("id", "abc");
	// Java: e.setAttribute("atusa", "ignore");
	// Java: e.setAttribute("class", "def");
	// Java: e.setAttribute("z", "z");
	// Java: e.setAttribute("a", "a");
	// Java: e.setAttribute("x", "a");
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
