// Package action provides web crawling action types and handling.
// This file implements Identification matching Java Crawljax's
// com.crawljax.core.state.Identification exactly.
package action

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// How defines the method used for identifying elements on the DOM tree.
// CRAWLJAX PARITY: Matches Java Identification.How enum EXACTLY.
// NOTE: NO HowCSS - Crawljax does not have CSS selector in How enum.
type How string

const (
	// HowXPath identifies element by XPath expression
	HowXPath How = "xpath"
	// HowName identifies element by name attribute
	HowName How = "name"
	// HowID identifies element by id attribute
	HowID How = "id"
	// HowTag identifies element by tag name
	HowTag How = "tag"
	// HowText identifies element by link text
	HowText How = "text"
	// HowPartialText identifies element by partial link text
	HowPartialText How = "partialText"
	// HowURL identifies element by URL (for navigation)
	HowURL How = "url"
)

// Identification identifies a specific element using a method and value.
// Matches Java com.crawljax.core.state.Identification exactly.
type Identification struct {
	How   How    `json:"how"`
	Value string `json:"value"`
}

// NewIdentification creates a new Identification.
// Matches Java constructor: Identification(How how, String value)
func NewIdentification(how How, value string) *Identification {
	return &Identification{
		How:   how,
		Value: value,
	}
}

// GetHow returns the identification method.
// Matches Java getHow()
func (i *Identification) GetHow() How {
	return i.How
}

// SetHow sets the identification method.
// Matches Java setHow(How how)
func (i *Identification) SetHow(how How) {
	i.How = how
}

// GetValue returns the identification value.
// Matches Java getValue()
func (i *Identification) GetValue() string {
	return i.Value
}

// SetValue sets the identification value.
// Matches Java setValue(String value)
func (i *Identification) SetValue(value string) {
	i.Value = value
}

// String converts Identification to a String.
// Matches Java toString(): returns "how value"
func (i *Identification) String() string {
	return fmt.Sprintf("%s %s", i.How, i.Value)
}

// Equals checks equality with another Identification.
// Matches Java equals(Object obj)
func (i *Identification) Equals(other *Identification) bool {
	if other == nil {
		return false
	}
	if i == other {
		return true
	}
	return i.How == other.How && i.Value == other.Value
}

// HashCode returns hash for use as map key.
// CRAWLJAX PARITY: Matches Java hashCode() using Apache HashCodeBuilder pattern.
func (i *Identification) HashCode() uint32 {
	h := fnv.New32a()
	h.Write([]byte(string(i.How)))
	h.Write([]byte(i.Value))
	return h.Sum32()
}

// ToXPath converts the identification to an XPath expression.
// CRAWLJAX PARITY: Equivalent to Java Identification.getWebDriverBy() but returns XPath string.
// This is used for element lookup via Rod's ElementX().
func (i *Identification) ToXPath() string {
	switch i.How {
	case HowID:
		// Use attribute selector to handle special chars in IDs (e.g., ":rs:")
		return fmt.Sprintf("//*[@id='%s']", i.Value)
	case HowName:
		return fmt.Sprintf("//*[@name='%s']", i.Value)
	case HowXPath:
		// CRAWLJAX PARITY: XPath workaround for HLWK driver bug
		return strings.ReplaceAll(i.Value, "/BODY[1]/", "/BODY/")
	case HowTag:
		// CRAWLJAX PARITY: Java By.tagName() doesn't uppercase, XPath is case-sensitive
		return fmt.Sprintf("//%s", i.Value)
	case HowText:
		return fmt.Sprintf("//a[text()='%s']", i.Value)
	case HowPartialText:
		return fmt.Sprintf("//a[contains(text(),'%s')]", i.Value)
	default:
		return ""
	}
}
