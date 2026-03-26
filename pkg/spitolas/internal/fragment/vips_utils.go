package fragment

import (
	"strings"
)

// InlineElements are HTML elements that are typically inline.
var InlineElements = map[string]bool{
	"#text":    true,
	"text":     true,
	"a":        false, // 'a' is special - treated as block for VIPS
	"abbr":     true,
	"acronym":  true,
	"b":        true,
	"bdo":      true,
	"big":      true,
	"br":       false, // 'br' is line break
	"button":   true,
	"cite":     true,
	"code":     true,
	"dfn":      true,
	"em":       true,
	"i":        true,
	"img":      true,
	"input":    true,
	"kbd":      true,
	"label":    true,
	"map":      true,
	"object":   true,
	"output":   true,
	"q":        true,
	"samp":     true,
	"select":   true,
	"option":   true,
	"small":    true,
	"span":     true,
	"strong":   true,
	"sub":      true,
	"sup":      true,
	"textarea": true,
	"time":     true,
	"tt":       true,
	"var":      true,
}

// SemanticElements are HTML5 semantic elements with higher DoC.
var SemanticElements = map[string]bool{
	"article": true,
	"section": true,
	"header":  true,
	"footer":  true,
	"nav":     true,
	"aside":   true,
	"main":    true,
}

// IsInlineElement checks if a tag name is an inline element.
func IsInlineElement(tagName string) bool {
	return InlineElements[strings.ToLower(tagName)]
}

// IsSemanticElement checks if a tag name is a semantic element.
func IsSemanticElement(tagName string) bool {
	return SemanticElements[strings.ToLower(tagName)]
}

// IsTextNode checks if a tag name represents a text node.
func IsTextNode(tagName string) bool {
	lower := strings.ToLower(tagName)
	return lower == "#text" || lower == "text"
}

// IsTableElement checks if a tag name is a table-related element.
func IsTableElement(tagName string) bool {
	lower := strings.ToLower(tagName)
	return lower == "table" || lower == "tr" || lower == "td" || lower == "th" ||
		lower == "thead" || lower == "tbody" || lower == "tfoot"
}

// IsFormElement checks if a tag name is a form-related element.
func IsFormElement(tagName string) bool {
	lower := strings.ToLower(tagName)
	return lower == "form" || lower == "input" || lower == "select" ||
		lower == "textarea" || lower == "button" || lower == "label"
}

// VipsNodeInfo holds VIPS-related information about a DOM node.
// This is extracted via JavaScript and used for rule application.
type VipsNodeInfo struct {
	TagName         string   `json:"tagName"`
	XPath           string   `json:"xpath"`
	Selector        string   `json:"selector"`
	Rect            RectInfo `json:"rect"`
	IsDisplayed     bool     `json:"isDisplayed"`
	BackgroundColor string   `json:"backgroundColor"`
	FontSize        int      `json:"fontSize"`
	FontWeight      string   `json:"fontWeight"`
	ChildCount      int      `json:"childCount"`
	TextLength      int      `json:"textLength"`
	HasText         bool     `json:"hasText"`
	HasOnlyText     bool     `json:"hasOnlyText"`
	HasInlineOnly   bool     `json:"hasInlineOnly"`
	ContainsHR      bool     `json:"containsHR"`
	ContainsTable   bool     `json:"containsTable"`
	ContainsP       bool     `json:"containsP"`
	ContainsImg     bool     `json:"containsImg"`
	IsVirtual       bool     `json:"isVirtual"`
	Children        []string `json:"children"` // Child XPaths
}

// RectInfo holds rectangle information from JavaScript.
type RectInfo struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// ToRect converts RectInfo to Rect.
func (ri RectInfo) ToRect() Rect {
	return Rect(ri)
}

// IsValid checks if the rectangle is valid (visible).
func (ri RectInfo) IsValid() bool {
	return ri.Width > 0 && ri.Height > 0 && ri.X >= 0 && ri.Y >= 0
}

// GetArea returns the area of the rectangle.
func (ri RectInfo) GetArea() float64 {
	return ri.Width * ri.Height
}

// CalculateDoC calculates the Degree of Coherence based on VIPS rules.
// DoC ranges from 1 (low coherence) to 11 (high coherence).
func CalculateDoC(info *VipsNodeInfo, ruleApplied int) int {
	doc := 5 // Base DoC

	// Semantic elements get higher DoC
	if IsSemanticElement(info.TagName) {
		doc += 2
	}

	// Single child = more coherent
	if info.ChildCount <= 1 {
		doc += 2
	} else if info.ChildCount <= 3 {
		doc += 1
	} else if info.ChildCount > 10 {
		doc -= 2
	}

	// Text-only content = more coherent
	if info.HasOnlyText {
		doc += 2
	}

	// Table elements
	if IsTableElement(info.TagName) {
		doc = 7 // Table cells have moderate DoC
	}

	// Form elements
	if IsFormElement(info.TagName) {
		doc = 8
	}

	// Apply rule-specific adjustments
	switch ruleApplied {
	case 4: // Rule 4: All children are text/virtual text
		if info.FontWeight == "bold" || info.FontWeight == "700" {
			doc = 10
		} else {
			doc = 9
		}
	case 7: // Rule 7: Different background colors
		doc = 7
	case 8: // Rule 8: Has text, small size
		if strings.ToLower(info.TagName) == "div" {
			doc = 5
		} else {
			doc = 8
		}
	case 9: // Rule 9: Max child size threshold
		if strings.ToLower(info.TagName) == "a" {
			doc = 11
		} else {
			doc = 8
		}
	case 12: // Rule 12: Do not divide
		switch strings.ToLower(info.TagName) {
		case "li", "span", "sup", "img":
			doc = 8
		default:
			doc = 7
		}
	}

	// Clamp to valid range
	if doc < 1 {
		doc = 1
	}
	if doc > 11 {
		doc = 11
	}

	return doc
}

// SizeThreshold represents size threshold for VIPS iterations.
type SizeThreshold struct {
	Width  int
	Height int
}

// IterationThresholds returns the size thresholds for each VIPS iteration.
func IterationThresholds(numIterations int) []SizeThreshold {
	thresholds := make([]SizeThreshold, numIterations)

	// Initial threshold based on iterations
	initialSize := (numIterations-5)*50 + 100
	if initialSize < 100 {
		initialSize = 100
	}

	for i := 0; i < numIterations; i++ {
		switch {
		case i < numIterations-5:
			size := initialSize - (i * 50)
			if size < 100 {
				size = 100
			}
			thresholds[i] = SizeThreshold{size, size}
		case i == numIterations-5:
			thresholds[i] = SizeThreshold{100, 100}
		case i == numIterations-4:
			thresholds[i] = SizeThreshold{80, 80}
		case i == numIterations-3:
			thresholds[i] = SizeThreshold{50, 50}
		case i == numIterations-2:
			thresholds[i] = SizeThreshold{20, 20}
		default: // Last iteration
			thresholds[i] = SizeThreshold{1, 1}
		}
	}

	return thresholds
}
