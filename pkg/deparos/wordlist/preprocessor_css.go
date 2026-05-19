package wordlist

import (
	"bytes"
	"context"
	"io"
	"regexp"
)

// CSSPreprocessor extracts class names, IDs, and URL values from CSS.
type CSSPreprocessor struct{}

// CSS extraction patterns
var (
	// Class selectors: .class-name
	cssClassPattern = regexp.MustCompile(`\.([a-zA-Z_][a-zA-Z0-9_-]*)`)

	// ID selectors: #id-name
	cssIDPattern = regexp.MustCompile(`#([a-zA-Z_][a-zA-Z0-9_-]*)`)

	// URL function: url("path") or url('path') or url(path)
	cssURLPattern = regexp.MustCompile(`url\s*\(\s*['"]?([^'"()\s]+)['"]?\s*\)`)

	// @import statements: @import "file.css" or @import url(...)
	cssImportPattern = regexp.MustCompile(`@import\s+['"]([^'"]+)['"]`)

	// Custom properties: --custom-property
	cssCustomPropPattern = regexp.MustCompile(`--([a-zA-Z][a-zA-Z0-9_-]*)`)

	// Animation/keyframe names
	cssAnimationPattern = regexp.MustCompile(`(?:animation(?:-name)?|@keyframes)\s*:\s*([a-zA-Z][a-zA-Z0-9_-]*)`)
)

// Process extracts meaningful identifiers from CSS.
func (p *CSSPreprocessor) Process(_ context.Context, reader io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	seen := make(map[string]struct{}) // Local dedup for this extraction

	// Helper to add unique values
	addUnique := func(value string) {
		if len(value) == 0 {
			return
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			output.WriteString(value)
			output.WriteByte(' ')
		}
	}

	// Extract class selectors
	for _, match := range cssClassPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	// Extract ID selectors
	for _, match := range cssIDPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	// Extract URL values
	for _, match := range cssURLPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	// Extract @import paths
	for _, match := range cssImportPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	// Extract custom property names
	for _, match := range cssCustomPropPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	// Extract animation names
	for _, match := range cssAnimationPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			addUnique(string(match[1]))
		}
	}

	return bytes.NewReader(output.Bytes()), nil
}

// ContentTypes returns the MIME types handled by this preprocessor.
func (p *CSSPreprocessor) ContentTypes() []string {
	return []string{
		"text/css",
	}
}
