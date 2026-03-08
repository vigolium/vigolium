package openapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const specLoadTimeout = 30 * time.Second

// LoadSpec loads an OpenAPI/Swagger spec from a file path or URL.
// Returns the content bytes and detected format extension (.json, .yaml, .yml).
func LoadSpec(input string) ([]byte, string, error) {
	if isURL(input) {
		return loadFromURL(input)
	}
	return loadFromFile(input)
}

// isURL checks if the input is a URL (starts with http:// or https://).
func isURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// loadFromFile reads spec from a local file.
func loadFromFile(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		ext = DetectFormatFromContent(data)
	}

	return data, ext, nil
}

// loadFromURL downloads spec from a URL.
func loadFromURL(url string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), specLoadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to detect format from URL path
	ext := strings.ToLower(filepath.Ext(strings.Split(url, "?")[0]))
	if ext == "" || (ext != ".json" && ext != ".yaml" && ext != ".yml") {
		// Try to detect from Content-Type header
		contentType := resp.Header.Get("Content-Type")
		ext = DetectFormatFromContentType(contentType)
		if ext == "" {
			ext = DetectFormatFromContent(data)
		}
	}

	return data, ext, nil
}

// DetectFormatFromContentType detects format from Content-Type header.
func DetectFormatFromContentType(contentType string) string {
	contentType = strings.ToLower(contentType)
	switch {
	case strings.Contains(contentType, "json"):
		return ".json"
	case strings.Contains(contentType, "yaml"):
		return ".yaml"
	}
	return ""
}

// DetectFormatFromContent detects format by examining content.
func DetectFormatFromContent(data []byte) string {
	// Skip whitespace
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		// JSON starts with { or [
		if c == '{' || c == '[' {
			return ".json"
		}
		// Otherwise assume YAML
		return ".yaml"
	}
	return ".yaml"
}
