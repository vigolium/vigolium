package input

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// uuidPattern matches UUIDs (8-4-4-4-12 hex digits).
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// httpMethodPattern matches raw HTTP request start lines.
var httpMethodPattern = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/`)

// base64Pattern matches strings that look like base64-encoded data:
// long enough, only valid base64 chars, optional padding.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/\s]+=*\s*$`)

// DetectInputType determines the input format from the raw string content.
func DetectInputType(input string) agenttypes.InputType {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return agenttypes.InputTypeUnknown
	}

	// UUID (record from DB)
	if uuidPattern.MatchString(trimmed) {
		return agenttypes.InputTypeRecordUUID
	}

	// Curl command
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "curl ") || strings.HasPrefix(lower, "$ curl ") {
		return agenttypes.InputTypeCurl
	}

	// Burp XML
	if strings.HasPrefix(trimmed, "<?xml") || strings.HasPrefix(trimmed, "<items") {
		return agenttypes.InputTypeBurp
	}

	// Raw HTTP request (starts with METHOD /path HTTP/x.x)
	if httpMethodPattern.MatchString(trimmed) {
		return agenttypes.InputTypeRaw
	}

	// URL
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return agenttypes.InputTypeURL
	}

	// Base64-encoded HTTP request (e.g. Burp base64 export)
	// Must be long enough to be meaningful and decode to a valid HTTP request.
	if len(trimmed) >= 20 && base64Pattern.MatchString(trimmed) {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(trimmed)); err == nil {
			decodedStr := string(decoded)
			if httpMethodPattern.MatchString(decodedStr) {
				return agenttypes.InputTypeBase64
			}
		}
	}

	return agenttypes.InputTypeUnknown
}

// NormalizeInput converts a raw input string into HttpRequestResponse objects.
// The inputType can be empty/unknown, in which case auto-detection is used.
func NormalizeInput(ctx context.Context, input string, inputType agenttypes.InputType, repo *database.Repository) ([]*httpmsg.HttpRequestResponse, error) {
	if inputType == "" || inputType == agenttypes.InputTypeUnknown {
		inputType = DetectInputType(input)
	}

	switch inputType {
	case agenttypes.InputTypeURL:
		return normalizeURL(input)
	case agenttypes.InputTypeCurl:
		return normalizeCurl(input)
	case agenttypes.InputTypeRaw:
		return normalizeRaw(input)
	case agenttypes.InputTypeBurp:
		return normalizeBurp(input)
	case agenttypes.InputTypeBase64:
		return normalizeBase64(input)
	case agenttypes.InputTypeRecordUUID:
		return normalizeRecordUUID(ctx, input, repo)
	default:
		return nil, fmt.Errorf("unable to detect input format; specify --input-type or use a supported format (URL, curl, raw HTTP, Burp XML, base64, record UUID)")
	}
}

func normalizeURL(input string) ([]*httpmsg.HttpRequestResponse, error) {
	url := strings.TrimSpace(input)
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create request from URL %q: %w", url, err)
	}
	return []*httpmsg.HttpRequestResponse{rr}, nil
}

func normalizeCurl(input string) ([]*httpmsg.HttpRequestResponse, error) {
	// Import curl parser lazily to avoid circular dependencies
	// The curl format parser is available as a package-level function
	trimmed := strings.TrimSpace(input)

	// Strip leading "$ " if present
	trimmed = strings.TrimPrefix(trimmed, "$ ")

	rr, err := parseCurlCommand(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse curl command: %w", err)
	}
	return []*httpmsg.HttpRequestResponse{rr}, nil
}

func normalizeRaw(input string) ([]*httpmsg.HttpRequestResponse, error) {
	rr, err := httpmsg.ParseRawRequest(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw HTTP request: %w", err)
	}
	return []*httpmsg.HttpRequestResponse{rr}, nil
}

func normalizeBurp(input string) ([]*httpmsg.HttpRequestResponse, error) {
	results, err := parseBurpXML(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Burp XML: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no HTTP requests found in Burp XML")
	}
	return results, nil
}

func normalizeBase64(input string) ([]*httpmsg.HttpRequestResponse, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 input: %w", err)
	}
	return normalizeRaw(string(decoded))
}

// TargetURLFromInput normalizes a raw input string and extracts the target URL.
// Useful for commands that need to derive --target from --input.
func TargetURLFromInput(ctx context.Context, input string, inputType agenttypes.InputType, repo *database.Repository) (string, error) {
	records, err := NormalizeInput(ctx, input, inputType, repo)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("no HTTP requests found in input")
	}
	if records[0].Request() != nil {
		if u, urlErr := records[0].URL(); urlErr == nil {
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("could not extract target URL from input")
}

func normalizeRecordUUID(ctx context.Context, input string, repo *database.Repository) ([]*httpmsg.HttpRequestResponse, error) {
	if repo == nil {
		return nil, fmt.Errorf("database repository required for record UUID lookup")
	}

	uuid := strings.TrimSpace(input)
	record, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch record %q: %w", uuid, err)
	}

	rr, err := database.RecordToHttpRequestResponse(record)
	if err != nil {
		return nil, fmt.Errorf("failed to convert record %q: %w", uuid, err)
	}

	return []*httpmsg.HttpRequestResponse{rr}, nil
}
