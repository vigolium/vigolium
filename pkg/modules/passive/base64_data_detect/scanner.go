package base64_data_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// base64Re matches interesting base64 encoded data prefixes:
//   - eyJ  = JSON ({"...)
//   - YTo  = PHP serialized array (a:...)
//   - Tzo  = PHP serialized object (O:...)
//   - PD8  = XML (<?...)
//   - PD9  = PHP (<?p...)
//   - aHR0cHM6L = https://
//   - aHR0cDo   = http:
//   - rO0  = Java serialized object
var base64Re = regexp.MustCompile(`([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}`)

var references = []string{
	"https://portswigger.net/kb/issues/00700200_base64-encoded-data-in-parameter",
	"https://cheatsheetseries.owasp.org/index.html",
}

// Module implements the Base64 Data Detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Base64 Data Detection module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeBoth,
		),
		rhm: dedup.LazyDefaultRHM("passive_base64_data_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks both request and response for interesting base64 encoded data.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	// Check response body
	if ctx.Response() != nil {
		body := ctx.Response().BodyToString()
		if body != "" {
			ct := strings.ToLower(ctx.Response().Header("Content-Type"))
			if !isMediaContentType(ct) {
				if matches := findBase64Matches(body); len(matches) > 0 {
					if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), "", "", "b64-resp") {
						results = append(results, &output.ResultEvent{
							ModuleID: ModuleID,
							Host:     urlx.Host,
							URL:      urlx.String(),
							Matched:  urlx.String(),
							Request:  string(ctx.Request().Raw()),
							ExtractedResults: append(
								[]string{"Source: response"},
								formatMatches(matches)...,
							),
							Info: output.Info{
								Name:        "Base64 Encoded Data in Response",
								Description: "Interesting base64-encoded information discovered within the response. Manual review is recommended.",
								Reference:   references,
								Tags:        []string{"base64", "encode", "interesting"},
							},
						})
					}
				}
			}
		}
	}

	// Check request (raw bytes include URL, headers, and body)
	if ctx.Request() != nil {
		raw := string(ctx.Request().Raw())
		if matches := findBase64Matches(raw); len(matches) > 0 {
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), "", "", "b64-req") {
				results = append(results, &output.ResultEvent{
					ModuleID: ModuleID,
					Host:     urlx.Host,
					URL:      urlx.String(),
					Matched:  urlx.String(),
					Request:  raw,
					ExtractedResults: append(
						[]string{"Source: request"},
						formatMatches(matches)...,
					),
					Info: output.Info{
						Name:        "Base64 Encoded Data in Request",
						Description: "Interesting base64-encoded information discovered within the request. Manual review is recommended.",
						Reference:   references,
						Tags:        []string{"base64", "encode", "interesting"},
					},
				})
			}
		}
	}

	return results, nil
}

// findBase64Matches returns unique base64 matches from the input.
func findBase64Matches(s string) []string {
	allMatches := base64Re.FindAllString(s, 20)
	if len(allMatches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(allMatches))
	var unique []string
	for _, match := range allMatches {
		// Trim leading non-base64 character from the match group
		trimmed := strings.TrimLeft(match, " \t\r\n&?=;,\"'<>{}[]():/")
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	return unique
}

// formatMatches truncates and formats base64 matches for display.
func formatMatches(matches []string) []string {
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		prefix := identifyPrefix(match)
		out = append(out, fmt.Sprintf("%s: %s", prefix, truncate(match, 80)))
	}
	return out
}

// identifyPrefix returns a human-readable label for the base64 prefix.
func identifyPrefix(s string) string {
	switch {
	case strings.HasPrefix(s, "eyJ"):
		return "JSON object"
	case strings.HasPrefix(s, "YTo"):
		return "PHP serialized array"
	case strings.HasPrefix(s, "Tzo"):
		return "PHP serialized object"
	case strings.HasPrefix(s, "PD8"):
		return "XML declaration"
	case strings.HasPrefix(s, "PD9"):
		return "PHP tag"
	case strings.HasPrefix(s, "aHR0cHM6L"):
		return "HTTPS URL"
	case strings.HasPrefix(s, "aHR0cDo"):
		return "HTTP URL"
	case strings.HasPrefix(s, "rO0"):
		return "Java serialized object"
	default:
		return "Base64 data"
	}
}

// isMediaContentType returns true for binary/media content types.
func isMediaContentType(ct string) bool {
	return strings.Contains(ct, "image/") ||
		strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") ||
		strings.Contains(ct, "octet-stream")
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
