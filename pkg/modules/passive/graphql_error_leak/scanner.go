package graphql_error_leak

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// leakPattern defines a detection rule for a specific type of GraphQL error leak.
type leakPattern struct {
	name    string
	pattern *regexp.Regexp
}

var leakPatterns = []leakPattern{
	// Field suggestion leaks: "Did you mean \"actualField\"?"
	{
		name:    "Field suggestion",
		pattern: regexp.MustCompile(`"Did you mean \\"[^"]+\\"\?"`),
	},
	// Type name exposure in error messages
	{
		name:    "Type name exposure",
		pattern: regexp.MustCompile(`"Cannot query field \\"[^"]+\\" on type \\"([^"]+)\\""`)},
	// Resolver path exposure: "path":["query","users","edges"]
	{
		name:    "Resolver path",
		pattern: regexp.MustCompile(`"path"\s*:\s*\[\s*"[^"]+"\s*(?:,\s*"[^"]+"\s*){1,}]`),
	},
	// Database/ORM error surfaced through GraphQL
	{
		name:    "Database error",
		pattern: regexp.MustCompile(`(?i)"message"\s*:\s*"(?:[^"]*(?:SQLSTATE|relation|column|table|constraint|duplicate key|foreign key|syntax error|ORA-|PG::|SequelizeDatabaseError|Prisma|TypeORM)[^"]*)"`)},
	// Stack trace in extensions.exception
	{
		name:    "Stack trace in error",
		pattern: regexp.MustCompile(`"(?:stacktrace|stack_trace|exception|backtrace)"\s*:\s*\[`)},
	// Internal server error with detailed message
	{
		name:    "Internal error details",
		pattern: regexp.MustCompile(`"message"\s*:\s*"(?:Internal server error|Unexpected error)[^"]*(?:at |in |/)[^"]*"`)},
	// Variable type validation leaking expected types
	{
		name:    "Variable type leak",
		pattern: regexp.MustCompile(`"Variable \\"[^"]+\\" of type \\"[^"]+\\" used in position expecting type \\"([^"]+)\\""`)},
	// Enum value suggestion
	{
		name:    "Enum value suggestion",
		pattern: regexp.MustCompile(`"value \\"[^"]+\\" does not exist in \\"([^"]+)\\" enum"`)},
}

// GraphQL error structure markers — require these to confirm it's a GraphQL response.
var graphqlErrorMarkers = []string{`"errors"`, `"message"`}

// Module implements the GraphQL Error Leak passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new GraphQL Error Leak module.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_graphql_error_leak"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes JSON responses for verbose GraphQL errors.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only inspect JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Confirm this is a GraphQL error response
	hasAllMarkers := true
	for _, marker := range graphqlErrorMarkers {
		if !strings.Contains(body, marker) {
			hasAllMarkers = false
			break
		}
	}
	if !hasAllMarkers {
		return nil, nil
	}

	// Check for leak patterns
	var matches []string
	for _, lp := range leakPatterns {
		match := lp.pattern.FindString(body)
		if match != "" {
			matches = append(matches, fmt.Sprintf("%s: %s", lp.name, truncate(match, 150)))
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	extracted := make([]string, 0, len(matches))
	for _, match := range matches {
		extracted = append(extracted, fmt.Sprintf("Leak: %s", match))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "GraphQL Verbose Error Detected",
				Description: fmt.Sprintf("GraphQL error response at %s leaks %d internal detail(s)", urlx.String(), len(matches)),
			},
		},
	}, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
