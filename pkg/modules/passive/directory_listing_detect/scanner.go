package directory_listing_detect

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

// iisPattern matches IIS default directory listing HTML structure.
var iisPattern = regexp.MustCompile(`</title></head><body><H1>.*?-.*?</H1><hr>`)

// genericListingPattern matches generic directory listing titles like:
// <title>listing directory /ftp/</title>, <title>Directory listing for /</title>,
// <title>Index of /uploads</title>, <title>Directory: /path</title>
var genericListingPattern = regexp.MustCompile(`(?i)<title>\s*(?:(?:listing|index)\s+(?:of|directory)|directory\s+(?:listing|index|of))\b`)

// Module implements the Directory Listing Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Directory Listing Detect module.
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
		rhm: dedup.LazyDefaultRHM("passive_directory_listing_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response for directory listing indicators.
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

	// Only process 2xx responses
	statusCode := ctx.Response().StatusCode()
	if statusCode < 200 || statusCode >= 300 {
		return nil, nil
	}

	// Skip binary/media content types
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") || strings.Contains(ct, "octet-stream") {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	serverType := detectDirectoryListing(body)
	if serverType == "" {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:    urlx.Host,
			URL:     urlx.String(),
			Request: string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Server: %s", serverType),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Directory Listing Detected (%s)", serverType),
				Description: fmt.Sprintf("Response contains %s directory listing indicators, potentially exposing sensitive files and internal assets", serverType),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"directory-listing", "misconfiguration", "information-disclosure"},
				Reference: []string{
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
				},
			},
		},
	}, nil
}

// detectDirectoryListing checks the response body for server-specific directory listing indicators.
// Returns the server type string if detected, empty string otherwise.
func detectDirectoryListing(body string) string {
	lower := strings.ToLower(body)

	// Jetty: <title>Directory: AND jetty-dir.css
	if strings.Contains(lower, "<title>directory:") && strings.Contains(lower, "jetty-dir.css") {
		return "Jetty"
	}

	// IIS: </title></head><body><H1>...-...</H1><hr>
	if iisPattern.MatchString(body) {
		return "IIS"
	}

	// Apache: <title>Index of AND <h1>Index of
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<h1>index of") {
		return "Apache"
	}

	// Nginx: <title>Index of AND <pre>
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<pre>") {
		return "Nginx"
	}

	// Generic catch-all: matches title patterns like "listing directory", "directory listing",
	// "index of", "directory of", etc. Covers Express serve-index, Python SimpleHTTPServer,
	// and other servers with directory listing titles.
	if genericListingPattern.MatchString(body) {
		return "Generic"
	}

	return ""
}
