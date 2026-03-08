package info_disclosure_detect

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

// disclosureCheck defines an information disclosure pattern.
type disclosureCheck struct {
	name    string
	source  string // "header" or "body"
	pattern *regexp.Regexp
}

var headerChecks = []disclosureCheck{
	{"Server Version", "header", regexp.MustCompile(`(?i)^(?:Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|Tomcat|Jetty|lighttpd)[\s/][\d.]+`)},
	{"X-Powered-By", "header", regexp.MustCompile(`(?i)^(?:PHP|ASP\.NET|Express|Servlet|JSP|Django|Ruby|Flask)`)},
	{"X-AspNet-Version", "header", regexp.MustCompile(`^\d+\.\d+`)},
	{"X-AspNetMvc-Version", "header", regexp.MustCompile(`^\d+\.\d+`)},
}

var bodyChecks = []disclosureCheck{
	{"Internal IP Address", "body", regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)},
	{"Stack Trace", "body", regexp.MustCompile(`(?i)(?:Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|Exception in thread|Fatal error:.*in .* on line \d+)`)},
	{"Debug Mode", "body", regexp.MustCompile(`(?i)(?:DJANGO_SETTINGS_MODULE|settings\.DEBUG|Werkzeug Debugger|Laravel.*debug.*true)`)},
	{"Directory Listing", "body", regexp.MustCompile(`(?i)(?:<title>Index of /|<title>Directory listing for|<title>listing directory|Parent Directory</a>)`)},
}

// Module implements the Information Disclosure Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Info Disclosure Detect module.
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
		rhm: dedup.LazyDefaultRHM("passive_info_disclosure_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response for information disclosure.
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

	var findings []string

	// Check headers
	for _, check := range headerChecks {
		val := ctx.Response().Header(check.name)
		if val != "" && check.pattern.MatchString(val) {
			findings = append(findings, fmt.Sprintf("%s: %s: %s", check.name, check.source, val))
		}
	}

	// Check body
	body := ctx.Response().BodyToString()
	if body != "" {
		// Skip binary content
		ct := strings.ToLower(ctx.Response().Header("Content-Type"))
		if !strings.Contains(ct, "image/") && !strings.Contains(ct, "audio/") &&
			!strings.Contains(ct, "video/") && !strings.Contains(ct, "octet-stream") {
			for _, check := range bodyChecks {
				if match := check.pattern.FindString(body); match != "" {
					findings = append(findings, fmt.Sprintf("%s: %s", check.name, truncate(match, 100)))
				}
			}
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: findings,
			Info: output.Info{
				Description: fmt.Sprintf("Found %d information disclosure(s)", len(findings)),
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
