package info_disclosure_detect

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// disclosureCheck defines an information disclosure pattern.
type disclosureCheck struct {
	name       string
	headerName string
	pattern    *regexp.Regexp
}

var headerChecks = []disclosureCheck{
	{"Server Version", "Server", regexp.MustCompile(`(?i)^(?:Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|Tomcat|Jetty|lighttpd)[\s/][\d.]+`)},
	{"Framework Version", "X-Powered-By", regexp.MustCompile(`(?i)^(?:PHP|ASP\.NET|Express|Servlet|JSP|Django|Ruby|Flask)(?:[/\s][\w.-]+)?`)},
	{"ASP.NET Version", "X-AspNet-Version", regexp.MustCompile(`^\d+\.\d+`)},
	{"ASP.NET MVC Version", "X-AspNetMvc-Version", regexp.MustCompile(`^\d+\.\d+`)},
}

var (
	privateIPv4Candidate = regexp.MustCompile(`\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	debugPrimary         = regexp.MustCompile(`(?i)(?:DJANGO_SETTINGS_MODULE|settings\.DEBUG|Werkzeug Debugger|Laravel[^\r\n]{0,80}debug[^\r\n]{0,20}true)`)
	debugCorroboration   = regexp.MustCompile(`(?i)(?:Traceback \(most recent call last\)|interactive debugger|console locked|stack trace|File ["'][^"']+["'], line \d+|Exception\b)`)
	directoryTitle       = regexp.MustCompile(`(?i)<title>\s*(?:Index of /|Directory listing for|listing directory)`)
	directoryNavigation  = regexp.MustCompile(`(?i)(?:Parent Directory</a>|href=["']\.\.?/["']|(?:Last modified|Name)\s*</th>)`)
)

type disclosureMatch struct {
	name        string
	evidence    string
	description string
	kind        output.RecordKind
	grade       output.EvidenceGrade
	severity    severity.Severity
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
	// A WAF/CDN edge block's headers and body are the edge's, not the
	// application's — its Server version, error text, or stack-trace-like content
	// is not the app disclosing information.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	var matches []disclosureMatch

	for _, check := range headerChecks {
		val := ctx.Response().Header(check.headerName)
		if val != "" && check.pattern.MatchString(val) {
			matches = append(matches, disclosureMatch{
				name:        check.name + " Disclosed",
				evidence:    fmt.Sprintf("%s: %s", check.headerName, truncate(val, 100)),
				description: "A response header identifies server or framework technology. This is reconnaissance context, not proof that the disclosed version is vulnerable.",
				kind:        output.RecordKindObservation,
				grade:       output.EvidenceGradeObservation,
				severity:    severity.Info,
			})
		}
	}

	body := ctx.Response().BodyToString()
	if body != "" {
		// Skip static assets and binary payloads. Internal IPs, "stack trace"
		// tokens, and "DEBUG" strings appear all over minified JS/CSS bundles
		// (dev hosts, example IPs, library error text); a body match there is not
		// a real disclosure. URL-extension gating misses extensionless JS, so
		// gate on the actual Content-Type. Header checks above still run.
		if !modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
			if privateIP := firstPrivateIPv4(body); privateIP != "" {
				matches = append(matches, disclosureMatch{
					name:        "Internal Network Address Disclosed",
					evidence:    "Private address: " + privateIP,
					description: "The response contains a syntactically valid private IPv4 address. It may reveal topology, but sensitivity and attacker usefulness depend on surrounding context.",
					kind:        output.RecordKindObservation,
					grade:       output.EvidenceGradeObservation,
					severity:    severity.Info,
				})
			}

			if primary := debugPrimary.FindString(body); primary != "" {
				match := disclosureMatch{
					name:        "Debug Artifact in Response",
					evidence:    "Debug marker: " + truncate(primary, 100),
					description: "A framework debug marker is present, but a single marker can occur in documentation or ordinary page text.",
					kind:        output.RecordKindObservation,
					grade:       output.EvidenceGradeObservation,
					severity:    severity.Info,
				}
				if corroborating := debugCorroboration.FindString(body); corroborating != "" && !strings.EqualFold(primary, corroborating) {
					match.kind = output.RecordKindCandidate
					match.grade = output.EvidenceGradeCandidate
					match.severity = severity.Low
					match.evidence += "; corroborating marker: " + truncate(corroborating, 100)
					match.description = "Independent framework and error/debug anchors indicate that a debug response may be exposed. Interactive access or sensitive state was not tested."
				}
				matches = append(matches, match)
			}

			if title := directoryTitle.FindString(body); title != "" {
				match := disclosureMatch{
					name:        "Directory Listing Marker",
					evidence:    "Listing title: " + truncate(title, 100),
					description: "A directory-listing title is visible, but no independent listing structure was found.",
					kind:        output.RecordKindObservation,
					grade:       output.EvidenceGradeObservation,
					severity:    severity.Info,
				}
				if navigation := directoryNavigation.FindString(body); navigation != "" {
					match.name = "Directory Listing Exposed"
					match.kind = output.RecordKindCandidate
					match.grade = output.EvidenceGradeCandidate
					match.severity = severity.Low
					match.evidence += "; listing structure: " + truncate(navigation, 100)
					match.description = "A directory-listing title and independent navigation structure are present. The listing may be intentionally public; sensitive file access was not established."
				}
				matches = append(matches, match)
			}
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	results := make([]*output.ResultEvent, 0, len(matches))
	for _, match := range matches {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       match.kind,
			EvidenceGrade:    match.grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: []string{match.evidence},
			Info: output.Info{
				Name:        match.name,
				Description: match.description,
				Severity:    match.severity,
				Confidence:  severity.Firm,
				Tags:        []string{"passive", "information-disclosure"},
			},
			Metadata: map[string]any{"status_code": ctx.Response().StatusCode(), "context_validated": match.kind == output.RecordKindCandidate},
		})
	}
	return results, nil
}

func firstPrivateIPv4(body string) string {
	for _, candidate := range privateIPv4Candidate.FindAllString(body, -1) {
		ip := net.ParseIP(candidate)
		if ip != nil && ip.To4() != nil && ip.IsPrivate() {
			return candidate
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
