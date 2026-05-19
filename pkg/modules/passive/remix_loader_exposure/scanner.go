package remix_loader_exposure

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

// remixStateBlob defines where to find Remix state data in HTML.
type remixStateBlob struct {
	name  string
	start string
	end   string
}

var remixStateBlobs = []remixStateBlob{
	{
		name:  "__remixContext",
		start: `window.__remixContext=`,
		end:   `;</script>`,
	},
	{
		name:  "__remixManifest",
		start: `window.__remixManifest=`,
		end:   `;</script>`,
	},
	{
		name:  "remix-loader-data",
		start: `"loaderData":`,
		end:   `,"actionData"`,
	},
}

// sensitivePattern defines a pattern to detect in Remix state data.
type sensitivePattern struct {
	name    string
	pattern *regexp.Regexp
	desc    string
}

var sensitivePatterns = []sensitivePattern{
	{
		name:    "API Key/Token",
		pattern: regexp.MustCompile(`"(?:api_?key|api_?token|access_?token|secret_?key|auth_?token)"\s*:\s*"([^"]{16,})"`),
		desc:    "API key or token found in Remix loader data",
	},
	{
		name:    "Admin Flag",
		pattern: regexp.MustCompile(`"(?:is_?[Aa]dmin|is_?[Ss]uperuser|is_?[Ss]taff|admin|role)"\s*:\s*(?:true|"admin"|"superuser")`),
		desc:    "Admin/privilege flag found in Remix loader data",
	},
	{
		name:    "Email Address",
		pattern: regexp.MustCompile(`"(?:email|mail|user_?email)"\s*:\s*"([^"]+@[^"]+\.[^"]+)"`),
		desc:    "Email address found in Remix loader data",
	},
	{
		name:    "Password Hash",
		pattern: regexp.MustCompile(`"(?:password|passwd|password_?hash|hashed_?password)"\s*:\s*"(\$2[aby]\$|pbkdf2|scrypt|argon2|sha256|sha512)[^"]*"`),
		desc:    "Password hash found in Remix loader data",
	},
	{
		name:    "Private IP",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^"]*)?"`),
		desc:    "Private/internal IP address found in Remix loader data",
	},
	{
		name:    "Database URL",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^"]+"`),
		desc:    "Database connection string found in Remix loader data",
	},
	{
		name:    "AWS Key",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"AKIA[0-9A-Z]{16}"`),
		desc:    "AWS access key found in Remix loader data",
	},
}

// knownPlaceholders are values to skip as likely non-sensitive (pre-lowercased).
var knownPlaceholders = []string{
	"undefined", "null", "true", "false",
	"change_me", "your_api_key", "xxx",
	"placeholder", "example",
}

// remixHeaderNames are response headers that indicate a Remix application.
var remixHeaderNames = []string{
	"X-Remix-Response",
	"X-Remix-Revalidate",
}

// Module implements the Remix loader exposure passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Remix Loader Exposure module.
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
		ds: dedup.LazyDiskSet("remix_loader_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans for sensitive data in Remix loader data and context.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	// Only process HTML responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var findings []string

	// Check for Remix response headers
	for _, headerName := range remixHeaderNames {
		headerVal := ctx.Response().Header(headerName)
		if headerVal != "" {
			findings = append(findings, fmt.Sprintf("Remix header detected: %s: %s", headerName, modkit.Truncate(headerVal, 120)))
		}
	}

	// Extract Remix state blobs and scan for sensitive data
	for _, blob := range remixStateBlobs {
		stateData := extractState(body, blob)
		if stateData == "" {
			continue
		}

		findings = append(findings, fmt.Sprintf("Remix state blob detected: %s", blob.name))

		for _, sp := range sensitivePatterns {
			matches := sp.pattern.FindAllString(stateData, 3)
			for _, match := range matches {
				if isPlaceholder(match) {
					continue
				}
				findings = append(findings, fmt.Sprintf("[%s] %s: %s", blob.name, sp.name, modkit.Truncate(match, 120)))
			}
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: findings,
			Info: output.Info{
				Name:        "Remix Loader Data Exposure",
				Description: fmt.Sprintf("Found %d Remix-related finding(s) at %s", len(findings), urlx.Path),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"remix", "data-exposure", "information-disclosure"},
				Reference:   []string{"https://remix.run/docs/en/main/route/loader"},
			},
			Metadata: map[string]any{
				"findingCount": len(findings),
			},
		},
	}, nil
}

// extractState extracts the state data from a blob definition.
func extractState(body string, blob remixStateBlob) string {
	idx := strings.Index(body, blob.start)
	if idx == -1 {
		return ""
	}
	start := idx + len(blob.start)
	remaining := body[start:]

	endIdx := strings.Index(remaining, blob.end)
	if endIdx == -1 {
		// Limit extraction to avoid processing huge chunks
		if len(remaining) > 50000 {
			remaining = remaining[:50000]
		}
		return remaining
	}

	return remaining[:endIdx]
}

// isPlaceholder checks if a matched value is a known placeholder.
func isPlaceholder(match string) bool {
	matchLower := strings.ToLower(match)
	for _, ph := range knownPlaceholders {
		if strings.Contains(matchLower, ph) {
			return true
		}
	}
	return false
}
