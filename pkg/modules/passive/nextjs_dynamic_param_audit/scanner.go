package nextjs_dynamic_param_audit

import (
	"fmt"
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

// paramIssue tracks a detected unsafe parameter usage.
type paramIssue struct {
	name     string
	desc     string
	severity severity.Severity
}

var (
	// Pattern 1: params used directly in DB queries (SQL injection / NoSQL injection risk)
	paramsDBComboRe = regexp.MustCompile(`(?:findUnique|findFirst|findMany|where|query|execute|raw)\s*\([^)]*params\.`)

	// Pattern 2: searchParams used in auth decisions
	searchParamsAuthRe = regexp.MustCompile(`searchParams\.(?:get\s*\(\s*['"](?:admin|isAdmin|role|permission|auth|token|access)['"]|(?:admin|isAdmin|role|permission|auth|token|access)\b)`)

	// Pattern 3: params used directly in SQL template literals
	paramsSQLRe = regexp.MustCompile("(?:`[^`]*\\$\\{\\s*params\\.\\w+\\s*\\}[^`]*`|'[^']*'\\s*\\+\\s*params\\.\\w+)")

	// Pattern 4: searchParams used directly in redirects/URLs without validation
	searchParamsRedirectRe = regexp.MustCompile(`(?:redirect|NextResponse\.redirect)\s*\([^)]*searchParams\.(?:get\s*\(\s*['"](?:next|returnTo|redirect|callbackUrl|url|goto|destination|forward)['"]|(?:next|returnTo|redirect|callbackUrl|url|goto|destination|forward)\b)`)

	// Validation patterns that mitigate the risk
	validationRe = regexp.MustCompile(`z\.(?:parse|safeParse|string|number|coerce)|parseInt\s*\(|Number\s*\(|\.validate\s*\(|isNaN\s*\(|typeof\s+params|schema\.parse|UUID\.parse`)
)

// Module implements the dynamic param audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Dynamic Param Audit module.
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
		ds: dedup.LazyDiskSet("nextjs_dynamic_param_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS/TS content types or URL paths ending in JS/TS extensions.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	if modkit.IsJSOrTSContentType(ctx.Response().Header("Content-Type")) {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		if modkit.HasJSExtension(strings.ToLower(u.Path)) {
			return true
		}
	}

	return false
}

// ScanPerRequest scans for unsafe dynamic param usage.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
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

	// Must reference params or searchParams
	if !strings.Contains(body, "params.") && !strings.Contains(body, "searchParams") {
		return nil, nil
	}

	// If validation is present, skip
	if validationRe.MatchString(body) {
		return nil, nil
	}

	var issues []paramIssue

	// Pattern 1: params directly in DB queries
	if paramsDBComboRe.MatchString(body) {
		issues = append(issues, paramIssue{
			name:     "Dynamic Params in DB Query",
			desc:     "Dynamic route params passed directly to database query without validation or type coercion",
			severity: severity.Medium,
		})
	}

	// Pattern 2: searchParams in auth decisions
	if matches := searchParamsAuthRe.FindAllString(body, 5); len(matches) > 0 {
		issues = append(issues, paramIssue{
			name:     "SearchParams in Auth Decision",
			desc:     "URL search parameters used in authorization decisions, allowing client-controlled privilege escalation",
			severity: severity.High,
		})
	}

	// Pattern 3: params in SQL template literals
	if paramsSQLRe.MatchString(body) {
		issues = append(issues, paramIssue{
			name:     "Params in SQL Interpolation",
			desc:     "Dynamic route params interpolated into SQL strings via template literals or concatenation",
			severity: severity.High,
		})
	}

	// Pattern 4: searchParams in redirects (open redirect risk)
	if searchParamsRedirectRe.MatchString(body) {
		issues = append(issues, paramIssue{
			name:     "SearchParams in Redirect",
			desc:     "URL search parameters used in redirect targets without validation, risking open redirect",
			severity: severity.Medium,
		})
	}

	if len(issues) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, issue := range issues {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Issue: %s", issue.name),
				issue.desc,
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Dynamic Param: %s", issue.name),
				Description: fmt.Sprintf("%s at %s", issue.desc, urlx.Path),
				Severity:    issue.severity,
				Confidence:  severity.Tentative,
				Tags:        []string{"input-validation", "dynamic-routes", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/20.html"},
			},
			Metadata: map[string]any{
				"cwe":     "CWE-20",
				"pattern": issue.name,
			},
		})
	}

	return results, nil
}
