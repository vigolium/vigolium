package cache_data_leak

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

var (
	// Pattern 1: getStaticProps with auth-scoped data
	getStaticPropsRe = regexp.MustCompile(`getStaticProps`)
	staticAuthRe     = regexp.MustCompile(`session|cookies|getSession|auth\(\)|getToken|Authorization`)

	// Pattern 2: force-static with auth imports
	forceStaticRe     = regexp.MustCompile(`dynamic\s*=\s*['"]force-static['"]`)
	forceStaticAuthRe = regexp.MustCompile(`getSession|auth|currentUser`)

	// Pattern 3: unstable_cache without user key
	unstableCacheRe  = regexp.MustCompile(`unstable_cache\s*\(`)
	cacheUserKeyRe   = regexp.MustCompile(`userId|sessionId|user`)
	cacheAuthBodyRe  = regexp.MustCompile(`session|cookies|auth`)

	// Pattern 4: Server fetch without no-store
	fetchWithAuthRe      = regexp.MustCompile(`fetch\s*\([\s\S]{0,200}?(?:Authorization|cookies\(\)|headers\(\))`)
	noStoreRe            = regexp.MustCompile(`cache\s*:\s*['"]no-store['"]`)
	revalidateZeroRe     = regexp.MustCompile(`revalidate\s*:\s*0`)
)

// cacheIssue represents a single detected caching issue.
type cacheIssue struct {
	name     string
	desc     string
	severity severity.Severity
}

// Module implements the cache data leak passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Cache Data Leak module.
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
		ds: dedup.LazyDiskSet("cache_data_leak"),
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

// ScanPerRequest scans for caching patterns that may leak user data.
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

	var issues []cacheIssue

	// Pattern 1: getStaticProps combined with auth patterns
	if getStaticPropsRe.MatchString(body) && staticAuthRe.MatchString(body) {
		issues = append(issues, cacheIssue{
			name:     "Static Generation with Auth Data",
			desc:     "getStaticProps fetches authentication-scoped data; static pages are shared across all users",
			severity: severity.High,
		})
	}

	// Pattern 2: force-static page with auth imports
	if forceStaticRe.MatchString(body) && forceStaticAuthRe.MatchString(body) {
		issues = append(issues, cacheIssue{
			name:     "Force-Static Page with Auth",
			desc:     "Page is forced to static rendering (dynamic = 'force-static') but imports authentication utilities",
			severity: severity.High,
		})
	}

	// Pattern 3: unstable_cache without user-scoped key
	if loc := unstableCacheRe.FindStringIndex(body); loc != nil {
		// Check a window after the unstable_cache call for key patterns
		end := loc[1] + 200
		if end > len(body) {
			end = len(body)
		}
		cacheContext := body[loc[0]:end]

		hasUserKey := cacheUserKeyRe.MatchString(cacheContext)
		hasAuthBody := cacheAuthBodyRe.MatchString(body)

		if !hasUserKey && hasAuthBody {
			issues = append(issues, cacheIssue{
				name:     "Cache Without User-Scoped Key",
				desc:     "unstable_cache is used without userId/sessionId in the cache key, but the function accesses auth-scoped data",
				severity: severity.Medium,
			})
		}
	}

	// Pattern 4: Server fetch with auth but without no-store
	// Only applies to server components (no "use client" directive)
	if !jsframework.UseClientDirectiveRe.MatchString(body) && fetchWithAuthRe.MatchString(body) {
		if !noStoreRe.MatchString(body) && !revalidateZeroRe.MatchString(body) {
			issues = append(issues, cacheIssue{
				name:     "Server Fetch Without no-store",
				desc:     "Server component fetches data with auth headers/cookies but does not set cache: 'no-store' or revalidate: 0",
				severity: severity.Medium,
			})
		}
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
				Name:        fmt.Sprintf("Cache Data Leak: %s", issue.name),
				Description: fmt.Sprintf("%s at %s", issue.desc, urlx.Path),
				Severity:    issue.severity,
				Confidence:  severity.Tentative,
				Tags:        []string{"caching", "information-disclosure", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/524.html"},
			},
			Metadata: map[string]any{
				"cwe":     "CWE-524",
				"pattern": issue.name,
			},
		})
	}

	return results, nil
}
