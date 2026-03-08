package nextjs_version_audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// versionPatterns extracts Next.js version from JS bundles.
	versionInBundleRe = regexp.MustCompile(`Next\.js\s+v?(\d+\.\d+\.\d+)`)
	versionAssignRe   = regexp.MustCompile(`NEXT_VERSION\s*(?:=|:)\s*["'](\d+\.\d+\.\d+)["']`)
	versionCommentRe  = regexp.MustCompile(`/\*\!?\s*next\s+v?(\d+\.\d+\.\d+)`)
	// Matches version in _buildManifest or _ssgManifest patterns
	versionInManifestRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)"`)
)

// Module implements the Next.js version audit active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Version Audit module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("nextjs_version_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerHost fingerprints Next.js version once per host and checks advisories.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Check if this is a Next.js host
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Try to extract version from the current response body first
	version := extractVersion(ctx.Response().BodyToString())

	// If not found, try fetching known JS bundle paths
	if version == "" {
		version = m.probeForVersion(ctx, httpClient)
	}

	if version == "" {
		return nil, nil
	}

	// Check version against known advisories
	var results []*output.ResultEvent
	target := ctx.Target()

	for _, adv := range knownAdvisories {
		if isVersionAffected(version, adv.affectedAbove, adv.affectedBelow) {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      target,
				Matched:  target,
				ExtractedResults: []string{
					fmt.Sprintf("Detected version: Next.js %s", version),
					fmt.Sprintf("Advisory: %s - %s", adv.cve, adv.title),
					fmt.Sprintf("Affected: >= %s, < %s", adv.affectedAbove, adv.affectedBelow),
					fmt.Sprintf("Fix: Upgrade to Next.js %s or later", adv.affectedBelow),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("Next.js %s (%s)", adv.cve, adv.title),
					Description: fmt.Sprintf("Next.js %s is affected by %s: %s. Upgrade to %s or later.", version, adv.cve, adv.description, adv.affectedBelow),
					Severity:    adv.severity,
					Confidence:  severity.Firm,
					Tags:        []string{"nextjs", "outdated", "cve", "version-audit"},
					Reference:   []string{adv.reference},
				},
				Metadata: map[string]any{
					"cve":              adv.cve,
					"detected_version": version,
					"fixed_version":    adv.affectedBelow,
				},
			})
		}
	}

	return results, nil
}

// probeForVersion fetches common Next.js bundle paths to extract version info.
func (m *Module) probeForVersion(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	buildID := jsframework.GetBuildID(ctx.Service().Host())

	probePaths := []string{
		"/_next/static/chunks/main.js",
		"/_next/static/chunks/framework.js",
		"/_next/static/chunks/webpack.js",
	}

	if buildID != "" {
		probePaths = append(probePaths,
			fmt.Sprintf("/_next/static/%s/_buildManifest.js", buildID),
			fmt.Sprintf("/_next/static/%s/_ssgManifest.js", buildID),
		)
	}

	for _, path := range probePaths {
		probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), path)
		if err != nil {
			continue
		}
		probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

		probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
		if err != nil {
			continue
		}
		probeReq = probeReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(probeReq, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := resp.Body().String()
			if v := extractVersion(body); v != "" {
				resp.Close()
				return v
			}
		}
		resp.Close()
	}

	return ""
}

// extractVersion tries multiple patterns to extract Next.js version from content.
func extractVersion(body string) string {
	for _, re := range []*regexp.Regexp{versionInBundleRe, versionAssignRe, versionCommentRe, versionInManifestRe} {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// isVersionAffected checks if a version falls within the affected range.
// Returns true if version >= affectedAbove AND version < affectedBelow.
func isVersionAffected(version, above, below string) bool {
	v := parseVersion(version)
	a := parseVersion(above)
	b := parseVersion(below)

	if v == nil || a == nil || b == nil {
		return false
	}

	return compareVersions(v, a) >= 0 && compareVersions(v, b) < 0
}

// semver holds parsed version components.
type semver struct {
	major, minor, patch int
}

// parseVersion parses a "major.minor.patch" version string.
func parseVersion(s string) *semver {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}
	return &semver{major, minor, patch}
}

// compareVersions returns -1, 0, or 1.
func compareVersions(a, b *semver) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}
