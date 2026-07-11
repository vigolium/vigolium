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
	// Every accepted pattern is explicitly Next.js-qualified. A generic
	// {"version":"x.y.z"} in an application response is usually the product/API
	// version and must never be attributed to the framework.
	versionAssignRe   = regexp.MustCompile(`\bNEXT_VERSION\s*(?:=|:)\s*["'](\d+\.\d+\.\d+)["']`)
	versionCommentRe  = regexp.MustCompile(`/\*\!?\s*(?:next|Next\.js)\s+v?(\d+\.\d+\.\d+)`)
	nextVersionJSONRe = regexp.MustCompile(`"(?:nextVersion|next_version)"\s*:\s*"(\d+\.\d+\.\d+)"`)
)

type versionEvidence struct {
	version string
	source  string
}

// Module implements the Next.js version audit active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

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
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}
	if diskSet := m.ds.Get(scanCtx.DedupMgr()); diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	evidence := extractVersionEvidence(ctx.Response().BodyToString(), "observed response")
	if evidence.version == "" {
		evidence = m.probeForVersion(ctx, httpClient)
	}
	if evidence.version == "" {
		return nil, nil
	}

	var results []*output.ResultEvent
	target := ctx.Target()
	for _, adv := range knownAdvisories {
		matchedRange, affected := advisoryAffectsVersion(evidence.version, adv)
		if !affected {
			continue
		}

		kind := output.RecordKindFinding
		grade := output.EvidenceGradeCandidate
		confidence := severity.Firm
		description := fmt.Sprintf(
			"Next.js %s falls in the reviewed affected interval %s for %s: %s.",
			evidence.version, formatVersionRange(matchedRange), adv.cve, adv.description,
		)
		if len(adv.prerequisites) > 0 {
			kind = output.RecordKindCandidate
			confidence = severity.Tentative
			description += " Exploitability additionally requires: " + strings.Join(adv.prerequisites, "; ") + "."
		}

		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			Host:          host,
			URL:           target,
			Matched:       target,
			RecordKind:    kind,
			EvidenceGrade: grade,
			ExtractedResults: []string{
				fmt.Sprintf("Detected version: Next.js %s", evidence.version),
				fmt.Sprintf("Version evidence: %s", evidence.source),
				fmt.Sprintf("Advisory: %s - %s", adv.cve, adv.title),
				fmt.Sprintf("Matched affected interval: %s", formatVersionRange(matchedRange)),
				fmt.Sprintf("Patched boundary for this branch: %s", matchedRange.fixed),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Next.js %s (%s)", adv.cve, adv.title),
				Description: description,
				Severity:    adv.severity,
				Confidence:  confidence,
				Tags:        []string{"nextjs", "outdated", "cve", "version-audit"},
				Reference:   []string{adv.reference},
			},
			Metadata: map[string]any{
				"cve":              adv.cve,
				"detected_version": evidence.version,
				"version_source":   evidence.source,
				"fixed_version":    matchedRange.fixed,
				"prerequisites":    adv.prerequisites,
			},
		})
	}
	return results, nil
}

func (m *Module) probeForVersion(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) versionEvidence {
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
		probeRaw, err = httpmsg.SetMethod(probeRaw, "GET")
		if err != nil {
			continue
		}
		probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())
		resp, _, err := httpClient.Execute(probeReq, http.Options{NoRedirects: true, NoClustering: true})
		if err != nil {
			continue
		}
		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := resp.Body().String()
			contentType := resp.Response().Header.Get("Content-Type")
			if looksLikeJavaScriptResponse(contentType, body) {
				if v := extractVersion(body); v != "" {
					resp.Close()
					return versionEvidence{version: v, source: path}
				}
			}
		}
		resp.Close()
	}
	return versionEvidence{}
}

func extractVersion(body string) string {
	return extractVersionEvidence(body, "content").version
}

func extractVersionEvidence(body, source string) versionEvidence {
	for _, re := range []*regexp.Regexp{versionAssignRe, versionCommentRe, nextVersionJSONRe} {
		if match := re.FindStringSubmatch(body); len(match) > 1 {
			return versionEvidence{version: match[1], source: source}
		}
	}
	return versionEvidence{}
}

func advisoryAffectsVersion(version string, adv advisory) (versionRange, bool) {
	for _, affected := range adv.affectedRanges {
		if isVersionAffected(version, affected.introduced, affected.fixed) {
			return affected, true
		}
	}
	return versionRange{}, false
}

func isVersionAffected(version, introduced, fixed string) bool {
	v := parseVersion(version)
	a := parseVersion(introduced)
	b := parseVersion(fixed)
	if v == nil || a == nil || b == nil {
		return false
	}
	return compareVersions(v, a) >= 0 && compareVersions(v, b) < 0
}

func formatVersionRange(r versionRange) string {
	return fmt.Sprintf(">= %s, < %s", r.introduced, r.fixed)
}

func looksLikeJavaScriptResponse(contentType, body string) bool {
	lowerCT := strings.ToLower(contentType)
	if strings.Contains(lowerCT, "javascript") || strings.Contains(lowerCT, "ecmascript") {
		return true
	}
	lowerBody := strings.ToLower(strings.TrimSpace(body))
	return !strings.HasPrefix(lowerBody, "<!doctype html") &&
		!strings.HasPrefix(lowerBody, "<html") &&
		(versionAssignRe.MatchString(body) || versionCommentRe.MatchString(body) || nextVersionJSONRe.MatchString(body))
}

type semver struct {
	major, minor, patch int
}

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
	return &semver{major: major, minor: minor, patch: patch}
}

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
