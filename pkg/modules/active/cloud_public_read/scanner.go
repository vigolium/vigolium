package cloud_public_read

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const minBodyLength = 50

var (
	sensitiveObjectNamePattern = regexp.MustCompile(`(?i)\b[[:alnum:]_./-]+\.(?:sql(?:\.gz)?|dump|bak|backup|env|pem|key|p12|log|csv|zip|tar|tgz|gz)\b`)
	genericObjectNamePattern   = regexp.MustCompile(`(?i)\b[[:alnum:]_./-]+\.[a-z0-9]{2,8}\b`)
	dotenvSecretPattern        = regexp.MustCompile(`(?mi)^(?:[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*[^\s"']{8,}`)
)

var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeHost, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("cloud_public_read"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil && ctx.Service() != nil && isCloudStorageHost(ctx.Service().Host())
}

func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Service() == nil || ctx.Request() == nil {
		return nil, nil
	}
	host := ctx.Service().Host()
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	cleanRaw, err := stripCredentials(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	cleanRaw, err = httpmsg.SetMethod(cleanRaw, "GET")
	if err != nil {
		return nil, nil
	}
	anonymousClient, cloneErr := httpClient.CloneWithoutCredentials()
	if cloneErr != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewRequestResponseRaw(cleanRaw, ctx.Service())

	var results []*output.ResultEvent
	for _, sensitivePath := range sensitivePaths {
		result, probeErr := m.probePath(anonymousCtx, anonymousClient, scanCtx, sensitivePath.path, sensitivePath.desc)
		if probeErr == nil && result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) probePath(ctx *httpmsg.HttpRequestResponse, client *http.Requester, scanCtx *modkit.ScanContext, path, desc string) (*output.ResultEvent, error) {
	modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), path)
	if err != nil {
		return nil, err
	}
	request := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())
	resp, _, err := client.Execute(request, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	if resp.Response() == nil || resp.Response().StatusCode < 200 || resp.Response().StatusCode >= 300 {
		return nil, nil
	}
	body := resp.Body().String()
	if len(body) < minBodyLength || isErrorResponse(body) {
		return nil, nil
	}

	// Cloud storage often returns branded 200 shells for every key. Require a
	// successful anonymous wildcard control and fail closed if it cannot be built.
	if scanCtx == nil {
		return nil, nil
	}
	wildcard, wildcardErr := scanCtx.WildcardProbe(ctx, client)
	if wildcardErr != nil || wildcard == nil || wildcard.MatchesBody(resp.Response().StatusCode, resp.Body().Bytes()) {
		return nil, nil
	}

	sensitiveContent := sensitiveContentEvidence(body)
	sensitiveNames := uniqueMatches(sensitiveObjectNamePattern, body, 8)
	listing := looksLikeObjectListing(body)
	if len(sensitiveContent) == 0 && (!listing || len(sensitiveNames) == 0) {
		if !listing {
			return nil, nil
		}
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "Anonymous Cloud Object Listing Observed: " + desc
	description := fmt.Sprintf("An isolated credential-free client can enumerate objects under %s. Public listings may be intentional; no sensitive object content was confirmed.", path)
	extracted := []string{fmt.Sprintf("path=%s status=%d body_length=%d", path, resp.Response().StatusCode, len(body))}
	if len(sensitiveNames) > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeDifferential
		sev = severity.Medium
		name = "Anonymous Sensitive-Object Listing Candidate: " + desc
		description = fmt.Sprintf("An isolated credential-free client can enumerate %d sensitive-looking object name(s) under %s. Fetch and inspect the objects before treating names alone as a data leak.", len(sensitiveNames), path)
		extracted = append(extracted, sensitiveNames...)
	}
	if len(sensitiveContent) > 0 {
		kind = output.RecordKindFinding
		grade = output.EvidenceGradeImpact
		sev = ModuleSeverity
		name = "Anonymous Sensitive Cloud Content Exposed: " + desc
		description = fmt.Sprintf("An isolated credential-free client received content at %s containing independent sensitive-data anchors: %s.", path, strings.Join(sensitiveContent, ", "))
		extracted = append(extracted, sensitiveContent...)
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       kind,
		EvidenceGrade:    grade,
		Host:             ctx.Service().Host(),
		URL:              ctx.Target(),
		Matched:          ctx.Target(),
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
		Metadata: map[string]any{
			"anonymous_client":          true,
			"object_listing":            listing,
			"sensitive_object_names":    len(sensitiveNames),
			"sensitive_content_anchors": len(sensitiveContent),
		},
	}, nil
}

func stripCredentials(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, header := range credentialHeaders {
		clean, err = httpmsg.RemoveHeader(clean, header)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func looksLikeObjectListing(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{"<listbucketresult", "<enumerationresults", "<contents>", "<blobs>", "<title>index of", "\"items\":"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Contains(lower, "<pre") && len(genericObjectNamePattern.FindAllString(body, 3)) >= 2
}

func sensitiveContentEvidence(body string) []string {
	lower := strings.ToLower(body)
	var evidence []string
	if strings.Contains(body, "-----BEGIN") && strings.Contains(body, "PRIVATE KEY-----") {
		evidence = append(evidence, "private-key material")
	}
	if dotenvSecretPattern.MatchString(body) {
		evidence = append(evidence, "dotenv credential assignment")
	}
	if (strings.Contains(lower, "-- mysql dump") || strings.Contains(lower, "-- postgresql database dump")) &&
		(strings.Contains(lower, "create table") || strings.Contains(lower, "insert into")) {
		evidence = append(evidence, "database dump structure")
	}
	return evidence
}

func uniqueMatches(pattern *regexp.Regexp, body string, limit int) []string {
	seen := make(map[string]bool)
	var results []string
	for _, match := range pattern.FindAllString(body, limit*2) {
		key := strings.ToLower(match)
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, match)
		if len(results) == limit {
			break
		}
	}
	return results
}
