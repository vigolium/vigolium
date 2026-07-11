package cloud_signed_url_leak

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("passive_cloud_signed_url_leak"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}
	// A WAF/CDN edge block is the edge talking, not the application — a signed URL
	// in such a page is not the app leaking one.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 || len(body) > 2<<20 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}

	var results []*output.ResultEvent

	for _, sp := range signedURLPatterns {
		matches := sp.re.FindAllString(body, 10)
		for _, match := range matches {
			sigHash := utils.Sha1(match)
			dedupKey := fmt.Sprintf("%s|%s", urlx.Host, sigHash)
			if diskSet != nil && diskSet.IsSeen(dedupKey) {
				continue
			}

			kind := output.RecordKindObservation
			grade := output.EvidenceGradeObservation
			sev := severity.Info
			conf := severity.Tentative
			var evidence []string
			var riskFactors []string
			evidence = append(evidence, fmt.Sprintf("Type: %s", sp.urlType))
			evidence = append(evidence, fmt.Sprintf("URL (signature redacted): %s", truncateURL(redactSignedURL(match), 200)))

			// Parse risk factors
			if isWriteCapable(match, sp.urlType) {
				riskFactors = append(riskFactors, "provider-declared write permission")
			}

			if isLongLived(match, sp.urlType) {
				riskFactors = append(riskFactors, "declared lifetime exceeds 24 hours")
			}

			if isExplicitlySharedCacheable(ctx.Response()) {
				riskFactors = append(riskFactors, "response is explicitly shared-cacheable")
			}

			name := fmt.Sprintf("Signed URL Observed: %s", sp.urlType)
			description := fmt.Sprintf("The response contains a %s. Signed URLs are commonly an intentional download/upload capability; recipient authorization and replay impact were not tested.", sp.urlType)
			if len(riskFactors) > 0 {
				kind = output.RecordKindCandidate
				grade = output.EvidenceGradeCandidate
				sev = severity.Medium
				conf = severity.Firm
				name = fmt.Sprintf("Risky Signed URL Exposure Candidate: %s", sp.urlType)
				description = fmt.Sprintf("The response contains a %s with risk-enhancing context (%s). The capability was not replayed and unauthorized access was not established.", sp.urlType, strings.Join(riskFactors, "; "))
				for _, risk := range riskFactors {
					evidence = append(evidence, "Risk context: "+risk)
				}
			}

			results = append(results, &output.ResultEvent{
				ModuleID:         ModuleID,
				RecordKind:       kind,
				EvidenceGrade:    grade,
				Host:             urlx.Host,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(ctx.Request().Raw()),
				Response:         string(ctx.Response().Raw()),
				ExtractedResults: evidence,
				Info: output.Info{
					Name:        name,
					Description: description,
					Severity:    sev,
					Confidence:  conf,
					Tags:        []string{"cloud-storage", "signed-url", "token-leak"},
				},
				Metadata: map[string]any{
					"url_type":                   sp.urlType,
					"risk_factors":               riskFactors,
					"capability_replayed":        false,
					"authorization_compared":     false,
					"signature_extracted_safely": true,
				},
			})
		}
	}

	return results, nil
}

func isWriteCapable(signedURL string, urlType signedURLType) bool {
	switch urlType {
	case typeAzureSAS:
		if m := azurePermsRe.FindStringSubmatch(signedURL); len(m) > 1 {
			perms := m[1]
			for _, wp := range writePermissions[typeAzureSAS] {
				if strings.Contains(perms, wp) {
					return true
				}
			}
		}
	case typeAWSPresigned, typeGCSSigned:
		// The HTTP method is part of the provider's canonical request, not a
		// trustworthy URL query attribute. Passive URL inspection cannot infer it.
		return false
	}
	return false
}

func isExplicitlySharedCacheable(response *httpmsg.HttpResponse) bool {
	if response == nil {
		return false
	}
	cacheControl := strings.ToLower(response.Header("Cache-Control"))
	if strings.Contains(cacheControl, "public") || strings.Contains(cacheControl, "s-maxage=") {
		return true
	}
	surrogateControl := strings.ToLower(response.Header("Surrogate-Control"))
	return strings.Contains(surrogateControl, "max-age=")
}

func redactSignedURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<signed URL redacted>"
	}
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "signature") || lower == "sig" || strings.Contains(lower, "token") {
			query.Set(key, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func isLongLived(signedURL string, urlType signedURLType) bool {
	const daySeconds = 86400

	switch urlType {
	case typeAWSPresigned:
		if m := awsExpiresRe.FindStringSubmatch(signedURL); len(m) > 1 {
			if expires, err := strconv.Atoi(m[1]); err == nil {
				return expires > daySeconds
			}
		}
	case typeGCSSigned:
		if m := gcsExpiresRe.FindStringSubmatch(signedURL); len(m) > 1 {
			if expires, err := strconv.Atoi(m[1]); err == nil {
				return expires > daySeconds
			}
		}
	case typeAzureSAS:
		if m := azureExpiryRe.FindStringSubmatch(signedURL); len(m) > 1 {
			decoded, err := url.QueryUnescape(m[1])
			if err != nil {
				return false
			}
			// Azure SAS expiry is ISO 8601
			expiry, err := time.Parse("2006-01-02T15:04:05Z", decoded)
			if err != nil {
				expiry, err = time.Parse("2006-01-02", decoded)
			}
			if err == nil {
				return time.Until(expiry) > 24*time.Hour
			}
		}
	}
	return false
}

func truncateURL(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
