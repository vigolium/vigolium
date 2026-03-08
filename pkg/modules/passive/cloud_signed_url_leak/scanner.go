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

	body := ctx.Response().BodyToString()
	if len(body) == 0 || len(body) > 2<<20 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	for _, sp := range signedURLPatterns {
		matches := sp.re.FindAllString(body, 10)
		for _, match := range matches {
			sigHash := utils.Sha1(match)
			dedupKey := fmt.Sprintf("%s|%s", urlx.Host, sigHash)
			if diskSet != nil && diskSet.IsSeen(dedupKey) {
				continue
			}

			sev := severity.Medium
			var evidence []string
			evidence = append(evidence, fmt.Sprintf("Type: %s", sp.urlType))
			evidence = append(evidence, fmt.Sprintf("URL: %s", truncateURL(match, 200)))

			// Parse risk factors
			if isWriteCapable(match, sp.urlType) {
				sev = severity.High
				evidence = append(evidence, "Risk: Write-capable token")
			}

			if isLongLived(match, sp.urlType) {
				sev = severity.High
				evidence = append(evidence, "Risk: Long-lived token (>24h)")
			}

			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     urlx.Host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: evidence,
				Info: output.Info{
					Name:        fmt.Sprintf("Signed URL Leak: %s", sp.urlType),
					Description: fmt.Sprintf("Response body contains a leaked %s with potential unauthorized access", sp.urlType),
					Severity:    sev,
					Confidence:  severity.Firm,
					Tags:        []string{"cloud-storage", "signed-url", "token-leak"},
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
		// AWS/GCS presigned URLs are typically scoped to a single method
		// Check if the URL path suggests a write operation
		upper := strings.ToUpper(signedURL)
		if strings.Contains(upper, "METHOD=PUT") || strings.Contains(upper, "METHOD=DELETE") {
			return true
		}
	}
	return false
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
