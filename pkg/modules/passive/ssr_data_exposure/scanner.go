package ssr_data_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// Module implements the SSR data exposure passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new SSR Data Exposure module.
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
		ds: dedup.LazyDiskSet("ssr_data_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans SSR state blobs for sensitive data.
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

	// Extract SSR state blobs
	var findings []string
	for _, blob := range stateBlobs {
		stateData := extractState(body, blob)
		if stateData == "" {
			continue
		}

		// Scan for sensitive patterns
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
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: findings,
			Info: output.Info{
				Name:        "SSR Data Exposure",
				Description: fmt.Sprintf("Found %d sensitive data pattern(s) in server-side rendered state at %s", len(findings), urlx.Path),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"ssr", "data-exposure", "information-disclosure"},
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
			Metadata: map[string]any{
				"findingCount": len(findings),
			},
		},
	}, nil
}

// extractState extracts the state data from a blob definition.
func extractState(body string, blob ssrStateBlob) string {
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

