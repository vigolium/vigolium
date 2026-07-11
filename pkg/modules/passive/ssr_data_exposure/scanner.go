package ssr_data_exposure

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/stateexposure"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	// Extract SSR state blobs
	var findings []string
	var signals []stateexposure.Hit
	candidateCount := 0
	for _, blob := range stateBlobs {
		stateData := extractState(body, blob)
		if stateData == "" {
			continue
		}

		for _, signal := range stateexposure.Analyze(stateData) {
			findings = append(findings, fmt.Sprintf("[%s] %s: %s", blob.name, signal.Category, signal.Evidence))
			signals = append(signals, signal)
			if signal.Candidate {
				candidateCount++
			}
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	conf := severity.Tentative
	name := "SSR State Security Signals"
	description := fmt.Sprintf("Found %d security-relevant client-state signal(s). Identity data, role flags, public identifiers, and internal addresses are observations rather than vulnerability proof.", len(findings))
	if candidateCount > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = ModuleSeverity
		conf = ModuleConfidence
		name = "Potential SSR Sensitive Data Exposure"
		description = fmt.Sprintf("Found %d substantive private credential or password-bearing service URL candidate(s) in serialized state. Credential validity, anonymous reachability, and cross-user authorization were not tested.", candidateCount)
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: findings,
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"ssr", "data-exposure", "information-disclosure"},
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
			Metadata: map[string]any{
				"signalCount":           len(findings),
				"candidateCount":        candidateCount,
				"signals":               signals,
				"credentialValidated":   false,
				"authorizationCompared": false,
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
