package remix_loader_exposure

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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var findings []string
	// The mere presence of a Remix header or a state blob is
	// NOT a leak: every Remix page ships window.__remixContext / "loaderData",
	// so triggering on their presence reported Medium/Firm on every Remix site with
	// zero sensitive data. Those presence lines are kept only as supporting
	// evidence, surfaced once a security-relevant state signal exists.
	var signals []stateexposure.Hit
	candidateCount := 0

	// Remix response headers — context evidence only, never a trigger.
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

		// Blob presence — context evidence only, never a trigger.
		findings = append(findings, fmt.Sprintf("Remix state blob detected: %s", blob.name))

		for _, signal := range stateexposure.Analyze(stateData) {
			findings = append(findings, fmt.Sprintf("[%s] %s: %s", blob.name, signal.Category, signal.Evidence))
			signals = append(signals, signal)
			if signal.Candidate {
				candidateCount++
			}
		}
	}

	// A result requires at least one security-relevant state signal; presence alone
	// (header or state blob) is normal for any Remix app and not reportable.
	if len(signals) == 0 {
		return nil, nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	conf := severity.Tentative
	name := "Remix Loader Security Signals"
	description := "Remix loader state contains identity, role, public-identifier, or infrastructure context. These are observations unless authorization or secret validity is established."
	if candidateCount > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = ModuleSeverity
		conf = ModuleConfidence
		name = "Potential Remix Loader Data Exposure"
		description = fmt.Sprintf("Remix loader state contains %d substantive private credential or password-bearing service URL candidate(s). Credential validity, anonymous reachability, and cross-user authorization were not tested.", candidateCount)
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
				Tags:        []string{"remix", "data-exposure", "information-disclosure"},
				Reference:   []string{"https://remix.run/docs/en/main/route/loader"},
			},
			Metadata: map[string]any{
				"signalCount":           len(signals),
				"candidateCount":        candidateCount,
				"signals":               signals,
				"credentialValidated":   false,
				"authorizationCompared": false,
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
