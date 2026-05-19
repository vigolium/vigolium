package lfi_path_traversal

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const minBodyDelta = 50  // minimum body length increase to consider a hit
const minMarkerCount = 2 // minimum markers that must match

// Module implements the LFI Path Traversal active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new LFI Path Traversal module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("lfi_path_traversal"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for advanced LFI path traversal.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Pre-filter: only test file-like parameters
	if !matchFileParams(ip.Name()) && !looksLikeFilePath(ip.BaseValue()) {
		return nil, nil
	}

	// Get baseline body for false-positive suppression
	var baselineBody string
	var baselineLen int
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineLen = len(baselineBody)
		baselineStatus = ctx.Response().StatusCode()
	}

	statusChanged := false

	// Tier 1: core traversal payloads
	for _, p := range tier1Payloads {
		result, sc, err := m.testPayload(ctx, ip, httpClient, p, baselineBody, baselineLen, baselineStatus)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		if sc {
			statusChanged = true
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	// Tier 2: only if tier 1 caused status code change (traversal may work, different file needed)
	if statusChanged {
		for _, p := range tier2CanaryFiles {
			result, _, err := m.testPayload(ctx, ip, httpClient, p, baselineBody, baselineLen, baselineStatus)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return nil, nil
				}
				continue
			}
			if result != nil {
				return []*output.ResultEvent{result}, nil
			}
		}
	}

	return nil, nil
}

// testPayload sends a single LFI payload and checks for marker matches.
// Returns (result, statusChanged, error).
func (m *Module) testPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	p lfiPayload,
	baselineBody string,
	baselineLen int,
	baselineStatus int,
) (*output.ResultEvent, bool, error) {
	fuzzedRaw := ip.BuildRequest([]byte(p.payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, false, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, false, err
	}
	defer resp.Close()

	body := resp.Body().String()
	respStatus := 0
	if resp.Response() != nil {
		respStatus = resp.Response().StatusCode
	}

	statusChanged := respStatus != baselineStatus && baselineStatus != 0

	// Body length delta check
	if len(body)-baselineLen < minBodyDelta {
		return nil, statusChanged, nil
	}

	// Marker matching with baseline subtraction
	matchCount := countNewMarkers(body, baselineBody, p.markers)
	if matchCount < minMarkerCount {
		return nil, statusChanged, nil
	}

	urlx, _ := ctx.URL()
	conf := severity.Firm
	if matchCount >= 3 {
		conf = severity.Certain
	}

	return &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(fuzzedRaw),
		Response:         resp.FullResponse().String(),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{p.payload},
		Info: output.Info{
			Name:        "LFI Path Traversal",
			Description: fmt.Sprintf("Local file inclusion detected via parameter %q with payload: %s (%d markers matched)", ip.Name(), p.payload, matchCount),
			Severity:    severity.High,
			Confidence:  conf,
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"},
		},
	}, statusChanged, nil
}

// countNewMarkers counts how many markers are present in data but absent from baseline.
func countNewMarkers(data, baseline string, markers []string) int {
	count := 0
	for _, marker := range markers {
		if strings.Contains(data, marker) && !strings.Contains(baseline, marker) {
			count++
		}
	}
	return count
}
