package rails_active_storage_probe

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Rails Active Storage Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Rails Active Storage Probe module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("rails_active_storage_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed Active Storage and Action Mailbox endpoints.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-rails-storage-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), p.method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	// OPTIONS probes: check Allow header for POST method
	if p.method == "OPTIONS" {
		allowHeader := resp.Response().Header.Get("Allow")
		if allowHeader != "" && strings.Contains(strings.ToUpper(allowHeader), "POST") {
			// Found - endpoint accepts POST
		} else {
			// Check body/headers for markers as fallback
			matched := false
			for _, marker := range p.markers {
				if strings.Contains(body, marker) {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}
	}

	// GET probes with no markers: check for indicators the route exists
	if p.method == "GET" && len(p.markers) == 0 {
		if status == 301 || status == 302 {
			// Redirect indicates the route exists
		} else if strings.Contains(body, "ActiveStorage") || strings.Contains(body, "ActionMailbox") {
			// Body contains Rails framework indicators
		} else if status == 200 {
			// 200 response on a known route is sufficient
		} else {
			return nil
		}
	}

	// GET probes with markers: require marker match
	if p.method == "GET" && len(p.markers) > 0 {
		matched := false
		for _, marker := range p.markers {
			if strings.Contains(body, marker) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	// Also check Allow header for matched markers on OPTIONS probes
	if p.method == "OPTIONS" {
		allowHeader := resp.Response().Header.Get("Allow")
		if allowHeader != "" && strings.Contains(strings.ToUpper(allowHeader), "POST") {
			matchedMarkers = append(matchedMarkers, "Allow: "+allowHeader)
		}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponse().String(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails Endpoint Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"rails", "ruby", "active-storage", "action-mailbox"},
			Reference:   []string{"https://guides.rubyonrails.org/active_storage_overview.html", "https://guides.rubyonrails.org/action_mailbox_basics.html"},
		},
	}
}
