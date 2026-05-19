package rails_action_mailbox_probe

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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("rails_action_mailbox_probe"),
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

func (m *Module) fingerprint404(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *notFoundFingerprint {
	randomPath := "/rails/action_mailbox/vigolium-404-" + utils.RandomString(8)

	modifiedRaw, _ := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	modifiedRaw, _ = httpmsg.SetPath(modifiedRaw, randomPath)

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
	// First try OPTIONS to check if the endpoint accepts POST
	modifiedRaw, _ := httpmsg.SetMethod(ctx.Request().Raw(), "OPTIONS")
	modifiedRaw, _ = httpmsg.SetPath(modifiedRaw, p.path)

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

	// Reject clearly absent endpoints
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	body := resp.Body().String()

	// Check 404 fingerprint
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

	// Determine detection evidence
	var evidence []string

	// Check Allow header for POST method
	allowHeader := resp.Response().Header.Get("Allow")
	if allowHeader != "" && strings.Contains(strings.ToUpper(allowHeader), "POST") {
		evidence = append(evidence, "Allow: "+allowHeader)
	}

	// Check for WWW-Authenticate (endpoint present but auth-gated)
	wwwAuth := resp.Response().Header.Get("WWW-Authenticate")
	if wwwAuth != "" {
		evidence = append(evidence, "WWW-Authenticate: "+wwwAuth)
	}

	// Check for ActionMailbox in response body
	if strings.Contains(body, "ActionMailbox") || strings.Contains(body, "Action Mailbox") || strings.Contains(body, "action_mailbox") {
		evidence = append(evidence, "Body: ActionMailbox reference")
	}

	// For conductor UI, also check for HTML content markers
	if strings.Contains(p.path, "conductor") {
		if strings.Contains(body, "Inbound Emails") || strings.Contains(body, "inbound_emails") {
			evidence = append(evidence, "Body: Inbound Emails UI")
		}
	}

	// Need at least one evidence item, or a 200/401 status indicating the route exists
	if len(evidence) == 0 {
		if status == 200 || status == 204 || status == 401 {
			evidence = append(evidence, fmt.Sprintf("Status: %d (endpoint exists)", status))
		} else {
			return nil
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	findingSev := p.sev
	conf := severity.Firm
	// Auth-gated endpoints are lower severity
	if status == 401 {
		findingSev = severity.Low
		conf = severity.Tentative
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponse().String(),
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails %s", p.name),
			Description: p.desc,
			Severity:    findingSev,
			Confidence:  conf,
			Tags:        []string{"rails", "ruby", "action-mailbox", "email-ingress"},
			Reference:   []string{"https://guides.rubyonrails.org/action_mailbox_basics.html"},
		},
	}
}
