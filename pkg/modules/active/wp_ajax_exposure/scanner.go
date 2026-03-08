package wp_ajax_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
		ds: dedup.LazyDiskSet("wp_ajax_exposure"),
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, action := range vulnerableActions {
		result := m.probeAction(ctx, httpClient, urlx.Scheme, urlx.Host, action)
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probeAction(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scheme, host string,
	action ajaxAction,
) *output.ResultEvent {
	path := "/wp-admin/admin-ajax.php"
	body := "action=" + action.name

	rawReq := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
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
	respBody := resp.Body().String()

	// WordPress returns "0" for unregistered actions
	// A real handler returns something else
	if status != 200 {
		return nil
	}
	trimmed := strings.TrimSpace(respBody)
	if trimmed == "0" || trimmed == "-1" || trimmed == "" {
		return nil
	}

	// Check for anti-markers (generic error pages)
	lowerBody := strings.ToLower(respBody)
	if strings.Contains(lowerBody, "<!doctype") || strings.Contains(lowerBody, "<html") {
		if !strings.Contains(lowerBody, "admin-ajax") {
			return nil
		}
	}

	targetURL := scheme + "://" + host + path + "?action=" + action.name

	sev := severity.High
	if action.sev != 0 {
		sev = action.sev
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          rawReq,
		Response:         respBody,
		ExtractedResults: []string{action.name, action.plugin},
		Info: output.Info{
			Name:        fmt.Sprintf("WordPress AJAX Action Exposed: %s", action.name),
			Description: fmt.Sprintf("The wp_ajax_nopriv_%s action (plugin: %s) responds to unauthenticated requests. %s", action.name, action.plugin, action.desc),
			Severity:    sev,
			Confidence:  severity.Firm,
			Tags:        []string{"wordpress", "ajax", "plugin-vulnerability"},
		},
		Metadata: map[string]any{
			"action": action.name,
			"plugin": action.plugin,
		},
	}
}
