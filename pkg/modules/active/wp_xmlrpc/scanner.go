package wp_xmlrpc

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const listMethodsBody = `<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`

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
		ds: dedup.LazyDiskSet("wp_xmlrpc"),
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

	// Build POST /xmlrpc.php with system.listMethods
	rawReq := "POST /xmlrpc.php HTTP/1.1\r\n" +
		"Host: " + urlx.Host + "\r\n" +
		"Content-Type: text/xml\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"\r\n" +
		listMethodsBody

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil, nil
	}

	body := resp.Body().String()

	// Must contain methodResponse to confirm XML-RPC is active
	if !strings.Contains(body, "methodResponse") {
		return nil, nil
	}

	// Must contain at least one method name
	if !strings.Contains(body, "<value>") {
		return nil, nil
	}

	targetURL := urlx.Scheme + "://" + urlx.Host + "/xmlrpc.php"
	var results []*output.ResultEvent

	// Base finding: XML-RPC is enabled
	results = append(results, &output.ResultEvent{
		URL:      targetURL,
		Matched:  targetURL,
		Request:  rawReq,
		Response: body,
		Info: output.Info{
			Name:        "WordPress XML-RPC Enabled",
			Description: "WordPress XML-RPC endpoint is enabled and responds to method listing requests. XML-RPC is a common brute-force and abuse target.",
			Severity:    severity.Low,
			Confidence:  severity.Certain,
			Tags:        []string{"wordpress", "xmlrpc"},
		},
	})

	// Check for dangerous methods
	hasMulticall := strings.Contains(body, "system.multicall")
	hasPingback := strings.Contains(body, "pingback.ping")
	hasGetUsersBlogs := strings.Contains(body, "wp.getUsersBlogs")

	if hasMulticall {
		extracted := []string{"system.multicall"}
		if hasGetUsersBlogs {
			extracted = append(extracted, "wp.getUsersBlogs")
		}
		results = append(results, &output.ResultEvent{
			URL:              targetURL,
			Matched:          targetURL,
			Request:          rawReq,
			Response:         body,
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "WordPress XML-RPC Multicall Brute-Force",
				Description: "system.multicall is available, enabling amplified brute-force attacks that test many credentials in a single HTTP request",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "xmlrpc", "brute-force"},
			},
		})
	}

	if hasPingback {
		results = append(results, &output.ResultEvent{
			URL:              targetURL,
			Matched:          targetURL,
			Request:          rawReq,
			Response:         body,
			ExtractedResults: []string{"pingback.ping"},
			Info: output.Info{
				Name:        "WordPress XML-RPC Pingback Enabled",
				Description: "pingback.ping is available, which can be abused for SSRF-like outbound requests and DDoS amplification",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "xmlrpc", "ssrf", "pingback"},
			},
		})
	}

	return results, nil
}
