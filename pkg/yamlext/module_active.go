package yamlext

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// YAMLActiveModule implements modules.ActiveModule from a .vgm.yaml definition.
type YAMLActiveModule struct {
	modkit.BaseActiveModule
	def        *ExtensionDef
	configVars map[string]string
	httpClient *http.Requester
}

// NewYAMLActiveModule creates an ActiveModule from a YAML extension definition.
func NewYAMLActiveModule(def *ExtensionDef, configVars map[string]string, httpClient *http.Requester) (*YAMLActiveModule, error) {
	scanTypes := ParseScanScopes(def.ScanTypes)
	sev := ParseSeverity(def.Severity)

	base := modkit.NewBaseActiveModule(
		"ext-"+def.ID,
		def.Name,
		def.Description,
		"YAML extension: "+def.Name,
		def.ConfirmationCriteria,
		sev,
		severity.Firm,
		scanTypes,
		modkit.AllInsertionPointTypes,
	)
	base.ModuleTags = def.Tags

	return &YAMLActiveModule{
		BaseActiveModule: base,
		def:              def,
		configVars:       configVars,
		httpClient:       httpClient,
	}, nil
}

func (m *YAMLActiveModule) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	_ *http.Requester,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if len(m.def.Payloads) == 0 {
		return nil, nil
	}

	for _, payloadTmpl := range m.def.Payloads {
		baseCtx := &TemplateContext{
			ConfigVars: m.configVars,
			Insertion: &InsertionCtx{
				Name:      ip.Name(),
				BaseValue: ip.BaseValue(),
				Type:      ip.Type().String(),
			},
		}
		if ctx.Request() != nil {
			baseCtx.Request = &RequestCtx{
				URL:    ctx.Target(),
				Method: ctx.Request().Method(),
			}
		}

		// Render payload (e.g. "VGNM{{rand(8)}}")
		payload := Render(payloadTmpl, baseCtx)
		baseCtx.Payload = payload

		// Build and send request
		rawReq := ip.BuildRequest([]byte(payload))
		fuzzedReq := httpmsg.NewHttpRequestResponse(
			httpmsg.NewHttpRequestWithService(ctx.Service(), rawReq),
			nil,
		)

		resp, _, err := m.httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		// Build response context from ResponseChain
		respBytes := resp.FullResponseBytes()
		resp.Close()
		httpResp := httpmsg.NewHttpResponse(respBytes)

		respCtx := buildResponseCtxFromHTTPResponse(httpResp)
		baseCtx.Response = respCtx

		// Evaluate matchers
		matched, value := EvalMatchers(m.def.Matchers, m.def.MatchersCondition, httpResp, baseCtx)
		if matched {
			baseCtx.Matched = value
			return m.buildFinding(baseCtx, ctx, string(rawReq), string(respBytes)), nil
		}
	}

	return nil, nil
}

func (m *YAMLActiveModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scanExistingResponse(ctx)
}

func (m *YAMLActiveModule) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scanExistingResponse(ctx)
}

func (m *YAMLActiveModule) scanExistingResponse(ctx *httpmsg.HttpRequestResponse) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	baseCtx := &TemplateContext{
		ConfigVars: m.configVars,
	}
	if ctx.Request() != nil {
		baseCtx.Request = &RequestCtx{
			URL:    ctx.Target(),
			Method: ctx.Request().Method(),
		}
	}
	baseCtx.Response = buildResponseCtxFromHTTPResponse(ctx.Response())

	reqStr := ""
	if ctx.Request() != nil {
		reqStr = string(ctx.Request().Raw())
	}
	respStr := string(ctx.Response().Raw())

	// Rules mode
	if len(m.def.Rules) > 0 {
		return m.evalRules(ctx.Response(), baseCtx, ctx, reqStr, respStr), nil
	}

	// Flat matchers mode
	if len(m.def.Matchers) > 0 {
		matched, value := EvalMatchers(m.def.Matchers, m.def.MatchersCondition, ctx.Response(), baseCtx)
		if matched {
			baseCtx.Matched = value
			return m.buildFinding(baseCtx, ctx, reqStr, respStr), nil
		}
	}

	return nil, nil
}

func (m *YAMLActiveModule) evalRules(
	resp *httpmsg.HttpResponse,
	baseCtx *TemplateContext,
	ctx *httpmsg.HttpRequestResponse,
	reqStr, respStr string,
) []*output.ResultEvent {
	var results []*output.ResultEvent
	for i := range m.def.Rules {
		rule := &m.def.Rules[i]
		matched, value := EvalRuleMatch(&rule.Match, resp, baseCtx)
		if matched {
			ruleCtx := *baseCtx
			ruleCtx.Matched = value
			results = append(results, m.buildRuleFinding(&rule.Finding, &ruleCtx, ctx, reqStr, respStr)...)
		}
	}
	return results
}

func (m *YAMLActiveModule) buildFinding(
	tctx *TemplateContext,
	ctx *httpmsg.HttpRequestResponse,
	reqStr, respStr string,
) []*output.ResultEvent {
	if m.def.Finding == nil {
		return nil
	}
	return m.buildRuleFinding(m.def.Finding, tctx, ctx, reqStr, respStr)
}

func (m *YAMLActiveModule) buildRuleFinding(
	finding *FindingDef,
	tctx *TemplateContext,
	ctx *httpmsg.HttpRequestResponse,
	reqStr, respStr string,
) []*output.ResultEvent {
	result := &output.ResultEvent{
		Type:     "http",
		URL:      ctx.Target(),
		Request:  reqStr,
		Response: respStr,
	}

	result.Info.Name = Render(finding.Name, tctx)
	result.Info.Description = Render(finding.Description, tctx)

	if finding.Severity != "" {
		result.Info.Severity = ParseSeverity(finding.Severity)
	} else {
		result.Info.Severity = m.Severity()
	}
	result.Info.Confidence = severity.Firm

	matchedStr := Render(finding.Matched, tctx)
	if matchedStr != "" {
		result.Matched = matchedStr
	} else if tctx.Matched != "" {
		result.Matched = tctx.Matched
	} else {
		result.Matched = ctx.Target()
	}

	return []*output.ResultEvent{result}
}

func buildResponseCtxFromHTTPResponse(resp *httpmsg.HttpResponse) *ResponseCtx {
	if resp == nil {
		return nil
	}
	hdrs := make(map[string]string)
	for _, h := range resp.Headers() {
		hdrs[h.Name] = h.Value
	}
	return &ResponseCtx{
		Status:  resp.StatusCode(),
		Body:    resp.BodyToString(),
		Headers: hdrs,
	}
}
