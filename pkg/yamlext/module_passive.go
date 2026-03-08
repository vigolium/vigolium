package yamlext

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// YAMLPassiveModule implements modules.PassiveModule from a .vgm.yaml definition.
type YAMLPassiveModule struct {
	modkit.BasePassiveModule
	def        *ExtensionDef
	configVars map[string]string
}

// NewYAMLPassiveModule creates a PassiveModule from a YAML extension definition.
func NewYAMLPassiveModule(def *ExtensionDef, configVars map[string]string) (*YAMLPassiveModule, error) {
	scanTypes := ParseScanScopes(def.ScanTypes)
	sev := ParseSeverity(def.Severity)
	scope := ParsePassiveScope(def.Scope)

	base := modkit.NewBasePassiveModule(
		"passive-ext-"+def.ID,
		def.Name,
		def.Description,
		"YAML extension: "+def.Name,
		def.ConfirmationCriteria,
		sev,
		severity.Firm,
		scanTypes,
		scope,
	)
	base.ModuleTags = def.Tags

	return &YAMLPassiveModule{
		BasePassiveModule: base,
		def:               def,
		configVars:        configVars,
	}, nil
}

func (m *YAMLPassiveModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scan(ctx)
}

func (m *YAMLPassiveModule) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scan(ctx)
}

func (m *YAMLPassiveModule) scan(ctx *httpmsg.HttpRequestResponse) ([]*output.ResultEvent, error) {
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

func (m *YAMLPassiveModule) evalRules(
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

func (m *YAMLPassiveModule) buildFinding(
	tctx *TemplateContext,
	ctx *httpmsg.HttpRequestResponse,
	reqStr, respStr string,
) []*output.ResultEvent {
	if m.def.Finding == nil {
		return nil
	}
	return m.buildRuleFinding(m.def.Finding, tctx, ctx, reqStr, respStr)
}

func (m *YAMLPassiveModule) buildRuleFinding(
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
