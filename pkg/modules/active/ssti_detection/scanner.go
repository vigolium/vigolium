package ssti_detection

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Module implements SSTI Detection via Boolean Error-Based Blind technique.
// Based on "Successful Errors" research by vladko312 (SSTImap).
type Module struct {
	modkit.BaseActiveModule
	rhm     dedup.Lazy[dedup.RequestHashManager]
	options *Options
}

// New creates a new SSTI Detection module.
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
			modkit.AllInsertionPointTypes,
		),
		rhm:     dedup.LazyDefaultRHM("ssti_detection"),
		options: DefaultOptions(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint performs SSTI detection scanning.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, err
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	paramName := ip.Name()
	paramType := fmt.Sprintf("%d", ip.Type())
	if rhm != nil && !rhm.ShouldCheckInsertionPoint(
		urlx, ctx.Request(), paramName, ip.BaseValue(), paramType,
	) {
		return nil, nil
	}

	httpService := ctx.Service()
	if httpService == nil {
		return nil, nil
	}

	baseValue := ip.BaseValue()
	zap.L().Debug("SSTI: Starting scan",
		zap.String("param", paramName),
		zap.String("baseValue", baseValue))

	payloadInjector := diffscan.NewPayloadInjector(
		ctx.Request().Raw(),
		ip,
		httpService,
		httpClient,
		m.options.DiffScanOptions,
	)

	softBase, crudeFuzz, err := m.buildBaselines(payloadInjector, baseValue)
	if err != nil {
		zap.L().Debug("SSTI: Baseline build failed", zap.Error(err))
		return nil, nil
	}

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		zap.L().Debug("SSTI: Baseline too similar, skipping",
			zap.String("param", paramName))
		return nil, nil
	}

	var results []*diffscan.Attack

	// Generic Detection
	if m.options.EnableGenericDetection {
		attacks := m.detectGeneric(payloadInjector, softBase)
		results = append(results, attacks...)
	}

	// Language-Specific Detection (raw language probes without template delimiters)
	attacks := m.detectLanguageSpecific(payloadInjector, softBase)
	results = append(results, attacks...)

	// Template Engine-Specific Detection
	attacks = m.detectTemplateEngines(payloadInjector, softBase)
	results = append(results, attacks...)

	if len(results) == 0 {
		return nil, nil
	}

	report := generateMarkdownReport(results, paramName)
	if report == "" {
		return nil, nil
	}

	bestSeverity := getBestSeverity(results)

	zap.L().Info("SSTI: Found issues",
		zap.String("param", paramName),
		zap.Int("count", len(results)/2))

	return []*output.ResultEvent{{
		URL:              urlx.String(),
		Request:          string(ctx.Request().Raw()),
		FuzzingParameter: paramName,
		Info: output.Info{
			Severity:    intToSeverity(bestSeverity),
			Description: report,
		},
	}}, nil
}

// buildBaselines creates soft and crude baselines for SSTI detection.
// Uses paired crude payloads (same characters, different order) to filter dynamic content.
//
// Key Pattern (from smart_behavior_detection):
//  1. First and second payloads contain SAME breaking characters in DIFFERENT order
//  2. Both must cause similar errors to confirm injection processing
//  3. This filters out false positives from dynamic content
//
// Crude payload covers all major template engines:
//   - {{  : Jinja2, Twig, Tornado, Nunjucks, Pebble, Blade, doT.js, Mustache, Handlebars, Go
//   - ${  : Mako, Freemarker, Velocity, Cheetah, Marko, SpEL, Thymeleaf, Groovy
//   - <%  : EJS, ERB, Mako, Cheetah
//   - {%  : Jinja2, Twig, Tornado, Nunjucks, Liquid
//   - <#  : Freemarker directives
//   - #{  : SpEL, Pug, Slim, Haml, Thymeleaf
//   - @   : OGNL static access
//   - *{  : Thymeleaf selection expressions
//   - ~{  : Thymeleaf fragment expressions
//   - [%  : Template Toolkit (Perl)
//   - {=  : Latte, doT.js (strict mode)
func (m *Module) buildBaselines(
	payloadInjector *diffscan.PayloadInjector,
	baseValue string,
) (*diffscan.Attack, *diffscan.Attack, error) {
	// Soft baseline: original parameter value
	softBase, err := payloadInjector.BuildAttack(baseValue, false)
	if err != nil {
		return nil, nil, err
	}

	// Crude fuzz: Opening delimiters that break ALL template parsers
	// Payload: {{${<%{%<##{@*{~{[%{=
	// Delimiters as sequences: {{ ${ <% {% <# #{ @ *{ ~{ [% {=
	// Chars: { x 8, $ x 1, < x 2, % x 3, # x 2, @ x 1, * x 1, ~ x 1, [ x 1, = x 1
	crudeFuzz, err := payloadInjector.BuildAttack("{{${<%{%<##{@*{~{[%{=", true)
	if err != nil {
		return nil, nil, err
	}

	// First similarity check
	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, fmt.Errorf("baseline too similar")
	}

	// Resend soft baseline to stabilize dynamic attributes
	_softBase, err := payloadInjector.BuildAttack(baseValue, false)
	if err != nil {
		return nil, nil, err
	}
	softBase.AddAttack(_softBase)

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, fmt.Errorf("baseline too similar after resend")
	}

	// Resend crude fuzz with SAME CHARACTERS in DIFFERENT ORDER
	// This is critical: proves the error is from template processing, not dynamic content
	// Reordered: ={[~*@##<{%<%${{{{{{%
	// Same chars: { x 8, $ x 1, < x 2, % x 3, # x 2, @ x 1, * x 1, ~ x 1, [ x 1, = x 1
	_crudeFuzz, err := payloadInjector.BuildAttack("={[~*@##<{%<%${{{{{{%", true)
	if err != nil {
		return nil, nil, err
	}
	crudeFuzz.AddAttack(_crudeFuzz)

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, fmt.Errorf("baseline too similar after double check")
	}

	return softBase, crudeFuzz, nil
}

// detectGeneric tests for generic SSTI via math syntax errors.
func (m *Module) detectGeneric(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
) []*diffscan.Attack {
	var results []*diffscan.Attack

	probes := []*diffscan.Probe{
		buildGenericSyntaxProbe1(),
		buildGenericSyntaxProbe2(),
	}

	for _, p := range probes {
		attacks, err := inj.Fuzz(softBase, p)
		if err != nil {
			continue
		}
		if len(attacks) > 0 {
			results = append(results, attacks...)
			zap.L().Debug("SSTI: Generic detection found",
				zap.String("probe", p.Name),
				zap.Int("attacks", len(attacks)))
		}
	}

	return results
}

// detectLanguageSpecific tests for language-specific vulnerabilities.
// These probes use raw language expressions without template delimiters.
func (m *Module) detectLanguageSpecific(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
) []*diffscan.Attack {
	var results []*diffscan.Attack
	var probes []*diffscan.Probe

	// Python probes (join quirk + bool behavior)
	if m.options.EnablePythonDetection {
		probes = append(probes,
			buildPythonJoinProbe(),
			buildPythonBoolProbe(),
		)
	}

	// PHP probes (type coercion + strlen)
	if m.options.EnablePHPDetection {
		probes = append(probes,
			buildPHPTypeCoercionProbe(),
			buildPHPStrlenProbe(),
		)
	}

	// JavaScript probes (typeof + parseInt)
	if m.options.EnableJavaScriptDetection {
		probes = append(probes,
			buildJSTypeofProbe(),
			buildJSParseIntProbe(),
		)
	}

	// Ruby probes (to_s + length)
	if m.options.EnableRubyDetection {
		probes = append(probes,
			buildRubyToSProbe(),
			buildRubyLengthProbe(),
		)
	}

	// Java probes (integer overflow)
	if m.options.EnableJavaDetection {
		probes = append(probes,
			buildJavaOverflowProbe(),
			buildJavaNegOverflowProbe(),
		)
	}

	for _, p := range probes {
		attacks, err := inj.Fuzz(softBase, p)
		if err != nil {
			continue
		}
		if len(attacks) > 0 {
			results = append(results, attacks...)
			zap.L().Debug("SSTI: Language-specific detected",
				zap.String("probe", p.Name),
				zap.Int("attacks", len(attacks)))
		}
	}

	return results
}

// detectTemplateEngines tests for specific template engine vulnerabilities.
func (m *Module) detectTemplateEngines(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
) []*diffscan.Attack {
	var results []*diffscan.Attack
	var probes []*diffscan.Probe

	// ===================
	// Python Engines
	// ===================

	// Jinja2/Django
	if m.options.EnableJinja2Detection {
		probes = append(probes,
			buildJinja2ExpressionProbe(),
			buildJinja2DivideProbe(),
			buildJinja2JoinProbe(),
		)
	}

	// Mako
	if m.options.EnableMakoDetection {
		probes = append(probes,
			buildMakoProbe(),
			buildMakoJoinProbe(),
		)
	}

	// Tornado
	if m.options.EnableTornadoDetection {
		probes = append(probes, buildTornadoProbe())
	}

	// Cheetah
	if m.options.EnableCheetahDetection {
		probes = append(probes, buildCheetahProbe())
	}

	// ===================
	// PHP Engines
	// ===================

	// Twig
	if m.options.EnableTwigDetection {
		probes = append(probes,
			buildTwigExpressionProbe(),
			buildTwigStatementProbe(),
		)
	}

	// Smarty
	if m.options.EnableSmartyDetection {
		probes = append(probes, buildSmartyProbe())
	}

	// Blade
	if m.options.EnableBladeDetection {
		probes = append(probes, buildBladeProbe())
	}

	// Latte
	if m.options.EnableLatteDetection {
		probes = append(probes, buildLatteProbe())
	}

	// ===================
	// Java Engines
	// ===================

	// Freemarker
	if m.options.EnableFreemarkerDetection {
		probes = append(probes,
			buildFreemarkerProbe(),
			buildFreemarkerDirectiveProbe(),
			buildFreemarkerBoolProbe(),
		)
	}

	// Velocity
	if m.options.EnableVelocityDetection {
		probes = append(probes,
			buildVelocityProbe(),
			buildVelocityBoolProbe(),
			buildVelocityEqualsProbe(),
		)
	}

	// SpEL (Spring Expression Language)
	if m.options.EnableSpELDetection {
		probes = append(probes,
			buildSpELOverflowProbe(),
			buildSpELNegOverflowProbe(),
		)
	}

	// OGNL (Struts)
	if m.options.EnableOGNLDetection {
		probes = append(probes,
			buildOGNLOverflowProbe(),
			buildOGNLNegOverflowProbe(),
		)
	}

	// Pebble
	if m.options.EnablePebbleDetection {
		probes = append(probes, buildPebbleProbe())
	}

	// ===================
	// JavaScript Engines
	// ===================

	// EJS
	if m.options.EnableEJSDetection {
		probes = append(probes, buildEJSProbe())
	}

	// Nunjucks
	if m.options.EnableNunjucksDetection {
		probes = append(probes, buildNunjucksProbe())
	}

	// Pug
	if m.options.EnablePugDetection {
		probes = append(probes, buildPugProbe())
	}

	// doT.js
	if m.options.EnableDotJSDetection {
		probes = append(probes, buildDotJSProbe())
	}

	// Marko
	if m.options.EnableMarkoDetection {
		probes = append(probes, buildMarkoProbe())
	}

	// ===================
	// Ruby Engines
	// ===================

	// ERB
	if m.options.EnableERBDetection {
		probes = append(probes,
			buildERBProbe(),
			buildERBToSProbe(),
		)
	}

	// Slim
	if m.options.EnableSlimDetection {
		probes = append(probes, buildSlimProbe())
	}

	// Haml
	if m.options.EnableHamlDetection {
		probes = append(probes, buildHamlProbe())
	}

	for _, p := range probes {
		attacks, err := inj.Fuzz(softBase, p)
		if err != nil {
			continue
		}
		if len(attacks) > 0 {
			results = append(results, attacks...)
			zap.L().Debug("SSTI: Template engine detected",
				zap.String("probe", p.Name),
				zap.Int("attacks", len(attacks)))
		}
	}

	return results
}

func intToSeverity(sev int) severity.Severity {
	switch {
	case sev >= 7:
		return severity.High
	case sev >= 3:
		return severity.Medium
	default:
		return severity.Low
	}
}
