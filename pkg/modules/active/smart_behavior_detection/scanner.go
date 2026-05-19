package smart_behavior_detection

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	globalutils "github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// Module implements Smart Behavior Detection for injection vulnerabilities.
type Module struct {
	modkit.BaseActiveModule
	rhm     dedup.Lazy[dedup.RequestHashManager]
	options *Options
}

// New creates a new Smart Behavior Detection module.
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
		rhm:     dedup.LazyDefaultRHM("smart_behavior_detection"),
		options: DefaultOptions(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// TimeoutHint raises the per-call active-module timeout above the executor
// default. Behavioral diffing sends many true/false probe pairs (escape sets ×
// soft concatenators) with HTTP round-trips per insertion point and is the
// slowest active module observed in practice, so it legitimately needs longer
// than the default — while still being bounded so it can't hold a worker for
// the whole phase.
func (m *Module) TimeoutHint() time.Duration {
	return 8 * time.Minute
}

// ScanPerInsertionPoint performs smart behavior detection scanning.
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

	// Skip URL path-based insertion points
	// if ip.Type() == httpmsg.INS_URL_PATH_FOLDER || ip.Type() == httpmsg.INS_URL_PATH_FILENAME {
	// 	zap.L().Debug("SmartBehavior: Skipping URL path insertion point",
	// 		zap.String("param", paramName),
	// 		zap.Int("type", int(ip.Type())))
	// 	return nil, nil
	// }

	httpService := ctx.Service()
	if httpService == nil {
		return nil, nil
	}

	baseValue := ip.BaseValue()
	zap.L().Debug("SmartBehavior: Starting scan",
		zap.String("param", paramName),
		zap.String("baseValue", baseValue))

	payloadInjector := diffscan.NewPayloadInjector(
		ctx.Request().Raw(),
		ip,
		httpService,
		httpClient,
		m.options.DiffScanOptions,
	)

	softBase, crudeFuzz, hardBase, err := m.buildBaselines(payloadInjector, baseValue)
	if err != nil {
		zap.L().Debug("SmartBehavior: Baseline build failed", zap.Error(err))
		return nil, nil
	}

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		zap.L().Debug("SmartBehavior: Baseline too similar, skipping",
			zap.String("param", paramName))
		return nil, nil
	}

	var results []*diffscan.Attack
	var potentialDelimiters []string

	// String Delimiter Detection
	if m.options.EnableStringDelimiterDetection {
		delimiters, attacks := m.detectStringDelimiters(payloadInjector, hardBase)
		potentialDelimiters = delimiters
		results = append(results, attacks...)
	}

	// Numeric Context Detection
	if m.options.EnableNumericContextDetection && globalutils.IsNumeric(baseValue) {
		attacks := m.detectNumericContext(payloadInjector, softBase)
		results = append(results, attacks...)
	}

	// Concatenation Testing
	if m.options.EnableConcatenationTesting {
		if !contains(potentialDelimiters, "\"") {
			potentialDelimiters = append(potentialDelimiters, "\"")
		}
		if !contains(potentialDelimiters, "'") {
			potentialDelimiters = append(potentialDelimiters, "'")
		}
		attacks := m.testConcatenation(payloadInjector, softBase, potentialDelimiters)
		results = append(results, attacks...)
	}

	// Order-By Injection
	if m.options.EnableOrderByInjection && globalutils.MightBeOrderBy(paramName, baseValue) {
		attacks := m.testOrderByInjection(payloadInjector, softBase)
		results = append(results, attacks...)
	}

	if len(results) == 0 {
		return nil, nil
	}

	report := generateMarkdownReport(results, paramName)
	if report == "" {
		return nil, nil
	}

	bestSeverity := getBestSeverity(results)

	zap.L().Info("SmartBehavior: Found issues",
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

// buildBaselines creates soft, crude, and hard baselines.
func (m *Module) buildBaselines(
	payloadInjector *diffscan.PayloadInjector,
	baseValue string,
) (*diffscan.Attack, *diffscan.Attack, *diffscan.Attack, error) {
	softBase, err := payloadInjector.BuildAttack(baseValue, false)
	if err != nil {
		return nil, nil, nil, err
	}

	crudeFuzz, err := payloadInjector.BuildAttack("`x'x\"x\\", true)
	if err != nil {
		return nil, nil, nil, err
	}

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, nil, fmt.Errorf("baseline too similar")
	}

	// Resend to update static attributes
	_softBase, err := payloadInjector.BuildAttack(baseValue, false)
	if err != nil {
		return nil, nil, nil, err
	}
	softBase.AddAttack(_softBase)

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, nil, fmt.Errorf("baseline too similar after resend")
	}

	// Send crude fuzz again
	_crudeFuzz, err := payloadInjector.BuildAttack("\\x`x'x\"\\", true)
	if err != nil {
		return nil, nil, nil, err
	}
	crudeFuzz.AddAttack(_crudeFuzz)

	if diffscan.VerySimilar(softBase, crudeFuzz) {
		return nil, nil, nil, fmt.Errorf("baseline too similar after double check")
	}

	// Hard base (empty payload)
	hardBase, err := payloadInjector.BuildAttack("", true)
	if err != nil {
		return nil, nil, nil, err
	}

	if !diffscan.VerySimilar(hardBase, crudeFuzz) {
		_hardBase, err := payloadInjector.BuildAttack("", true)
		if err != nil {
			return nil, nil, nil, err
		}
		hardBase.AddAttack(_hardBase)
	}

	return softBase, crudeFuzz, hardBase, nil
}

// detectStringDelimiters tests for string delimiter vulnerabilities.
func (m *Module) detectStringDelimiters(
	inj *diffscan.PayloadInjector,
	hardBase *diffscan.Attack,
) ([]string, []*diffscan.Attack) {
	var delimiters []string
	var results []*diffscan.Attack

	probes := []*diffscan.Probe{
		buildBackslashProbe(),
		buildApostropheProbe(),
		buildDoubleQuoteProbe(),
		buildBacktickProbe(),
	}

	for _, p := range probes {
		attacks, err := inj.Fuzz(hardBase, p)
		if err != nil {
			continue
		}
		if len(attacks) > 0 {
			delimiters = append(delimiters, p.Base)
			results = append(results, attacks...)
			zap.L().Debug("SmartBehavior: Found delimiter",
				zap.String("delimiter", p.Base),
				zap.Int("attacks", len(attacks)))
		}
	}

	return delimiters, results
}

// detectNumericContext tests for numeric context vulnerabilities.
func (m *Module) detectNumericContext(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
) []*diffscan.Attack {
	p := buildDivideBy0Probe()
	attacks, err := inj.Fuzz(softBase, p)
	if err != nil {
		return nil
	}
	if len(attacks) > 0 {
		zap.L().Debug("SmartBehavior: Numeric context found",
			zap.Int("attacks", len(attacks)))
	}
	return attacks
}

// testConcatenation tests for concatenation vulnerabilities.
// 1. First approach: concat+d+d (break) vs d+concat+d (escape)
// 2. Second approach (fallback): d+concat+d (break) vs concat+d+d (escape)
func (m *Module) testConcatenation(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
	delimiters []string,
) []*diffscan.Attack {
	var results []*diffscan.Attack

	for _, delimiter := range delimiters {
		for _, concat := range m.options.SoftConcatenators {
			// First approach
			p := buildConcatenationProbe(delimiter, concat)
			attacks, err := inj.Fuzz(softBase, p)
			if err == nil && len(attacks) > 0 {
				results = append(results, attacks...)
				zap.L().Debug("SmartBehavior: Concatenation found (approach 1)",
					zap.String("delimiter", delimiter),
					zap.String("concat", concat))
				continue // Found, no need for second approach
			}

			// Second approach (fallback)
			p2 := buildConcatenationProbe2(delimiter, concat)
			attacks2, err := inj.Fuzz(softBase, p2)
			if err == nil && len(attacks2) > 0 {
				results = append(results, attacks2...)
				zap.L().Debug("SmartBehavior: Concatenation found (approach 2)",
					zap.String("delimiter", delimiter),
					zap.String("concat", concat))
			}
		}
	}

	return results
}

// testOrderByInjection tests for ORDER BY injection.
func (m *Module) testOrderByInjection(
	inj *diffscan.PayloadInjector,
	softBase *diffscan.Attack,
) []*diffscan.Attack {
	p := buildOrderByProbe()
	attacks, err := inj.Fuzz(softBase, p)
	if err != nil {
		return nil
	}
	if len(attacks) > 0 {
		zap.L().Debug("SmartBehavior: Order-by injection found",
			zap.Int("attacks", len(attacks)))
	}
	return attacks
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
