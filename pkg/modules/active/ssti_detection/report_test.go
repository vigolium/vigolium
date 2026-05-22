package ssti_detection

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, severity.Certain, m.Confidence())
	assert.Equal(t, modkit.ScanScopeInsertionPoint, m.ScanScopes())
}

func mkAttack(probe string, sev, status, length int, payload string) *diffscan.Attack {
	return &diffscan.Attack{
		Probe:         &diffscan.Probe{Name: probe, Severity: sev},
		Payload:       payload,
		FirstSnapshot: &diffscan.ResponseSnapshot{StatusCode: status, ContentLength: length},
	}
}

func TestEscapeMarkdown(t *testing.T) {
	assert.Equal(t, "\\`code\\`", escapeMarkdown("`code`"))
	assert.Equal(t, "a\\|b", escapeMarkdown("a|b"))
	assert.Equal(t, "plain", escapeMarkdown("plain"))
}

func TestGetBestSeverity(t *testing.T) {
	t.Run("picks the maximum", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			mkAttack("p1", 4, 200, 10, "a"),
			mkAttack("p2", 7, 200, 10, "b"),
			mkAttack("p3", 5, 200, 10, "c"),
		}
		assert.Equal(t, 7, getBestSeverity(attacks))
	})

	t.Run("tolerates nil attacks and nil probes", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			nil,
			{Probe: nil, Payload: "x"},
			mkAttack("p", 3, 200, 10, "y"),
		}
		assert.Equal(t, 3, getBestSeverity(attacks))
	})

	t.Run("empty input", func(t *testing.T) {
		assert.Equal(t, 0, getBestSeverity(nil))
	})
}

func TestExtractAttackPairs(t *testing.T) {
	t.Run("pairs break and escape sequentially", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			mkAttack("Jinja2", 5, 500, 12, "{{7*'7'}}"),
			mkAttack("Jinja2", 5, 200, 49, "{{7*7}}"),
		}
		pairs := extractAttackPairs(attacks)
		assert.Len(t, pairs, 1)
		assert.Equal(t, "Jinja2", pairs[0].ProbeName)
		assert.Equal(t, "{{7*'7'}}", pairs[0].BreakPayload)
		assert.Equal(t, 500, pairs[0].BreakStatus)
		assert.Equal(t, "{{7*7}}", pairs[0].EscapePayload)
		assert.Equal(t, 49, pairs[0].EscapeLength)
	})

	t.Run("drops dangling unpaired break", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			mkAttack("p", 5, 500, 12, "break"),
			mkAttack("p", 5, 200, 49, "escape"),
			mkAttack("p", 5, 500, 12, "lonely-break"),
		}
		pairs := extractAttackPairs(attacks)
		assert.Len(t, pairs, 1)
	})

	t.Run("skips WAF-blocked pairs", func(t *testing.T) {
		// Status 429 is treated as WAF-blocked by ResponseSnapshot.WafBlocked.
		attacks := []*diffscan.Attack{
			mkAttack("p", 5, 429, 12, "break"),
			mkAttack("p", 5, 200, 49, "escape"),
		}
		assert.Empty(t, extractAttackPairs(attacks))
	})

	t.Run("skips nil attacks in a pair", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			nil,
			mkAttack("p", 5, 200, 49, "escape"),
		}
		assert.Empty(t, extractAttackPairs(attacks))
	})
}

func TestGroupByProbeName(t *testing.T) {
	pairs := []attackPair{
		{ProbeName: "A"},
		{ProbeName: "B"},
		{ProbeName: "A"},
	}
	groups := groupByProbeName(pairs)
	assert.Len(t, groups["A"], 2)
	assert.Len(t, groups["B"], 1)
}

func TestGenerateMarkdownReport(t *testing.T) {
	t.Run("empty when no attacks", func(t *testing.T) {
		assert.Equal(t, "", generateMarkdownReport(nil, "q"))
	})

	t.Run("renders header and payloads", func(t *testing.T) {
		attacks := []*diffscan.Attack{
			mkAttack("Jinja2 divide", 5, 500, 12, "{{7/0}}"),
			mkAttack("Jinja2 divide", 5, 200, 49, "{{7/1}}"),
		}
		report := generateMarkdownReport(attacks, "name")
		assert.Contains(t, report, "## SSTI Detection - name")
		assert.Contains(t, report, "Jinja2 divide")
		assert.Contains(t, report, "{{7/0}}")
		assert.Contains(t, report, "{{7/1}}")
	})
}

// TestProbeBreakEscapeDistinct enforces the invariant that every SSTI probe
// has a non-empty break payload and a distinct escape payload. The detection
// is purely differential: if the break and escape payloads are identical (a
// common copy-paste mistake when adding a new engine), the probe can never
// produce a response difference and silently detects nothing.
func TestProbeBreakEscapeDistinct(t *testing.T) {
	builders := map[string]func() *diffscan.Probe{
		"GenericSyntax1":      buildGenericSyntaxProbe1,
		"GenericSyntax2":      buildGenericSyntaxProbe2,
		"PythonJoin":          buildPythonJoinProbe,
		"PythonBool":          buildPythonBoolProbe,
		"PHPTypeCoercion":     buildPHPTypeCoercionProbe,
		"PHPStrlen":           buildPHPStrlenProbe,
		"JSTypeof":            buildJSTypeofProbe,
		"JSParseInt":          buildJSParseIntProbe,
		"RubyToS":             buildRubyToSProbe,
		"RubyLength":          buildRubyLengthProbe,
		"JavaOverflow":        buildJavaOverflowProbe,
		"JavaNegOverflow":     buildJavaNegOverflowProbe,
		"Jinja2Expression":    buildJinja2ExpressionProbe,
		"Jinja2Divide":        buildJinja2DivideProbe,
		"Jinja2Join":          buildJinja2JoinProbe,
		"Mako":                buildMakoProbe,
		"MakoJoin":            buildMakoJoinProbe,
		"Tornado":             buildTornadoProbe,
		"Cheetah":             buildCheetahProbe,
		"TwigExpression":      buildTwigExpressionProbe,
		"TwigStatement":       buildTwigStatementProbe,
		"Smarty":              buildSmartyProbe,
		"Blade":               buildBladeProbe,
		"Latte":               buildLatteProbe,
		"Freemarker":          buildFreemarkerProbe,
		"FreemarkerDirective": buildFreemarkerDirectiveProbe,
		"FreemarkerBool":      buildFreemarkerBoolProbe,
		"Velocity":            buildVelocityProbe,
		"VelocityBool":        buildVelocityBoolProbe,
		"VelocityEquals":      buildVelocityEqualsProbe,
		"SpELOverflow":        buildSpELOverflowProbe,
		"SpELNegOverflow":     buildSpELNegOverflowProbe,
		"OGNLOverflow":        buildOGNLOverflowProbe,
		"OGNLNegOverflow":     buildOGNLNegOverflowProbe,
		"Pebble":              buildPebbleProbe,
		"EJS":                 buildEJSProbe,
		"Nunjucks":            buildNunjucksProbe,
		"Pug":                 buildPugProbe,
		"DotJS":               buildDotJSProbe,
		"Marko":               buildMarkoProbe,
		"ERB":                 buildERBProbe,
		"ERBToS":              buildERBToSProbe,
		"Slim":                buildSlimProbe,
		"Haml":                buildHamlProbe,
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			p := build()
			assert.NotEmpty(t, p.Name, "probe must have a name")
			assert.Positive(t, p.Severity, "probe must declare a severity")

			breaks := p.GetBreakStrings()
			escapes := p.GetEscapeStrings()
			assert.NotEmpty(t, breaks, "probe must have a break payload")
			assert.NotEmpty(t, escapes, "probe must have an escape payload")

			breakPayload := breaks[0]
			escapePayload := strings.Join(escapes[0], "")
			assert.NotEqual(t, breakPayload, escapePayload,
				"break and escape payloads must differ or the differential check is a no-op")
		})
	}
}
