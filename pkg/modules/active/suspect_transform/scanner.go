package suspect_transform

import (
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// confirmCount is the number of times a transformation must be confirmed
// to reduce false positives (each attempt uses random anchors).
const confirmCount = 2

// Check represents a single transformation detection check.
type Check struct {
	Name     string
	GetProbe func() (probe string, expects []string)
	Links    []string
}

// Module detects suspicious input transformations that may indicate vulnerabilities.
type Module struct {
	modkit.BaseActiveModule
	rhm    dedup.Lazy[dedup.RequestHashManager]
	checks []Check
}

// New creates a new SuspectTransform module.
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
		rhm:    dedup.LazyDefaultRHM("suspect_transform"),
		checks: buildChecks(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// buildChecks creates all transformation detection checks.
func buildChecks() []Check {
	return []Check{
		{
			Name:     "quote consumption",
			GetProbe: detectQuoteConsumption,
			Links:    []string{},
		},
		{
			Name:     "arithmetic evaluation",
			GetProbe: detectArithmetic,
			Links:    []string{},
		},
		{
			Name:     "expression evaluation",
			GetProbe: detectExpression,
			Links:    []string{"https://portswigger.net/research/server-side-template-injection"},
		},
		{
			Name:     "template evaluation",
			GetProbe: detectRazorExpression,
			Links:    []string{"https://portswigger.net/research/server-side-template-injection"},
		},
		{
			Name:     "EL evaluation",
			GetProbe: detectAltExpression,
			Links:    []string{"https://portswigger.net/research/server-side-template-injection"},
		},
		{
			Name:     "unicode normalisation",
			GetProbe: detectUnicodeNormalisation,
			Links:    []string{"https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/"},
		},
		{
			Name:     "url decoding error",
			GetProbe: detectURLDecodeError,
			Links:    []string{"https://cwe.mitre.org/data/definitions/172.html"},
		},
		{
			Name:     "unicode byte truncation",
			GetProbe: detectUnicodeByteTruncation,
			Links:    []string{"https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows"},
		},
		{
			Name:     "unicode case conversion",
			GetProbe: detectUnicodeCaseConversion,
			Links:    []string{"https://www.unicode.org/charts/case/index.html"},
		},
		{
			Name:     "unicode combining diacritic",
			GetProbe: detectUnicodeCombiningDiacritic,
			Links:    []string{"https://codepoints.net/combining_diacritical_marks?lang=en"},
		},
		{
			Name:     "Jinja2 template evaluation",
			GetProbe: detectJinja2Template,
			Links:    []string{"https://portswigger.net/research/server-side-template-injection"},
		},
		{
			Name:     "Twig template evaluation",
			GetProbe: detectTwigTemplate,
			Links:    []string{"https://portswigger.net/research/server-side-template-injection"},
		},
	}
}

// ScanPerInsertionPoint tests a single insertion point for suspicious transformations.
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

	// Check deduplication
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get initial response for baseline check
	var initialResponse string
	if ctx.HasResponse() {
		initialResponse = ctx.Response().BodyToString()
	} else {
		baseResp, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			return nil, nil
		}
		initialResponse = baseResp.Body().String()
		baseResp.Close()
	}

	var results []*output.ResultEvent

	for _, check := range m.checks {
		result := m.runCheck(ctx, ip, httpClient, check, initialResponse)
		if result != nil {
			result.URL = urlx.String()
			result.FuzzingParameter = ip.Name()
			results = append(results, result)
		}
	}

	return results, nil
}

// runCheck runs a single transformation check with confirmation.
func (m *Module) runCheck(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	check Check,
	initialResponse string,
) *output.ResultEvent {
	for attempt := range confirmCount {
		probe, expects := check.GetProbe()

		// Build and send fuzzed request
		fuzzedRaw := ip.BuildRequest([]byte(probe))
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			return nil
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil
			}
			return nil
		}

		attackResponse := resp.Body().String()
		fullResponse := resp.FullResponseString()
		resp.Close()

		// Check if any expected value is found in response but not in initial response
		var matched bool
		var matchedExpect string
		for _, expect := range expects {
			if strings.Contains(attackResponse, expect) && !strings.Contains(initialResponse, expect) {
				matched = true
				matchedExpect = expect
				break
			}
		}

		if !matched {
			// No match, skip to next check
			break
		}

		// If this is the final confirmation attempt, report the finding
		if attempt == confirmCount-1 {
			description := fmt.Sprintf("Suspicious input transformation: %s", check.Name)
			if len(check.Links) > 0 {
				description += " | References: " + strings.Join(check.Links, ", ")
			}

			return &output.ResultEvent{
				Request:          string(fuzzedRaw),
				Response:         fullResponse,
				ExtractedResults: []string{probe, matchedExpect},
				Info: output.Info{
					Description: description,
					Reference:   check.Links,
				},
			}
		}
	}

	return nil
}

// randomString generates a random alphanumeric string of the given length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

// Detection functions - each returns (probe, expectedValues)

func detectQuoteConsumption() (string, []string) {
	left := randomString(6)
	right := randomString(6)
	return left + "''" + right, []string{left + "'" + right}
}

func detectArithmetic() (string, []string) {
	x := 99 + rand.IntN(9901) // 99-9999
	y := 99 + rand.IntN(9901)
	probe := fmt.Sprintf("%d*%d", x, y)
	expect := fmt.Sprintf("%d", x*y)
	return probe, []string{expect}
}

func detectExpression() (string, []string) {
	probe, expects := detectArithmetic()
	return "${" + probe + "}", expects
}

func detectRazorExpression() (string, []string) {
	probe, expects := detectArithmetic()
	return "@(" + probe + ")", expects
}

func detectAltExpression() (string, []string) {
	probe, expects := detectArithmetic()
	return "%{" + probe + "}", expects
}

func detectUnicodeNormalisation() (string, []string) {
	left := randomString(6)
	right := randomString(6)
	// U+212A KELVIN SIGN normalizes to 'K'
	return left + "\u212a" + right, []string{left + "K" + right}
}

func detectURLDecodeError() (string, []string) {
	left := randomString(6)
	right := randomString(6)
	// U+0391 GREEK CAPITAL LETTER ALPHA may produce decoding artifacts
	return left + "\u0391" + right, []string{left + "N\u0011" + right}
}

func detectUnicodeByteTruncation() (string, []string) {
	left := randomString(6)
	right := randomString(6)
	// U+CF7B when truncated to single byte becomes '{'
	return left + "\ucf7b" + right, []string{left + "{" + right}
}

func detectUnicodeCaseConversion() (string, []string) {
	left := randomString(6)
	right := randomString(6)
	// U+0131 LATIN SMALL LETTER DOTLESS I uppercases to 'I'
	return left + "\u0131" + right, []string{left + "I" + right}
}

func detectJinja2Template() (string, []string) {
	x := 99 + rand.IntN(9901)
	y := 99 + rand.IntN(9901)
	probe := fmt.Sprintf("{{%d*%d}}", x, y)
	expect := fmt.Sprintf("%d", x*y)
	return probe, []string{expect}
}

func detectTwigTemplate() (string, []string) {
	x := 99 + rand.IntN(9901)
	y := 99 + rand.IntN(9901)
	probe := fmt.Sprintf("{{%d*'%d'}}", x, y)
	expect := fmt.Sprintf("%d", x*y)
	return probe, []string{expect}
}

func detectUnicodeCombiningDiacritic() (string, []string) {
	right := randomString(6)
	// U+0338 COMBINING LONG SOLIDUS OVERLAY combined with '>' produces U+226F NOT GREATER-THAN
	return "\u0338" + right, []string{"\u226f" + right}
}
