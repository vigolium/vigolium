package angular_template_injection

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

// confirmCount is the number of times an injection must be confirmed
// to reduce false positives (each attempt uses fresh random values).
const confirmCount = 2

// probeTemplate defines an Angular template injection probe format.
type probeTemplate struct {
	name string
	// format takes (left, mathA, mathB, right) — left/right are random anchors
	format string
}

var probeTemplates = []probeTemplate{
	{
		name:   "basic-expression",
		format: "%s{{%d*%d}}%s",
	},
	{
		name:   "constructor-bypass",
		format: "%s{{constructor.constructor('return %d*%d')()}}%s",
	},
}

// Module implements the Angular template injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Angular Template Injection module.
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
		rhm: dedup.LazyDefaultRHM("angular_template_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for Angular template injection.
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

	// Get baseline response body
	var baselineBody string
	if ctx.HasResponse() {
		baselineBody = ctx.Response().BodyToString()
	} else {
		baseResp, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			return nil, nil
		}
		baselineBody = baseResp.Body().String()
		baseResp.Close()
	}

	// Try each probe template
	for _, tmpl := range probeTemplates {
		result := m.tryProbeTemplate(ctx, httpClient, ip, tmpl, baselineBody)
		if result != nil {
			result.URL = urlx.String()
			return []*output.ResultEvent{result}, nil
		}
	}

	return nil, nil
}

// tryProbeTemplate runs the confirmation loop for a specific probe template.
func (m *Module) tryProbeTemplate(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	tmpl probeTemplate,
	baselineBody string,
) *output.ResultEvent {
	for attempt := range confirmCount {
		left := randomString(6)
		right := randomString(6)
		mathA := 1970 + rand.IntN(100)
		mathB := 2024 + rand.IntN(100)
		computed := strconv.Itoa(mathA * mathB)

		probe := fmt.Sprintf(tmpl.format, left, mathA, mathB, right)
		expectedResult := left + computed + right

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

		attackBody := resp.Body().String()
		fullResponse := resp.FullResponse().String()
		resp.Close()

		// Check if the COMPUTED result appears in the response but not in the baseline
		if !strings.Contains(attackBody, expectedResult) || strings.Contains(baselineBody, expectedResult) {
			break // Not vulnerable via this template
		}

		// On final confirmation, report finding
		if attempt == confirmCount-1 {
			return &output.ResultEvent{
				Request:          string(fuzzedRaw),
				Response:         fullResponse,
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{probe, expectedResult, tmpl.name},
				Info: output.Info{
					Description: fmt.Sprintf(
						"Angular template injection detected via %s. "+
							"The parameter '%s' evaluates Angular expressions server-side or client-side. "+
							"Proof: injected `%s` — computed result `%s` appeared in response body.",
						tmpl.name, ip.Name(), probe, expectedResult,
					),
					Reference: []string{
						"https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs",
						"https://github.com/nicedayzhu/angular-sandbox-bypass-collection",
					},
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
