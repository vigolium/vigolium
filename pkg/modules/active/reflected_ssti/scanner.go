package reflected_ssti

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// primaryFirst/primaryLast are the operands of the primary probe expression
// (1970*2024). They are deliberately year-shaped so the product (3987280) is a
// plausible-but-uncommon 7-digit number rather than the classic 7*7=49 that
// matches almost any page. The reflection-tracking confirmation re-derives the
// breakout template from a matched payload by swapping this exact expression for a
// fresh random one, so the two must stay in sync (the test invariant pins it).
const (
	primaryFirst = 1970
	primaryLast  = 2024
)

// primaryExpr is the literal multiplication embedded in every breakout payload
// (primaryFirst*primaryLast). The reflection-tracking confirmation swaps exactly
// this substring for a fresh expression, so it is computed once from the operands.
var primaryExpr = strconv.Itoa(primaryFirst) + "*" + strconv.Itoa(primaryLast)

type Module struct {
	modkit.BaseActiveModule
	result   string
	payloads []string
	rhm      dedup.Lazy[dedup.RequestHashManager]
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		result:   strconv.Itoa(primaryFirst * primaryLast),
		payloads: buildPayloads(primaryFirst, primaryLast),
		rhm:      dedup.LazyDefaultRHM("reflected_ssti"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// template payload request and verifying the evaluated math result reproducibly
// appears as content absent from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// ScanPerInsertionPoint tests a single insertion point for SSTI.
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

	// Check if we should scan this insertion point
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	for _, payload := range m.payloads {
		// Build fuzzed request with payload
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		matched := strings.Contains(resp.Body().String(), m.result)
		var fullResp string
		if matched {
			fullResp = resp.FullResponseString()
		}
		resp.Close()
		if !matched {
			continue
		}

		// Reflection-tracking confirmation: the primary result (3987280) is a fixed
		// number, so a page that contains it for an unrelated reason — a product id,
		// a byte size, a timestamp fragment — matches every payload without any
		// template ever evaluating. Re-inject the winning breakout template with
		// FRESH random operands and require the newly-computed product to appear; a
		// genuine evaluation tracks the changing operands while a static number
		// cannot. The fresh product is also inherently absent from any baseline, so
		// this doubles as a baseline-exclusion check. Fail OPEN on a transport error
		// (cerr != nil) so a transient failure never suppresses a real finding.
		if confirmed, cerr := m.confirmEvaluation(ctx, ip, httpClient, payload); cerr == nil && !confirmed {
			continue
		}

		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Request:          string(fuzzedRaw),
			Response:         fullResp,
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{ip.BaseValue()},
		})
		// A confirmed evaluation is decisive; stop probing further breakout forms for
		// this insertion point (downstream dedup would collapse them anyway).
		return results, nil
	}

	return results, nil
}

// confirmEvaluation re-injects the winning breakout template (matchedPayload, which
// embeds the primary primaryFirst*primaryLast expression) with FRESH random
// operands and requires the newly-computed product to appear in the response each
// round. Because every payload is guaranteed to contain the literal primary
// expression (pinned by TestResultMatchesProduct), the fresh payload is built by
// swapping just that expression — preserving the exact template engine delimiters
// that evaluated. A real SSTI evaluation tracks the changing operands every round;
// a page that merely contains the fixed primary result cannot predict a fresh
// random product, so it is dropped. Two independent rounds make a coincidental
// double-match astronomically unlikely.
//
// Returns (confirmed, err): err != nil signals a transport/parse failure so the
// caller fails OPEN (keeps the finding) rather than suppressing a genuine positive.
func (m *Module) confirmEvaluation(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	matchedPayload string,
) (bool, error) {
	const rounds = 2
	for i := 0; i < rounds; i++ {
		// Fresh 4-digit operands keep the product in the same 7-8 digit magnitude as
		// the primary (so an engine that renders the primary plainly renders this one
		// the same way), while randomness makes it unpredictable.
		freshExpr, product := modkit.FreshMultExpr()
		payload := strings.Replace(matchedPayload, primaryExpr, freshExpr, 1)

		fuzzedRaw := ip.BuildRequest([]byte(payload))
		req := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
		if err != nil {
			return false, err
		}
		if resp.Response() == nil {
			resp.Close()
			return false, fmt.Errorf("reflected-ssti confirmation: nil response")
		}
		hit := strings.Contains(resp.Body().String(), product)
		resp.Close()
		if !hit {
			return false, nil // fresh product did not evaluate → the match was coincidental
		}
	}
	return true, nil
}

func buildPayloads(firstNum, lastNum int) []string {
	return []string{
		fmt.Sprintf("${{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("{{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("<%%=%d*%d%%>", firstNum, lastNum),
		fmt.Sprintf("{%d*%d}", firstNum, lastNum),
		fmt.Sprintf("{{{%d*%d}}}", firstNum, lastNum),
		fmt.Sprintf("${{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("#{%d*%d}", firstNum, lastNum),
		fmt.Sprintf("[[%d*%d]]", firstNum, lastNum),
		fmt.Sprintf("{{=%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("[[${%d*%d}]]", firstNum, lastNum),
		fmt.Sprintf("${xyz|%d*%d}", firstNum, lastNum),
		fmt.Sprintf("#set($x=%d*%d)${x}", firstNum, lastNum),
		fmt.Sprintf("@(%d*%d)", firstNum, lastNum),
		fmt.Sprintf("{@%d*%d}", firstNum, lastNum),
		fmt.Sprintf("${%d*%d}", firstNum, lastNum),
	}
}
