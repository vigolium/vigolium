package sqli_boolean_blind

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/infra/parampollution"
	"github.com/vigolium/vigolium/pkg/output"
)

// hppBlockProbe is a canonical SQL-ish value appended to the base value to check
// whether a front-end filter is actually rejecting the plain single-parameter
// payloads. HPP is only worth attempting when such a filter is present — its
// value is making the front-end and back-end disagree about which occurrence of
// the parameter is authoritative.
const hppBlockProbe = "' AND 1=1-- -"

// tryHPPFallback is the additive HTTP Parameter Pollution fallback for a single
// insertion point. It runs ONLY after the normal single-parameter differential
// path produced no confirmed finding for the point (inconclusive), and it never
// lowers the confirmation bar: it re-delivers the EXACT same TRUE/FALSE
// differential and 3-round confirmation battery through a duplicated-parameter
// channel by swapping the plain insertion point for a pollution-aware one
// (parampollution.VariantInsertionPoint). Only a full confirmation through that
// channel yields a finding, which is then annotated with the bypass strategy.
//
// It is heavily gated so it adds neither false positives nor meaningful traffic
// on ordinary endpoints:
//
//  1. only URL/body parameters have pollution variants at all;
//  2. the plain payload must be actively FILTERED (blocked) — otherwise the
//     endpoint isn't discriminating on the value and pollution can't help;
//  3. a benign duplicate (base&base) must be accepted cleanly (CleanControl) —
//     an endpoint hostile to duplicates would only manufacture artifacts;
//  4. duplicate ORDERING must actually change the response — if the backend
//     canonicalizes duplicates, no parser split exists to exploit.
func (m *Module) tryHPPFallback(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	baselineSig responseSignature,
	baselineFull string,
) (*output.ResultEvent, error) {
	variantIPs := parampollution.VariantInsertionPoints(ctx, ip)
	if len(variantIPs) == 0 {
		return nil, nil
	}

	// Gate 1: is the plain single-parameter payload filtered? HPP is a filter /
	// parser-discrepancy bypass; if the endpoint doesn't block the plain payload
	// there is nothing for pollution to slip past.
	_, _, plainBlocked, err := m.sendPayload(ctx, httpClient, ip, baseValue+hppBlockProbe)
	if err != nil {
		return nil, err
	}
	if !plainBlocked {
		return nil, nil
	}

	// Gate 2: the endpoint must accept a purely benign duplicate cleanly. If it
	// blocks / errors on / mangles (name=base&name=base), duplicate handling is
	// hostile and any later differential would be a duplicate artifact, not SQL.
	control, ok := parampollution.CleanControl(ctx, ip)
	if !ok {
		return nil, nil
	}
	_, ctrlSig, ctrlBlocked, err := m.sendRaw(ctx, httpClient, control, baseValue)
	if err != nil {
		return nil, err
	}
	if ctrlBlocked || !statusOK(ctrlSig) || !ratioSimilar(ctrlSig, baselineSig) {
		return nil, nil
	}

	// Gate 3: duplicate ordering must matter. If both orderings of the same
	// candidate return the same page, the backend canonicalizes duplicates and no
	// parser split exists — stop before spending the full battery.
	candidates := getPayloadsForValue(baseValue)
	if len(candidates) == 0 {
		return nil, nil
	}
	if !m.hppOrderingMatters(ctx, httpClient, variantIPs, baseValue+candidates[0].trueVal) {
		return nil, nil
	}

	// Battery: run the UNCHANGED differential + confirmation through each pollution
	// channel. The variant's own benign duplicate (name=base&name=base) is the
	// per-channel baseline, so the differential is measured against the same
	// pollution shape it is delivered through.
	for i := range variantIPs {
		vip := variantIPs[i]
		vBaseFull, vBaseSig, vBaseBlocked, err := m.sendPayload(ctx, httpClient, vip, baseValue)
		if err != nil {
			return nil, err
		}
		// A variant whose own benign form is blocked or non-200 is not a usable
		// 200-vs-200 differential surface — skip it.
		if vBaseBlocked || !statusOK(vBaseSig) {
			continue
		}
		for _, pair := range candidates {
			result, err := m.testPayloadPair(ctx, httpClient, vip, baseValue, pair, vBaseSig, vBaseFull)
			if err != nil {
				return nil, err
			}
			if result != nil {
				annotateHPP(result, vip)
				return result, nil
			}
		}
	}

	return nil, nil
}

// hppOrderingMatters reports whether the two duplicate orderings produce
// materially different responses for the candidate payload. A difference in
// blocked-state or status is the clearest signal (the classic WAF-inspects-one-
// occurrence split); otherwise it falls back to a body-ratio comparison. When the
// ordering pair cannot be identified it returns true (do not suppress HPP).
func (m *Module) hppOrderingMatters(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	variantIPs []parampollution.VariantInsertionPoint,
	payload string,
) bool {
	safeFirst, payloadFirst := pickDupOrderings(variantIPs)
	if safeFirst == nil || payloadFirst == nil {
		return true
	}

	_, sfSig, sfBlocked, err := m.sendPayload(ctx, httpClient, *safeFirst, payload)
	if err != nil {
		return false
	}
	_, pfSig, pfBlocked, err := m.sendPayload(ctx, httpClient, *payloadFirst, payload)
	if err != nil {
		return false
	}
	if sfBlocked != pfBlocked {
		return true
	}
	if sfSig.StatusCode != pfSig.StatusCode {
		return true
	}
	return !ratioSimilar(sfSig, pfSig)
}

// pickDupOrderings returns the pure-duplicate (single-channel) variants for the
// two wire orderings, used to probe whether ordering changes the response.
func pickDupOrderings(variantIPs []parampollution.VariantInsertionPoint) (safeFirst, payloadFirst *parampollution.VariantInsertionPoint) {
	for i := range variantIPs {
		v := &variantIPs[i]
		if !v.IsPureDuplicate() {
			continue
		}
		switch v.Ordering() {
		case parampollution.OrderingSafeFirst:
			if safeFirst == nil {
				safeFirst = v
			}
		case parampollution.OrderingPayloadFirst:
			if payloadFirst == nil {
				payloadFirst = v
			}
		}
	}
	return safeFirst, payloadFirst
}

// annotateHPP records on a confirmed finding that it was reached through HTTP
// Parameter Pollution, including the ordering and channels of the working variant.
func annotateHPP(r *output.ResultEvent, vip parampollution.VariantInsertionPoint) {
	if r == nil {
		return
	}
	if r.Metadata == nil {
		r.Metadata = map[string]interface{}{}
	}
	r.Metadata["bypass-strategy"] = "http-parameter-pollution"
	r.Metadata["duplicate-ordering"] = vip.Ordering()
	r.Metadata["channels"] = vip.Channels()
	r.AdditionalEvidence = append(r.AdditionalEvidence, fmt.Sprintf(
		"# [bypass] Confirmed via HTTP Parameter Pollution: variant=%s ordering=%s channels=%s "+
			"(the plain single-parameter payload was filtered; delivering it as a duplicate reached the SQL boolean oracle)",
		vip.VariantName(), vip.Ordering(), vip.Channels()))
}

// sendRaw sends an already-built raw request (used for HPP control probes whose
// shape has no plain insertion point) and returns the full response string, its
// comparison signature, and whether it was a WAF/CDN block. It mirrors
// sendPayload's transport options exactly — most importantly NoClustering, so the
// stability re-sends are never served from the request-cluster cache.
func (m *Module) sendRaw(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	raw []byte,
	reflect string,
) (string, responseSignature, bool, error) {
	fuzzedReq := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return "", responseSignature{}, false, err
	}
	defer resp.Close()

	blocked := infra.IsBlockedResponse(resp)
	if resp.Response() == nil {
		return "", responseSignature{}, blocked, nil
	}
	fullResp := resp.FullResponseString()
	sig := newResponseSignature(resp.Response().StatusCode, resp.Body().String(), reflect)
	return fullResp, sig, blocked, nil
}
