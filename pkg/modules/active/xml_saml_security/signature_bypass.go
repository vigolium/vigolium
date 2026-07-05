package xml_saml_security

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// signatureRe matches an XML-DSig <Signature> element regardless of namespace
// prefix. Used to strip the signature from a SAML assertion/response.
var signatureRe = regexp.MustCompile(`(?s)<(\w+:)?Signature[\s>].*?</(\w+:)?Signature>`)

// issuerRe / nameIDRe match the text content of the Issuer and NameID elements so
// the negative control can swap in a wrong identity/issuer.
var (
	issuerRe = regexp.MustCompile(`(?s)(<(\w+:)?Issuer[^>]*>)([^<]*)(</(\w+:)?Issuer>)`)
	nameIDRe = regexp.MustCompile(`(?s)(<(\w+:)?NameID[^>]*>)([^<]*)(</(\w+:)?NameID>)`)
)

// authSig captures the response signals that distinguish an accepted SAML
// assertion (post-auth redirect/page) from a rejected one.
type authSig struct {
	status   int
	location string
	body     string
	ok       bool
}

// scanSignatureBypass tests whether the SP accepts a SAML assertion whose XML
// signature has been stripped. Confirmation is a pure differential requiring NO
// prior knowledge of what "authenticated" looks like:
//
//   - baseline R0   = the SP's response to the original (validly signed) assertion.
//   - stripped R_s  = the same assertion with <Signature> removed.
//   - bogus    R_b  = signature stripped AND Issuer/NameID replaced with garbage.
//
// A finding requires R_s to reproduce R0 (unsigned-but-valid assertion accepted)
// while R_b does NOT (a wrong-identity/issuer assertion is rejected). That pairing
// can only hold when R0 is the accepted state and the SP validates assertion
// content but not the signature — so an expired/replay-rejected baseline (R0 is a
// rejection, R_b also a rejection ≈ R0) yields no finding, and a secure SP (R_s
// rejected ≠ R0) yields no finding. There is no signature to strip → no test.
func (m *Module) scanSignatureBypass(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	decoded *DecodedSAML,
) *output.ResultEvent {
	stripped, removed := stripSAMLSignature(decoded.XMLContent)
	if !removed {
		return nil // no signature present — nothing to strip
	}
	bogus := makeBogusAssertion(stripped)
	if bogus == stripped {
		return nil // no Issuer/NameID to mutate — can't build a sound negative control
	}

	// R0: prefer the captured baseline (response to the valid signed assertion);
	// otherwise re-send the original assertion.
	r0 := m.baselineSig(ctx, ip, httpClient, decoded)
	if !r0.ok {
		return nil
	}
	rStrip := m.sendSAMLVariant(ctx, ip, httpClient, EncodeSAML(stripped, decoded))
	rBogus := m.sendSAMLVariant(ctx, ip, httpClient, EncodeSAML(bogus, decoded))
	if !rStrip.ok || !rBogus.ok {
		return nil
	}
	if !authMatch(rStrip, r0) || authMatch(rBogus, r0) {
		return nil
	}

	// Second confirmation round: re-send the stripped assertion and a FRESH bogus
	// control (makeBogusAssertion mints a new random identity each call), and require
	// the same differential to hold. A one-off / dynamic / load-balanced response
	// that coincidentally matched in round one will not reproduce it here.
	rStrip2 := m.sendSAMLVariant(ctx, ip, httpClient, EncodeSAML(stripped, decoded))
	rBogus2 := m.sendSAMLVariant(ctx, ip, httpClient, EncodeSAML(makeBogusAssertion(stripped), decoded))
	if !rStrip2.ok || !rBogus2.ok {
		return nil
	}
	if !authMatch(rStrip2, r0) || authMatch(rBogus2, r0) {
		return nil
	}

	urlx, _ := ctx.URL()
	target := ""
	if urlx != nil {
		target = urlx.String()
	}
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		URL:              target,
		Matched:          target,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{
			"attack=SAML signature stripping",
			fmt.Sprintf("baseline_status=%d stripped_status=%d bogus_status=%d", r0.status, rStrip.status, rBogus.status),
		},
		Info: output.Info{
			Name:        "SAML Signature Not Verified (signature stripping)",
			Description: "The Service Provider accepted a SAML assertion with its XML signature removed — the response matched the validly-signed baseline — while rejecting a wrong-identity control assertion. This means the SP validates assertion content but not its signature, so an attacker can forge assertions to authenticate as any user (full authentication bypass).",
			Severity:    severity.Critical,
			Confidence:  severity.Firm,
			Tags:        append(append([]string{}, ModuleTags...), "signature-bypass", "auth-bypass"),
		},
	}
}

// baselineSig returns the auth signal for the original signed assertion: the
// captured response if present, otherwise a fresh re-send.
func (m *Module) baselineSig(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	decoded *DecodedSAML,
) authSig {
	if resp := ctx.Response(); resp != nil && resp.StatusCode() > 0 {
		return authSig{
			status:   resp.StatusCode(),
			location: resp.Header("Location"),
			body:     resp.BodyToString(),
			ok:       true,
		}
	}
	return m.sendSAMLVariant(ctx, ip, httpClient, ip.BaseValue())
}

// sendSAMLVariant injects value at the SAML insertion point, sends it, and returns
// the auth signal. A blocked/failed request is not ok.
func (m *Module) sendSAMLVariant(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) authSig {
	req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(value)), ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return authSig{}
	}
	defer resp.Close()
	// No WAF/block filtering here: a 401/403 rejection is the exact signal the
	// differential relies on. A genuine WAF block would hit all three variants
	// equally, so the bogus control would still match the baseline and suppress the
	// finding — the differential handles it without a special case.
	if resp.Response() == nil {
		return authSig{}
	}
	return authSig{
		status:   resp.Response().StatusCode,
		location: resp.Response().Header.Get("Location"),
		body:     resp.Body().String(),
		ok:       true,
	}
}

// authMatch reports whether two responses represent the same auth outcome: same
// status class, and — for redirects — the same Location path, otherwise a similar
// body. This treats "accepted" vs "rejected" as distinct even when both are 2xx/3xx.
func authMatch(a, b authSig) bool {
	if a.status/100 != b.status/100 {
		return false
	}
	if a.status >= 300 && a.status < 400 {
		return locationPath(a.location) == locationPath(b.location)
	}
	return modkit.BodiesSimilar(a.body, b.body)
}

// locationPath returns the scheme+host+path of a redirect Location, dropping the
// query (post-auth redirects often carry a per-request token there that would make
// two otherwise-identical redirects compare unequal).
func locationPath(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// stripSAMLSignature removes every XML-DSig <Signature> element. removed is true
// when at least one was present.
func stripSAMLSignature(xml string) (string, bool) {
	out := signatureRe.ReplaceAllString(xml, "")
	return out, out != xml
}

// makeBogusAssertion swaps the Issuer and NameID text for a unique garbage value,
// producing a structurally valid but wrong-identity/issuer (and already unsigned)
// assertion that any content-validating SP must reject.
func makeBogusAssertion(xml string) string {
	tok := "vig-bogus-" + utils.RandomString(8)
	out := issuerRe.ReplaceAllString(xml, "${1}"+tok+"${4}")
	out = nameIDRe.ReplaceAllString(out, "${1}"+tok+"${4}")
	return out
}
