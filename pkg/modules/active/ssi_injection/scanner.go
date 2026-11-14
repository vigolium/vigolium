package ssi_injection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

// The oracle is a BRACKETED ECHO OF A SERVER-OWNED VALUE, which is how every other
// evaluation-proving module in this tree works: infra.CmdiArithMarker brackets a
// computed sum the payload never contains, and reflected_ssti and
// struts_ognl_injection match on a freshly computed product. The needle is then
// something reflection cannot produce, in any encoding, so the check needs no
// decoding at all.
//
// **This replaced a set/echo differential that filed ~113 high-severity false
// positives.** That design put a scanner-supplied canary in `value="…"` and proved
// evaluation by the ABSENCE of the directive markup around it. Absence oracles fire on
// any transformation, not just evaluation: an Akamai denial page re-emitting the URL
// as "&#37;23set", an SSO gate re-emitting it as "%2523set", and a keyword-stripping
// WAF deleting "#set" outright all read as "the directive was consumed".
//
// Here the payload is `<L><!--#echo var="DATE_GMT"--><R>` and the needle is L and R
// separated by a short middle that ssiPlainMiddle accepts. Only a server that PARSED
// the comment can put them there. The proof deliberately does not depend on DATE_GMT
// resolving, so it holds across mod_include, nginx ssi, IIS and lighttpd: Apache's
// `(none)`, nginx's `none` and even `[an error occurred while processing this
// directive]` all still prove the parser ran.
const (
	ssiEchoDirective = `<!--#echo var="DATE_GMT"-->`

	// ssiControlComment is an ordinary HTML comment — no leading "#", so no SSI
	// implementation evaluates it. It is the discriminator for the one false positive
	// this design introduces: a sanitizer that STRIPS `<!--…-->` also brings L and R
	// together. A real SSI server passes this through verbatim (leaving "<" between the
	// tags, which fails the needle); a stripper removes it and matches, and that match
	// is what rules the target out.
	ssiControlComment = `<!--x-->`

	// ssiMiddleMax bounds what may sit between the tags. A date renders in ~32 bytes
	// and the longest fallback (Apache's directive-error string) in 48; the bound stops
	// an unrelated pair of tag occurrences far apart in a page from matching, and caps
	// the work ssiEchoValue does per occurrence of the left tag.
	ssiMiddleMax = 64

	// ssiPlainPunct is every non-alphanumeric byte a server-rendered SSI value may
	// contain: a date's separators, a `(none)` fallback's parens, the brackets of
	// Apache's directive-error string. Every encoding of the payload keeps at least one
	// byte outside this set and the alphanumerics — "<" verbatim, "&" entity-escaped,
	// "%" percent-encoded, and `"`/`#`/`=`/`!` even after tag-stripping.
	ssiPlainPunct = ` ,:-./+()[]`
)

// ssiExecTemplates render an SSI exec directive that reaches the collaborator over
// different channels. nslookup exercises DNS-only egress; curl/wget exercise an HTTP
// fetch (a stronger, higher-confidence signal). One host is minted per template so a
// callback pinpoints the exact directive that fired.
var ssiExecTemplates = []func(host string) string{
	func(h string) string { return `<!--#exec cmd="nslookup ` + h + `"-->` },
	func(h string) string { return `<!--#exec cmd="curl http://` + h + `"-->` },
	func(h string) string { return `<!--#exec cmd="wget -q -O- http://` + h + `"-->` },
}

// Module implements the Server-Side Includes injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSI injection module.
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
		rhm: dedup.LazyDefaultRHM("ssi_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SSI injection. It runs the
// in-band bracketed echo first (Firm), then fires out-of-band exec directives whose
// callbacks arrive asynchronously.
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
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	// Tech-stack pre-filter: SSI is evaluated only on HTML documents. Skip a non-HTML
	// observed response outright; confirmEvaluation below re-checks the fuzzed
	// response's content-type and also derives reachability, so no separate probe is
	// needed.
	if r := ctx.Response(); r != nil && modkit.ClassifyContentType(r.Header("Content-Type")) != modkit.ContentClassHTML {
		return nil, nil
	}

	finding, reached := m.confirmEvaluation(ctx, ip, httpClient, urlx.String(), ip.Name())
	if finding != nil {
		return []*output.ResultEvent{finding}, nil
	}

	// Out-of-band exec (async): even where directive output is not evaluated in band,
	// an SSI exec directive can reach the collaborator — but only fire it when the
	// input actually reached an HTML page, the necessary SSI precondition. Findings
	// arrive via OAST polling.
	if reached {
		m.fireExecOAST(ctx, ip, httpClient, scanCtx, urlx.String())
	}

	return nil, nil
}

// confirmEvaluation proves that the target's SSI parser consumed an injected comment,
// building the finding itself so the probe's value, request and response stay where
// they were observed. It returns reached separately: true once the tags are seen in an
// HTML body the APPLICATION rendered, even if nothing parsed them, which is the
// precondition the caller's out-of-band exec route needs.
//
// Two requests, and the second only on the confirming path:
//
//  1. The probe `<L><!--#echo var="DATE_GMT"--><R>`. The tags are freshly minted per
//     call, so a fixed string already on the page cannot satisfy the needle — which is
//     why no second probe round is needed to rule out coincidence (the old design
//     needed one because its needle was a value it had supplied).
//  2. The control `<L><!--x--><R>`. It must NOT match; a match means the target strips
//     comments wholesale rather than parsing them, so the probe proved nothing. Fail
//     OPEN on a transport error, matching reflected_ssti — a transient failure must not
//     suppress a real finding — and CLOSED on a genuine match, which is the stripper
//     this round exists to catch.
func (m *Module) confirmEvaluation(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	urlStr, param string,
) (finding *output.ResultEvent, reached bool) {
	left, right := modkit.FreshCanary(), modkit.FreshCanary()

	// The full response is materialized only when the probe actually matches: it copies
	// headers plus body, and every other outcome would throw that copy away.
	var value string
	var parsed bool
	probeRaw := ip.BuildRequest([]byte(left + ssiEchoDirective + right))
	body, full, ok := m.renderedHTMLBody(ctx, httpClient, probeRaw, func(b string) bool {
		value, parsed = ssiEchoValue(b, left, right)
		return parsed
	})
	if !ok || !strings.Contains(body, left) {
		return nil, false
	}
	if !parsed {
		return nil, true
	}

	controlRaw := ip.BuildRequest([]byte(left + ssiControlComment + right))
	if controlBody, _, controlOK := m.renderedHTMLBody(ctx, httpClient, controlRaw, nil); controlOK {
		if _, stripped := ssiEchoValue(controlBody, left, right); stripped {
			return nil, true
		}
	}

	return &output.ResultEvent{
		URL:              urlStr,
		Matched:          urlStr,
		Request:          string(probeRaw),
		Response:         full,
		FuzzingParameter: param,
		// The observed values, not the method — ModuleConfirmation states how the check
		// works, and a triager needs what to grep the response for. The value is
		// server-owned: the target's own DATE_GMT expansion.
		ExtractedResults: []string{"echoed_var=DATE_GMT", "server_value=" + value},
		Info: output.Info{
			Name:        ModuleName,
			Description: ModuleDesc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{output.MetaSignal: output.SignalInband},
	}, true
}

// renderedHTMLBody sends rawReq and returns its body only when the response is one the
// application itself rendered as HTML. It is the provenance gate every round shares,
// and skipping it is what made this module's dominant false positive: an Akamai
// "Access Denied" 403 echoes the requested URL back into its body on a page the origin
// never saw, as does an SSO gate's 401 interstitial that embeds the URL in an OAuth
// `state`. Both are what infra.IsBlockedResponse exists to reject.
//
// keepFull, when non-nil, decides from the body whether the caller wants the whole
// response as evidence — it runs while the response is still open, because
// FullResponseString copies headers and body and must precede Close.
func (m *Module) renderedHTMLBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
	keepFull func(body string) bool,
) (body, full string, ok bool) {
	req := httpmsg.NewRequestResponseRaw(rawReq, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", "", false
	}
	defer resp.Close()

	// Content class first: it is a header lookup, where IsBlockedResponse scans up to
	// 64 KB of body for challenge markers. SSI runs only over HTML, so a non-HTML
	// response is rejected without paying for that scan.
	r := resp.Response()
	if r == nil || modkit.ClassifyContentType(r.Header.Get("Content-Type")) != modkit.ContentClassHTML {
		return "", "", false
	}
	// A WAF/CDN block or auth gate is the edge talking; a 404 resolved no document and
	// a 3xx carries no rendered output, so neither ran an SSI parser over the input.
	if infra.IsBlockedResponse(resp) || !infra.IsErrorSurfaceStatus(resp) {
		return "", "", false
	}

	body = resp.Body().String()
	if keepFull != nil && keepFull(body) {
		full = resp.FullResponseString()
	}
	return body, full, true
}

// ssiEchoValue returns the string the server put between left and right, and whether
// any occurrence of the pair qualifies. Scanning every occurrence of left matters
// because a page may echo the input more than once — into a <title> and a form field,
// say — and only one of those may sit in an SSI-parsed region.
//
// The search for right is bounded to ssiMiddleMax past the left tag rather than run to
// end of body. Unbounded, a page that reflects the input into many truncated slots
// (a "recent searches" list keeps the 13-byte left tag but drops the right) made every
// occurrence scan the whole remaining body — quadratic, and 8.5s on a 900 KB page.
// Because the search is bounded, a miss says nothing about later occurrences, so it
// continues rather than returning.
func ssiEchoValue(body, left, right string) (string, bool) {
	for off := 0; ; {
		i := strings.Index(body[off:], left)
		if i < 0 {
			return "", false
		}
		mid := off + i + len(left)
		hi := min(len(body), mid+ssiMiddleMax+len(right))
		if j := strings.Index(body[mid:hi], right); j >= 1 && ssiPlainMiddle(body[mid:mid+j]) {
			return body[mid : mid+j], true
		}
		off = mid
	}
}

// ssiPlainMiddle reports whether s could be a server-rendered SSI value rather than a
// surviving fragment of the directive.
func ssiPlainMiddle(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && strings.IndexByte(ssiPlainPunct, c) < 0 {
			return false
		}
	}
	// A server that strips the punctuation out of a reflected value leaves
	// "echovarDATEGMT" here — plain by byte, but plainly still our own directive. Any
	// such middle is a subsequence of the directive text, because stripping only
	// removes characters; a real value is not, since the directive holds no digit and
	// no "n", so every date, `(none)`, `none` and Apache's error string survives.
	// Derived from the payload rather than enumerated, so it closes the whole class
	// rather than the couple of spellings someone thought to list.
	return !subsequenceFold(s, ssiEchoDirective)
}

// subsequenceFold reports whether every byte of s appears in ref, in order, under
// ASCII case folding — so a stripper that also lowercases is caught too.
func subsequenceFold(s, ref string) bool {
	i := 0
	for j := 0; i < len(s) && j < len(ref); j++ {
		if foldASCII(s[i]) == foldASCII(ref[j]) {
			i++
		}
	}
	return i == len(s)
}

// foldASCII lowercases an ASCII byte and leaves every other byte alone.
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// fireExecOAST injects SSI exec directives, one collaborator host per template, so a
// callback confirms server-side command execution via SSI out of band.
func (m *Module) fireExecOAST(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlStr string,
) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}
	requestHash := ctx.Request().ID()
	for _, tmpl := range ssiExecTemplates {
		host := modkit.OASTURLFor(oast, oastclass.CMDI, urlStr, ip.Name(), "ssi-injection command execution", ModuleID, requestHash)
		if host == "" {
			return
		}
		payload := tmpl(host)
		oast.RecordPayload(host, payload)
		fuzzedRaw := ip.BuildRequest([]byte(payload))
		req := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return
			}
			continue
		}
		resp.Close()
	}
}

// RequiresReflection opts into the executor's shared reflection probe
// (modkit.ReflectionAware): the oracle reads the payload back, so a
// point whose value does not come back is skipped.
func (m *Module) RequiresReflection() modkit.ReflectionNeed { return modkit.ReflectBody }

// HasOutOfBandLeg: the OAST include/exec leg needs no reflection, so the
// reflection gate applies only while OAST is off (modkit.OutOfBandLeg).
func (m *Module) HasOutOfBandLeg() bool { return true }
