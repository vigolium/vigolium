package modkit

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// ProofPayload renders the value a recipe places at the insertion point,
// given the marker to plant (a module whose oracle reads no marker ignores it).
type ProofPayload func(marker string) string

// BuildProofRecipe turns a module's decision into an output.ProofRecipe: the
// attack request built from attack at ip, the control built the same way from
// control, and oracle. Nil when the decision cannot be stated as a recipe a
// caller can replay faithfully:
//
//   - the point's encoding rewrites the marker, so the caller's substitution
//     would miss it (a base64- or hex-wrapping point);
//   - the payload lands in a credential header, which a recipe never carries;
//   - the result fails output.ProofRecipe.Validate.
//
// The marker is planted as an alphanumeric sentinel and every occurrence in
// the built request is rewritten to output.MarkerPlaceholder, so the url,
// headers and body carry the placeholder exactly where the point put it.
func BuildProofRecipe(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	attack, control ProofPayload,
	oracle output.ProofOracle,
) *output.ProofRecipe {
	if ctx == nil || ctx.Service() == nil || ip == nil || attack == nil || control == nil {
		return nil
	}
	if proofPointIsCredential(ip) {
		return nil
	}
	sentinel := proofSentinel()
	point := output.ProofInsertionPoint{Type: ip.Type().String(), Name: ip.Name()}

	req, ok := proofRequest(ctx.Service(), ip, attack(sentinel), sentinel)
	if !ok {
		return nil
	}
	req.InsertionPoint = point
	ctl, ok := proofRequest(ctx.Service(), ip, control(sentinel), sentinel)
	if !ok {
		return nil
	}
	recipe := &output.ProofRecipe{
		Request: req,
		Control: output.ProofControl{
			Method: ctl.Method, URL: ctl.URL, Headers: ctl.Headers, Body: ctl.Body,
			InsertionPoint: &point, PayloadTemplate: ctl.PayloadTemplate,
		},
		Oracle:        oracle,
		Preconditions: output.ProofPreconditions{MethodSafe: httpmsg.IsSafeMethod(req.Method)},
	}
	if recipe.Validate() != nil {
		return nil
	}
	return recipe
}

// proofPointIsCredential reports whether ip writes into a header a recipe
// never carries: a cookie, or an Authorization-class header.
func proofPointIsCredential(ip httpmsg.InsertionPoint) bool {
	switch ip.Type() {
	case httpmsg.INS_PARAM_COOKIE:
		return true
	case httpmsg.INS_HEADER:
		return slices.Contains(proofCredentialHeaders, strings.ToLower(ip.Name()))
	}
	return false
}

// proofSentinel is a fresh token no request carries by chance and no point
// encoding rewrites (lowercase letters and digits only).
func proofSentinel() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "vgpm" + hex.EncodeToString(buf)
}

// proofCredentialHeaders never ride on a recipe; proofFramingHeaders are the
// caller's to set from the url and body.
var (
	proofCredentialHeaders = []string{"authorization", "cookie", "proxy-authorization"}
	proofFramingHeaders    = []string{"host", "content-length", "transfer-encoding", "connection"}
)

// proofRequest builds one recipe request: payload at ip, the sentinel
// rewritten to the placeholder. ok is false when the sentinel was planted but
// does not survive verbatim, or lands in a credential header.
func proofRequest(svc *httpmsg.Service, ip httpmsg.InsertionPoint, payload, sentinel string) (output.ProofRequest, bool) {
	raw := ip.BuildRequest([]byte(payload))
	parsed := httpmsg.NewHttpRequestWithService(svc, raw)
	planted := strings.Contains(payload, sentinel)
	if planted && !strings.Contains(string(raw), sentinel) {
		return output.ProofRequest{}, false
	}
	put := func(s string) string { return strings.ReplaceAll(s, sentinel, output.MarkerPlaceholder) }

	headers := map[string]string{}
	for _, h := range parsed.Headers() {
		lower := strings.ToLower(h.Name)
		if slices.Contains(proofCredentialHeaders, lower) {
			if strings.Contains(h.Value, sentinel) {
				return output.ProofRequest{}, false
			}
			continue
		}
		if slices.Contains(proofFramingHeaders, lower) {
			continue
		}
		if prev, dup := headers[h.Name]; dup {
			headers[h.Name] = prev + ", " + put(h.Value)
			continue
		}
		headers[h.Name] = put(h.Value)
	}
	return output.ProofRequest{
		Method:          parsed.Method(),
		URL:             put(proofURL(svc, parsed.Path())),
		Headers:         headers,
		Body:            put(parsed.BodyToString()),
		PayloadTemplate: put(payload),
	}, true
}

// proofURL is the request's absolute URL: an absolute-form target as sent,
// otherwise the service origin (default port omitted) and the raw target.
func proofURL(svc *httpmsg.Service, target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	scheme := svc.Protocol()
	host := svc.Host()
	port := svc.Port()
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) || port == 0 {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return scheme + "://" + host + target
}
