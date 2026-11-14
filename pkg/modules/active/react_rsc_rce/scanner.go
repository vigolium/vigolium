package react_rsc_rce

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maliciousRef is the crafted Flight (RSC) argument. The colon-delimited object
// reference makes the server-action decoder dereference a property that does not
// exist, throwing during deserialization.
const maliciousRef = `["$1:a:a"]`

// benignRef is the negative control. "$undefined" is a well-formed Flight sentinel
// that decodes cleanly, so it must NOT reproduce the crafted request's crash. If the
// control also 500s with a digest, the endpoint errors regardless of our payload and
// the signal is discarded.
const benignRef = `["$undefined"]`

// Module implements the React Server Components RCE active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new React Server Components RCE module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("react_rsc_rce"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false: this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess requires an observed response so the Next.js fingerprint gate has a
// body to inspect.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerRequest sends one crafted server-action request to the application root
// and confirms the decoder crash with a benign-control differential. The check is
// gated on a Next.js fingerprint and deduplicated per host.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Gate on Next.js: this is a Next.js / RSC-specific vector, and firing the POST
	// at every host would be noise. Gate BEFORE the dedup test-and-set so a non-Next
	// request does not consume this host's single probe slot — a later Next-looking
	// request on the same host can still trigger it.
	host := service.Host()
	if !jsframework.LooksLikeNextJS(host, observedBody(ctx)) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	// Malicious probe: crafted reference must crash the decoder (500 + error digest).
	malStatus, malBody, malRaw, malFull, ok := m.sendActionProbe(ctx, httpClient, maliciousRef)
	if !ok || !crashed(malStatus, malBody) {
		return nil, nil
	}

	// Reproduce the crash: a one-off 500 (a deploy blip or an unrelated error) is not
	// enough — the crafted reference must trigger the same 500 + digest again.
	mal2Status, mal2Body, _, _, ok2 := m.sendActionProbe(ctx, httpClient, maliciousRef)
	if !ok2 || !crashed(mal2Status, mal2Body) {
		return nil, nil
	}

	// Negative control: a well-formed reference must NOT reproduce the crash. If it
	// does, the endpoint 500s on any server-action call and the digest is not
	// evidence of the decoder flaw — drop.
	ctrlStatus, ctrlBody, _, _, ctrlOK := m.sendActionProbe(ctx, httpClient, benignRef)
	if ctrlOK && crashed(ctrlStatus, ctrlBody) {
		return nil, nil
	}

	target := urlx.Scheme + "://" + urlx.Host + "/"
	return []*output.ResultEvent{{
		URL:      target,
		Matched:  target,
		Request:  string(malRaw),
		Response: malFull,
		ExtractedResults: []string{
			"malicious_status=500 (error digest present)",
			fmt.Sprintf("control_status=%d (no error digest)", ctrlStatus),
			"payload=" + maliciousRef,
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: ModuleDesc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
				"https://nvd.nist.gov/vuln/detail/CVE-2025-66478",
			},
		},
	}}, nil
}

// sendActionProbe issues one server-action POST to "/" carrying ref as the sole
// action argument, and returns the response status, body, the request bytes and the
// full response string.
func (m *Module) sendActionProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ref string,
) (status int, body string, rawReq []byte, full string, ok bool) {
	boundary := "----VigoliumRSC" + utils.RandomString(8)
	mpBody := buildMultipart(boundary, ref)

	raw := ctx.Request().Raw()
	var err error
	if raw, err = httpmsg.SetMethod(raw, "POST"); err != nil {
		return 0, "", nil, "", false
	}
	if raw, err = httpmsg.SetPath(raw, "/"); err != nil {
		return 0, "", nil, "", false
	}
	for _, h := range [][2]string{
		{"Content-Type", "multipart/form-data; boundary=" + boundary},
		{"Accept", "text/x-component"},
		{"Next-Action", utils.RandomString(20)},
		{"Next-Router-State-Tree", `[""]`},
		{"X-Nextjs-Request-Id", uuid.NewString()},
	} {
		if raw, err = httpmsg.AddOrReplaceHeader(raw, h[0], h[1]); err != nil {
			return 0, "", nil, "", false
		}
	}
	if raw, err = httpmsg.SetBody(raw, []byte(mpBody)); err != nil {
		return 0, "", nil, "", false
	}

	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, execErr := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if execErr != nil {
		return 0, "", nil, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", nil, "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), raw, resp.FullResponseString(), true
}

// crashed reports the decoder-crash signature: a 500 carrying a Next.js error digest.
func crashed(status int, body string) bool {
	return status == 500 && hasErrorDigest(body)
}

// buildMultipart renders the two-part server-action body: the bound-args part
// ("1" -> {}) and the action arguments part ("0" -> ref).
func buildMultipart(boundary, ref string) string {
	var b strings.Builder
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"1\"\r\n\r\n")
	b.WriteString("{}\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"0\"\r\n\r\n")
	b.WriteString(ref + "\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

// hasErrorDigest reports whether body carries a Next.js error digest — the surface
// form of an unhandled server-side exception during action decoding.
func hasErrorDigest(body string) bool {
	if strings.Contains(body, `E{"digest"`) {
		return true
	}
	return strings.Contains(body, "digest") && strings.Contains(body, "Error")
}

// observedBody returns the observed response body used for the Next.js fingerprint.
func observedBody(ctx *httpmsg.HttpRequestResponse) string {
	if ctx.Response() == nil {
		return ""
	}
	return ctx.Response().BodyToString()
}
