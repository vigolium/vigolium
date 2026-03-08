package aspnet_fingerprint

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var iisVersionRe = regexp.MustCompile(`Microsoft-IIS/([\d.]+)`)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("aspnet_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	// Detection signals
	detected := false
	var extracted []string
	meta := map[string]any{
		"platform": "aspnet",
	}

	// Header signals
	if v := hdr("X-AspNet-Version"); v != "" {
		detected = true
		extracted = append(extracted, "X-AspNet-Version: "+v)
		meta["aspnetVersion"] = v
	}
	if v := hdr("X-AspNetMvc-Version"); v != "" {
		detected = true
		extracted = append(extracted, "X-AspNetMvc-Version: "+v)
		meta["mvcVersion"] = v
	}
	if v := hdr("X-Powered-By"); strings.Contains(v, "ASP.NET") {
		detected = true
		extracted = append(extracted, "X-Powered-By: "+v)
	}

	serverHdr := hdr("Server")
	if m := iisVersionRe.FindStringSubmatch(serverHdr); len(m) > 1 {
		detected = true
		extracted = append(extracted, "Server: "+serverHdr)
		meta["iisVersion"] = m[1]
	}

	// Cookie signals
	cookieSignals := []string{"ASP.NET_SessionId", ".ASPXAUTH", ".AspNetCore.Cookies", "__RequestVerificationToken"}
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		for _, sig := range cookieSignals {
			if strings.Contains(h.Value, sig) {
				detected = true
				extracted = append(extracted, "Cookie: "+sig)
			}
		}
		if strings.HasPrefix(strings.ToUpper(h.Value), "ASPSESSIONID") {
			detected = true
			extracted = append(extracted, "Cookie: ASPSESSIONID*")
			meta["isClassicAsp"] = true
		}
	}

	// Body signals (only check HTML responses)
	ct := strings.ToLower(hdr("Content-Type"))
	if strings.Contains(ct, "text/html") {
		bodySignals := map[string]string{
			"__VIEWSTATE":          "WebForms ViewState",
			"__EVENTVALIDATION":    "WebForms EventValidation",
			"__VIEWSTATEGENERATOR": "WebForms ViewStateGenerator",
			"__doPostBack(":        "WebForms PostBack",
			"WebResource.axd":      "WebResource.axd",
			"ScriptResource.axd":   "ScriptResource.axd",
		}
		for sig, label := range bodySignals {
			if strings.Contains(body, sig) {
				detected = true
				extracted = append(extracted, "Body: "+label)
				if sig == "__VIEWSTATE" || sig == "__doPostBack(" {
					meta["isWebForms"] = true
				}
			}
		}
	}

	if !detected {
		return nil, nil
	}

	desc := "ASP.NET/IIS installation detected"
	if v, ok := meta["iisVersion"]; ok {
		desc = "Microsoft IIS/" + v.(string) + " detected"
	}
	if v, ok := meta["aspnetVersion"]; ok {
		desc += " with ASP.NET " + v.(string)
	}
	if _, ok := meta["isWebForms"]; ok {
		desc += " (Web Forms)"
	}
	if _, ok := meta["isClassicAsp"]; ok {
		desc += " (Classic ASP)"
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "ASP.NET/IIS Installation Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"aspnet", "iis", "fingerprint", "microsoft"},
			},
			Metadata: meta,
		},
	}, nil
}
