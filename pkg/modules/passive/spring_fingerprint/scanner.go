package spring_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
		ds: dedup.LazyDiskSet("spring_fingerprint"),
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

	detected := false
	var extracted []string
	meta := map[string]any{
		"platform": "spring",
	}

	// X-Application-Context header (Spring Boot specific)
	if appCtx := hdr("X-Application-Context"); appCtx != "" {
		detected = true
		extracted = append(extracted, "X-Application-Context: "+appCtx)
	}

	// Server header signals
	serverHdr := strings.ToLower(hdr("Server"))
	if strings.Contains(serverHdr, "apache-coyote") || strings.Contains(serverHdr, "tomcat") {
		detected = true
		extracted = append(extracted, "Server: Tomcat")
		meta["server"] = "tomcat"
	} else if strings.Contains(serverHdr, "jetty") {
		detected = true
		extracted = append(extracted, "Server: Jetty")
		meta["server"] = "jetty"
	} else if strings.Contains(serverHdr, "undertow") {
		detected = true
		extracted = append(extracted, "Server: Undertow")
		meta["server"] = "undertow"
	}

	// X-Powered-By header
	poweredBy := strings.ToLower(hdr("X-Powered-By"))
	if strings.Contains(poweredBy, "spring") {
		detected = true
		extracted = append(extracted, "X-Powered-By: "+hdr("X-Powered-By"))
	} else if strings.Contains(poweredBy, "servlet") {
		detected = true
		extracted = append(extracted, "X-Powered-By: "+hdr("X-Powered-By"))
		meta["servlet"] = true
	}

	// Spring-specific content type
	ct := strings.ToLower(hdr("Content-Type"))
	if strings.Contains(ct, "spring-boot.actuator") {
		detected = true
		extracted = append(extracted, "Content-Type: Spring Actuator")
	}

	// Cookie signals: JSESSIONID is common in Java/Spring apps
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		cookieLower := strings.ToLower(h.Value)
		if strings.Contains(cookieLower, "jsessionid=") {
			detected = true
			extracted = append(extracted, "Cookie: JSESSIONID")
			meta["sessionCookie"] = "JSESSIONID"
		}
	}

	// Body signals (HTML responses only)
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") {
		// Whitelabel Error Page
		if strings.Contains(body, "Whitelabel Error Page") {
			detected = true
			extracted = append(extracted, "Body: Whitelabel Error Page")
			meta["whitelabel"] = true
		}
		// Spring Security default login
		if strings.Contains(body, `name="_csrf"`) && strings.Contains(body, "Log in") {
			detected = true
			extracted = append(extracted, "Body: Spring Security login form")
		}
		// Spring Boot default error attributes
		if strings.Contains(body, `"timestamp"`) && strings.Contains(body, `"status"`) && strings.Contains(body, `"error"`) && strings.Contains(body, `"path"`) {
			detected = true
			extracted = append(extracted, "Body: Spring Boot error JSON")
		}
	}

	// JSON error response pattern (Spring Boot default error)
	if strings.Contains(ct, "json") {
		if strings.Contains(body, `"timestamp"`) && strings.Contains(body, `"status"`) && strings.Contains(body, `"error"`) && strings.Contains(body, `"path"`) {
			detected = true
			extracted = append(extracted, "JSON: Spring Boot default error response")
		}
	}

	if !detected {
		return nil, nil
	}

	desc := "Spring Boot/Spring MVC application detected"
	if server, ok := meta["server"]; ok {
		desc += " running on " + server.(string)
	}

	scanCtx.MarkTech(host, "spring")
	scanCtx.MarkTech(host, "java")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Spring Boot/Spring MVC Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"spring", "java", "fingerprint"},
			},
			Metadata: meta,
		},
	}, nil
}
