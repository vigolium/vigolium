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

// hasSpringBootErrorJSON reports whether body carries the four fields of Spring
// Boot's default JSON error response (timestamp, status, error, path).
func hasSpringBootErrorJSON(body string) bool {
	return strings.Contains(body, `"timestamp"`) && strings.Contains(body, `"status"`) &&
		strings.Contains(body, `"error"`) && strings.Contains(body, `"path"`)
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
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	// springDetected requires a Spring-specific signal. Generic servlet-container
	// evidence (Tomcat/Jetty/Undertow, JSESSIONID, bare "servlet") proves Java, not
	// Spring — java_server_fingerprint marks those. Marking "spring" off them alone
	// false-positived Spring (and its whole active-module family) on every Java host.
	springDetected := false
	var extracted []string
	meta := map[string]any{
		"platform": "spring",
	}

	// X-Application-Context header (Spring Boot specific)
	if appCtx := hdr("X-Application-Context"); appCtx != "" {
		springDetected = true
		extracted = append(extracted, "X-Application-Context: "+appCtx)
	}

	// Server header — a servlet container is generic Java, not proof of Spring.
	// Captured only as supporting context for a Spring finding confirmed elsewhere.
	serverHdr := strings.ToLower(hdr("Server"))
	switch {
	case strings.Contains(serverHdr, "apache-coyote") || strings.Contains(serverHdr, "tomcat"):
		extracted = append(extracted, "Server: Tomcat")
		meta["server"] = "tomcat"
	case strings.Contains(serverHdr, "jetty"):
		extracted = append(extracted, "Server: Jetty")
		meta["server"] = "jetty"
	case strings.Contains(serverHdr, "undertow"):
		extracted = append(extracted, "Server: Undertow")
		meta["server"] = "undertow"
	}

	// X-Powered-By header — "spring" confirms; bare "servlet" is generic Java.
	poweredBy := strings.ToLower(hdr("X-Powered-By"))
	if strings.Contains(poweredBy, "spring") {
		springDetected = true
		extracted = append(extracted, "X-Powered-By: "+hdr("X-Powered-By"))
	} else if strings.Contains(poweredBy, "servlet") {
		extracted = append(extracted, "X-Powered-By: "+hdr("X-Powered-By"))
		meta["servlet"] = true
	}

	// Spring-specific content type
	ct := strings.ToLower(hdr("Content-Type"))
	if strings.Contains(ct, "spring-boot.actuator") {
		springDetected = true
		extracted = append(extracted, "Content-Type: Spring Actuator")
	}

	// Cookie signals: JSESSIONID is a generic servlet-container cookie (any Java
	// app), not Spring — supporting context only.
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.Contains(strings.ToLower(h.Value), "jsessionid=") {
			extracted = append(extracted, "Cookie: JSESSIONID")
			meta["sessionCookie"] = "JSESSIONID"
		}
	}

	// Body signals (HTML responses only)
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") {
		// Whitelabel Error Page
		if strings.Contains(body, "Whitelabel Error Page") {
			springDetected = true
			extracted = append(extracted, "Body: Whitelabel Error Page")
			meta["whitelabel"] = true
		}
		// Spring Security default login
		if strings.Contains(body, `name="_csrf"`) && strings.Contains(body, "Log in") {
			springDetected = true
			extracted = append(extracted, "Body: Spring Security login form")
		}
		// Spring Boot default error attributes
		if hasSpringBootErrorJSON(body) {
			springDetected = true
			extracted = append(extracted, "Body: Spring Boot error JSON")
		}
	}

	// JSON error response pattern (Spring Boot default error)
	if strings.Contains(ct, "json") && hasSpringBootErrorJSON(body) {
		springDetected = true
		extracted = append(extracted, "JSON: Spring Boot default error response")
	}

	if !springDetected {
		return nil, nil
	}

	desc := "Spring Boot/Spring MVC application detected"
	if server, ok := meta["server"]; ok {
		desc += " running on " + server.(string)
	}

	scanCtx.MarkTech(host, "spring")
	scanCtx.MarkTech(host, "java")

	// Claim the host only now that it matched (MISS-19): a host whose
	// first response showed nothing stays open for later responses.
	if diskSet != nil && !diskSet.ClaimOnMatch(host) {
		return nil, nil
	}
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
