package java_server_fingerprint

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
		ds: dedup.LazyDiskSet("java_server_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// serverTags maps a substring of the Server header to the tech tag we publish.
var serverTags = []struct{ needle, tag string }{
	{"tomcat", "tomcat"},
	{"jetty", "jetty"},
	{"jboss", "jboss"},
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

	var evidence []string
	var serverTag string

	server := strings.ToLower(ctx.Response().Header("Server"))
	for _, st := range serverTags {
		if strings.Contains(server, st.needle) {
			serverTag = st.tag
			evidence = append(evidence, "Server: "+ctx.Response().Header("Server"))
			break
		}
	}

	hasJSession := false
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.HasPrefix(h.Value, "JSESSIONID=") {
			hasJSession = true
			evidence = append(evidence, "Set-Cookie: JSESSIONID")
			break
		}
	}

	xpb := strings.ToLower(ctx.Response().Header("X-Powered-By"))
	hasServlet := strings.Contains(xpb, "servlet")
	if hasServlet {
		evidence = append(evidence, "X-Powered-By: "+ctx.Response().Header("X-Powered-By"))
	}

	if len(evidence) == 0 {
		return nil, nil
	}
	// JSESSIONID alone is widely used (also by old JSP, Glassfish, custom apps) —
	// safe to publish "java" but skip emitting a finding if it's the only signal.
	if serverTag == "" && !hasServlet && hasJSession && len(evidence) == 1 {
		scanCtx.MarkTech(host, "java")
		return nil, nil
	}

	scanCtx.MarkTech(host, "java")
	if serverTag != "" {
		scanCtx.MarkTech(host, serverTag)
	}

	name := "Java Application Server Detected"
	if serverTag != "" {
		name = "Java App Server Detected: " + serverTag
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        name,
				Description: name + " from response headers / cookies",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"java", "fingerprint", serverTag},
			},
			Metadata: map[string]any{
				"platform": "java",
				"server":   serverTag,
			},
		},
	}, nil
}
