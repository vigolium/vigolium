package csp_weakness_audit

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// cspWeakness defines a single CSP weakness.
type cspWeakness struct {
	name      string
	directive string
	severity  severity.Severity
	desc      string
}

// Module implements the CSP weakness audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSP Weakness Audit module.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("csp_weakness_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost checks CSP header for weaknesses once per host.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only check HTML responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	csp := ctx.Response().Header("Content-Security-Policy")
	if csp == "" {
		return nil, nil // security_headers_missing handles absent CSP
	}

	directives := parseCSPDirectives(csp)
	weaknesses := analyzeCSP(directives)

	if len(weaknesses) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, w := range weaknesses {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Weakness: %s", w.name),
				fmt.Sprintf("Directive: %s", w.directive),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("CSP Weakness: %s", w.name),
				Description: w.desc,
				Severity:    w.severity,
				Confidence:  severity.Firm,
				Tags:        []string{"csp", "security-headers", "misconfiguration"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
			},
			Metadata: map[string]any{
				"cwe":       "CWE-693",
				"directive": w.directive,
			},
		})
	}

	return results, nil
}

// parseCSPDirectives splits a CSP header into a map of directive name to values.
func parseCSPDirectives(csp string) map[string]string {
	directives := make(map[string]string)
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, " ", 2)
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		value := ""
		if len(fields) > 1 {
			value = strings.ToLower(strings.TrimSpace(fields[1]))
		}
		directives[name] = value
	}
	return directives
}

// analyzeCSP checks parsed directives for weaknesses.
func analyzeCSP(directives map[string]string) []cspWeakness {
	var weaknesses []cspWeakness

	scriptSrc, hasScriptSrc := directives["script-src"]
	defaultSrc := directives["default-src"]

	// Effective script source (script-src falls back to default-src)
	effectiveScriptSrc := scriptSrc
	if !hasScriptSrc {
		effectiveScriptSrc = defaultSrc
	}

	// Check unsafe-inline in script context
	if strings.Contains(effectiveScriptSrc, "'unsafe-inline'") {
		directive := "script-src"
		if !hasScriptSrc {
			directive = "default-src (fallback for script-src)"
		}
		weaknesses = append(weaknesses, cspWeakness{
			name:      "unsafe-inline in Script Source",
			directive: directive,
			severity:  severity.High,
			desc:      "CSP allows 'unsafe-inline' for scripts, which permits inline script execution and largely negates XSS protection",
		})
	}

	// Check unsafe-eval in script context
	if strings.Contains(effectiveScriptSrc, "'unsafe-eval'") {
		directive := "script-src"
		if !hasScriptSrc {
			directive = "default-src (fallback for script-src)"
		}
		weaknesses = append(weaknesses, cspWeakness{
			name:      "unsafe-eval in Script Source",
			directive: directive,
			severity:  severity.Medium,
			desc:      "CSP allows 'unsafe-eval' for scripts, which permits eval() and similar dynamic code execution",
		})
	}

	// Check wildcard in script context
	if hasScriptSrc && containsWildcard(scriptSrc) {
		weaknesses = append(weaknesses, cspWeakness{
			name:      "Wildcard Script Source",
			directive: "script-src",
			severity:  severity.High,
			desc:      "CSP script-src contains wildcard '*', allowing scripts from any origin",
		})
	}

	// Check data: URI in script context
	if strings.Contains(effectiveScriptSrc, "data:") {
		directive := "script-src"
		if !hasScriptSrc {
			directive = "default-src (fallback for script-src)"
		}
		weaknesses = append(weaknesses, cspWeakness{
			name:      "data: URI in Script Source",
			directive: directive,
			severity:  severity.High,
			desc:      "CSP allows data: URIs for scripts, which can be used to execute arbitrary JavaScript",
		})
	}

	// Check blob: URI in script context
	if strings.Contains(effectiveScriptSrc, "blob:") {
		directive := "script-src"
		if !hasScriptSrc {
			directive = "default-src (fallback for script-src)"
		}
		weaknesses = append(weaknesses, cspWeakness{
			name:      "blob: URI in Script Source",
			directive: directive,
			severity:  severity.Medium,
			desc:      "CSP allows blob: URIs for scripts, which may be leveraged for script execution",
		})
	}

	// Check missing frame-ancestors
	if _, has := directives["frame-ancestors"]; !has {
		weaknesses = append(weaknesses, cspWeakness{
			name:      "Missing frame-ancestors",
			directive: "frame-ancestors",
			severity:  severity.Medium,
			desc:      "CSP does not define frame-ancestors, leaving the application potentially vulnerable to clickjacking attacks",
		})
	}

	// Check missing base-uri
	if _, has := directives["base-uri"]; !has {
		weaknesses = append(weaknesses, cspWeakness{
			name:      "Missing base-uri",
			directive: "base-uri",
			severity:  severity.Low,
			desc:      "CSP does not restrict base-uri, which could allow attackers to change the base URL for relative URLs via <base> tag injection",
		})
	}

	// Check object-src not restricted
	objectSrc, hasObjectSrc := directives["object-src"]
	if hasObjectSrc {
		if objectSrc != "'none'" {
			weaknesses = append(weaknesses, cspWeakness{
				name:      "Permissive object-src",
				directive: "object-src",
				severity:  severity.Medium,
				desc:      "CSP object-src is not set to 'none', allowing potentially dangerous plugin content (Flash, Java applets)",
			})
		}
	} else if defaultSrc != "'none'" {
		weaknesses = append(weaknesses, cspWeakness{
			name:      "Missing object-src Restriction",
			directive: "object-src",
			severity:  severity.Medium,
			desc:      "CSP does not explicitly restrict object-src and default-src is not 'none', allowing potentially dangerous plugin content",
		})
	}

	return weaknesses
}

// containsWildcard checks if a directive value contains a standalone wildcard.
func containsWildcard(value string) bool {
	for _, part := range strings.Fields(value) {
		if part == "*" {
			return true
		}
	}
	return false
}
