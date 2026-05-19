package yamlext

import (
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// YAMLPreHook implements jsext.PreHookExecutor for YAML-defined pre-hooks.
type YAMLPreHook struct {
	def        *ExtensionDef
	configVars map[string]string
}

// NewYAMLPreHook creates a pre-hook from a YAML extension definition.
func NewYAMLPreHook(def *ExtensionDef, configVars map[string]string) *YAMLPreHook {
	return &YAMLPreHook{
		def:        def,
		configVars: configVars,
	}
}

// ID returns the hook identifier.
func (h *YAMLPreHook) ID() string { return h.def.ID }

// Execute runs the pre-hook on a request.
// Returns nil, nil to skip the item.
func (h *YAMLPreHook) Execute(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	if req == nil || req.Request() == nil {
		return req, nil
	}

	// Check skip_when.config_empty — if config var empty, skip the hook (pass through)
	if h.def.SkipWhen != nil && h.def.SkipWhen.ConfigEmpty != "" {
		val := h.configVars[h.def.SkipWhen.ConfigEmpty]
		if val == "" {
			return req, nil
		}
	}

	url := req.Target()
	urlLower := strings.ToLower(url)

	// Check skip_extensions — skip the request item if URL matches
	if len(h.def.SkipExtensions) > 0 {
		// Strip query string for extension matching
		path := strings.SplitN(urlLower, "?", 2)[0]
		ext := strings.ToLower(filepath.Ext(path))
		for _, skipExt := range h.def.SkipExtensions {
			if !strings.HasPrefix(skipExt, ".") {
				skipExt = "." + skipExt
			}
			if ext == strings.ToLower(skipExt) {
				return nil, nil // Skip this request
			}
		}
	}

	// Check skip_when.url_contains — skip the request item if URL matches
	if h.def.SkipWhen != nil {
		for _, pattern := range h.def.SkipWhen.URLContains {
			if strings.Contains(urlLower, strings.ToLower(pattern)) {
				return nil, nil // Skip this request
			}
		}
	}

	// Apply add_headers
	if len(h.def.AddHeaders) > 0 {
		tctx := &TemplateContext{
			ConfigVars: h.configVars,
			Request: &RequestCtx{
				URL:    url,
				Method: req.Request().Method(),
			},
		}

		raw := make([]byte, len(req.Request().Raw()))
		copy(raw, req.Request().Raw())

		for name, valueTmpl := range h.def.AddHeaders {
			value := Render(valueTmpl, tctx)
			modified, err := httpmsg.AddOrReplaceHeader(raw, name, value)
			if err == nil {
				raw = modified
			}
		}

		newReq := httpmsg.NewHttpRequestWithService(req.Service(), raw)
		return httpmsg.NewHttpRequestResponse(newReq, req.Response()), nil
	}

	return req, nil
}

// YAMLPostHook implements jsext.PostHookExecutor for YAML-defined post-hooks.
type YAMLPostHook struct {
	def        *ExtensionDef
	configVars map[string]string
}

// NewYAMLPostHook creates a post-hook from a YAML extension definition.
func NewYAMLPostHook(def *ExtensionDef, configVars map[string]string) *YAMLPostHook {
	return &YAMLPostHook{
		def:        def,
		configVars: configVars,
	}
}

// ID returns the hook identifier.
func (h *YAMLPostHook) ID() string { return h.def.ID }

// Execute runs the post-hook on a result.
// Returns nil, nil to drop the result.
func (h *YAMLPostHook) Execute(result *output.ResultEvent) (*output.ResultEvent, error) {
	if result == nil {
		return result, nil
	}

	urlLower := strings.ToLower(result.URL)

	// Check drop_when
	if h.def.DropWhen != nil {
		// Drop by severity
		if len(h.def.DropWhen.Severity) > 0 {
			resultSev := strings.ToLower(result.Info.Severity.String())
			for _, dropSev := range h.def.DropWhen.Severity {
				if resultSev == strings.ToLower(dropSev) {
					return nil, nil // Drop
				}
			}
		}

		// Drop by URL pattern
		for _, pattern := range h.def.DropWhen.URLContains {
			if strings.Contains(urlLower, strings.ToLower(pattern)) {
				return nil, nil // Drop
			}
		}
	}

	// Check escalate
	if h.def.Escalate != nil {
		for _, pattern := range h.def.Escalate.WhenURLContains {
			if strings.Contains(urlLower, strings.ToLower(pattern)) {
				// Bump severity
				if h.def.Escalate.BumpSeverity {
					result.Info.Severity = BumpSeverity(result.Info.Severity)
				}

				// Add tag to name
				if h.def.Escalate.Tag != "" {
					tag := Render(h.def.Escalate.Tag, &TemplateContext{
						Matched:    pattern,
						ConfigVars: h.configVars,
					})
					result.Info.Name = result.Info.Name + " [" + tag + "]"
				}

				return result, nil
			}
		}
	}

	return result, nil
}
