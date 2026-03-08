package wp_rest_api_detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

// coreNamespaces are the built-in WordPress REST API namespaces.
var coreNamespaces = map[string]bool{
	"":                  true,
	"wp/v2":             true,
	"wp-site-health/v1": true,
	"oembed/1.0":        true,
}

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
		ds: dedup.LazyDiskSet("wp_rest_api_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only analyze wp-json responses
	path := urlx.Path
	if !strings.Contains(path, "wp-json") {
		return nil, nil
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	var results []*output.ResultEvent

	// Case 1: /wp-json/ index — extract namespaces
	if strings.HasSuffix(strings.TrimSuffix(path, "/"), "wp-json") {
		result := m.analyzeIndex(urlx.String(), host, body)
		if result != nil {
			results = append(results, result)
		}
	}

	// Case 2: /wp-json/wp/v2/users — user data exposure
	if strings.Contains(path, "wp/v2/users") {
		result := m.analyzeUsers(urlx.String(), host, body)
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) analyzeIndex(url, host, body string) *output.ResultEvent {
	var index struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := json.Unmarshal([]byte(body), &index); err != nil {
		return nil
	}
	if len(index.Namespaces) == 0 {
		return nil
	}

	var customNS []string
	for _, ns := range index.Namespaces {
		if !coreNamespaces[ns] {
			customNS = append(customNS, ns)
		}
	}

	extracted := make([]string, 0, len(index.Namespaces))
	for _, ns := range index.Namespaces {
		label := ns
		if !coreNamespaces[ns] {
			label = ns + " (plugin)"
		}
		extracted = append(extracted, label)
	}

	sev := severity.Info
	desc := fmt.Sprintf("WordPress REST API exposes %d namespace(s)", len(index.Namespaces))
	if len(customNS) > 0 {
		sev = severity.Low
		desc = fmt.Sprintf("WordPress REST API exposes %d namespace(s), including %d custom plugin namespace(s): %s",
			len(index.Namespaces), len(customNS), strings.Join(customNS, ", "))
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "WordPress REST API Namespaces Exposed",
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        []string{"wordpress", "rest-api", "information-disclosure"},
		},
		Metadata: map[string]any{
			"namespaces":       index.Namespaces,
			"customNamespaces": customNS,
		},
	}
}

func (m *Module) analyzeUsers(url, host, body string) *output.ResultEvent {
	var users []struct {
		ID   int    `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(body), &users); err != nil {
		return nil
	}
	if len(users) == 0 {
		return nil
	}

	var extracted []string
	for _, u := range users {
		if u.Slug != "" {
			extracted = append(extracted, fmt.Sprintf("%s (id:%d)", u.Slug, u.ID))
		}
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "WordPress Users Exposed via REST API",
			Description: fmt.Sprintf("Unauthenticated access to wp/v2/users reveals %d user account(s)", len(users)),
			Severity:    severity.Medium,
			Confidence:  severity.Certain,
			Tags:        []string{"wordpress", "rest-api", "user-enumeration"},
		},
		Metadata: map[string]any{
			"userCount": len(users),
		},
	}
}
