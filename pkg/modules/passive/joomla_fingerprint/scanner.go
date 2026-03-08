package joomla_fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var (
	componentRegex = regexp.MustCompile(`/(?:components|media)/com_([a-zA-Z0-9_]+)/`)
	moduleRegex    = regexp.MustCompile(`/modules/mod_([a-zA-Z0-9_]+)/`)
	pluginRegex    = regexp.MustCompile(`/plugins/([a-zA-Z0-9_]+)/([a-zA-Z0-9_]+)/`)
)

// Module implements the Joomla fingerprinting passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Joomla Fingerprint module.
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
		ds: dedup.LazyDiskSet("joomla_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to identify Joomla installations.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	// Dedup by host — only fingerprint once
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	isJoomla := false
	generation := ""
	var signals []string

	// Generator meta tag
	if strings.Contains(body, `content="Joomla`) || strings.Contains(body, `content="Joomla!`) {
		isJoomla = true
		signals = append(signals, "Generator meta tag")
	}

	// Joomla system JS paths
	if strings.Contains(body, "/media/system/js/") {
		isJoomla = true
		signals = append(signals, "/media/system/js/ asset path")
	}

	// Administrator link
	if strings.Contains(body, "/administrator/") {
		isJoomla = true
		signals = append(signals, "/administrator/ reference")
	}

	// com_* component references
	if strings.Contains(body, "option=com_") || strings.Contains(body, "/components/com_") || strings.Contains(body, "/media/com_") {
		isJoomla = true
		signals = append(signals, "Joomla component references (com_*)")
	}

	// Joomla.optionsStorage or Joomla.getOptions (Joomla 4+)
	if strings.Contains(body, "Joomla.optionsStorage") || strings.Contains(body, "Joomla.getOptions") {
		isJoomla = true
		generation = "4+"
		signals = append(signals, "Joomla 4+ JavaScript API")
	}

	// /api/index.php reference (Joomla 4+)
	if strings.Contains(body, "/api/index.php") {
		isJoomla = true
		if generation == "" {
			generation = "4+"
		}
		signals = append(signals, "/api/index.php reference (Joomla 4+)")
	}

	if !isJoomla {
		return nil, nil
	}

	// Extract extensions
	seen := make(map[string]bool)
	var extensions []string

	for _, match := range componentRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			name := "com_" + match[1]
			if !seen[name] {
				seen[name] = true
				extensions = append(extensions, name)
			}
		}
	}
	for _, match := range moduleRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			name := "mod_" + match[1]
			if !seen[name] {
				seen[name] = true
				extensions = append(extensions, name)
			}
		}
	}
	for _, match := range pluginRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 2 {
			name := "plg_" + match[1] + "_" + match[2]
			if !seen[name] {
				seen[name] = true
				extensions = append(extensions, name)
			}
		}
	}

	extracted := make([]string, 0, len(signals)+2)
	if generation != "" {
		extracted = append(extracted, fmt.Sprintf("Generation: Joomla %s", generation))
	}
	extracted = append(extracted, signals...)
	if len(extensions) > 0 {
		extracted = append(extracted, fmt.Sprintf("Extensions: %s", strings.Join(extensions, ", ")))
	}

	genLabel := ""
	if generation != "" {
		genLabel = fmt.Sprintf(" %s", generation)
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("CMS Detected: Joomla%s", genLabel),
				Description: fmt.Sprintf("Identified Joomla%s installation via %s", genLabel, strings.Join(signals, ", ")),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "fingerprint", "joomla"},
			},
			Metadata: map[string]any{
				"cms":        "joomla",
				"generation": generation,
				"extensions": extensions,
			},
		},
	}, nil
}
