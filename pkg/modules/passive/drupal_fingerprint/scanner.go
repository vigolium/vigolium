package drupal_fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var contribModuleRegex = regexp.MustCompile(`/modules/contrib/([a-zA-Z0-9_-]+)/`)
var d7ModuleRegex = regexp.MustCompile(`/sites/all/modules/([a-zA-Z0-9_-]+)/`)

// Module implements the Drupal fingerprinting passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Drupal Fingerprint module.
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
		ds: dedup.LazyDiskSet("drupal_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to identify Drupal installations.
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

	// Check headers
	isDrupal := false
	generation := ""
	var signals []string

	for _, hdr := range ctx.Response().Headers() {
		name := strings.ToLower(hdr.Name)
		if name == "x-drupal-cache" {
			isDrupal = true
			signals = append(signals, "X-Drupal-Cache header")
		}
		if name == "x-drupal-dynamic-cache" {
			isDrupal = true
			generation = "8+"
			signals = append(signals, "X-Drupal-Dynamic-Cache header (Drupal 8+)")
		}
		if name == "x-generator" && strings.Contains(strings.ToLower(hdr.Value), "drupal") {
			isDrupal = true
			signals = append(signals, fmt.Sprintf("X-Generator: %s", hdr.Value))
		}
	}

	// Check body signals
	if strings.Contains(body, `name="generator" content="Drupal`) {
		isDrupal = true
		signals = append(signals, "Generator meta tag")
	}
	if strings.Contains(body, "drupalSettings") || strings.Contains(body, "Drupal.settings") {
		isDrupal = true
		signals = append(signals, "drupalSettings JS object")
	}

	// Drupal 8+ signals
	if strings.Contains(body, "/core/misc/") || strings.Contains(body, "/core/modules/") {
		isDrupal = true
		if generation == "" {
			generation = "8+"
		}
		signals = append(signals, "Drupal 8+ core asset paths")
	}

	// Drupal 7 signals
	if strings.Contains(body, "/misc/drupal.js") || strings.Contains(body, "/sites/all/modules/") {
		isDrupal = true
		if generation == "" {
			generation = "7"
		}
		signals = append(signals, "Drupal 7 asset paths")
	}

	if !isDrupal {
		return nil, nil
	}

	// Extract contrib modules
	seen := make(map[string]bool)
	var modules []string

	for _, match := range contribModuleRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			modules = append(modules, match[1])
		}
	}
	for _, match := range d7ModuleRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			modules = append(modules, match[1])
		}
	}

	extracted := make([]string, 0, len(signals)+2)
	if generation != "" {
		extracted = append(extracted, fmt.Sprintf("Generation: Drupal %s", generation))
	}
	extracted = append(extracted, signals...)
	if len(modules) > 0 {
		extracted = append(extracted, fmt.Sprintf("Contrib modules: %s", strings.Join(modules, ", ")))
	}

	genLabel := ""
	if generation != "" {
		genLabel = fmt.Sprintf(" %s", generation)
	}

	scanCtx.MarkTech(host, "drupal")
	scanCtx.MarkTech(host, "php")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("CMS Detected: Drupal%s", genLabel),
				Description: fmt.Sprintf("Identified Drupal%s installation via %s", genLabel, strings.Join(signals, ", ")),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "fingerprint", "drupal"},
			},
			Metadata: map[string]any{
				"cms":        "drupal",
				"generation": generation,
				"modules":    modules,
			},
		},
	}, nil
}
