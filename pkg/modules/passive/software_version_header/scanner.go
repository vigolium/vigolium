package software_version_header

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

// versionHeader defines an HTTP header to check for version disclosure.
type versionHeader struct {
	name string
}

var versionHeaders = []versionHeader{
	{name: "Server"},
	{name: "X-Powered-By"},
	{name: "X-AspNet-Version"},
	{name: "X-AspNetMvc-Version"},
	{name: "X-Generator"},
	{name: "X-Drupal-Cache"},
	{name: "X-Varnish"},
	{name: "X-Runtime"},
	{name: "X-OWA-Version"},
	{name: "X-SharePointHealthScore"},
}

// versionPattern matches common version number formats (e.g., "1.2.3", "2.0", "1.2.3-beta.1").
var versionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?`)

// Module implements the Software Version Header passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Software Version Header module.
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
		ds: dedup.LazyDiskSet("passive_software_version_header"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response headers for software version disclosure.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	// Dedup by host — report each server's version headers once
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var extracted []string

	for _, vh := range versionHeaders {
		for _, hdr := range ctx.Response().Headers() {
			if !strings.EqualFold(hdr.Name, vh.name) {
				continue
			}

			version := versionPattern.FindString(hdr.Value)
			if version == "" {
				continue
			}

			extracted = append(extracted, fmt.Sprintf("%s: %s (version: %s)", hdr.Name, hdr.Value, version))
		}
	}

	if len(extracted) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Software Version Disclosed in Headers",
				Description: fmt.Sprintf("HTTP response headers from %s disclose %d software version(s)", host, len(extracted)),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"passive", "fingerprint", "version"},
			},
			Metadata: map[string]any{
				"header_count": len(extracted),
			},
		},
	}, nil
}
