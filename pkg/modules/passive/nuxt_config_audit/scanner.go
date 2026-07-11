package nuxt_config_audit

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/modules/shared/stateexposure"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// configPattern defines a single insecure configuration pattern to detect.
type configPattern struct {
	name       string
	re         *regexp.Regexp
	cwe        string
	severity   severity.Severity
	confidence severity.Confidence
	desc       string
}

var configPatterns = []configPattern{
	{
		name:       "Devtools Enabled",
		re:         regexp.MustCompile(`devtools\s*:\s*true`),
		cwe:        "CWE-489",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Nuxt devtools are enabled, potentially exposing application internals",
	},
	{
		name:       "Runtime Config Secret Exposure",
		re:         regexp.MustCompile(`runtimeConfig.*(?:secret|key|token|password)`),
		cwe:        "CWE-200",
		severity:   severity.High,
		confidence: severity.Firm,
		desc:       "Nuxt runtimeConfig contains references to secrets, keys, tokens, or passwords that may be exposed to the client",
	},
	{
		name:       "Production Source Maps",
		re:         regexp.MustCompile(`productionSourceMap\s*:\s*true`),
		cwe:        "CWE-540",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Production source maps are enabled, exposing application source code",
	},
	{
		name:       "Debug Mode Enabled",
		re:         regexp.MustCompile(`debug\s*:\s*true`),
		cwe:        "CWE-489",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Debug mode is enabled in production, potentially exposing verbose error information",
	},
}

// nuxtStateBlob defines where to find Nuxt state data in HTML.
type nuxtStateBlob struct {
	name  string
	start string
	end   string
}

var nuxtStateBlobs = []nuxtStateBlob{
	{
		name:  "__NUXT__",
		start: `window.__NUXT__=`,
		end:   `;</script>`,
	},
	{
		name:  "__NUXT_DATA__",
		start: `<script id="__NUXT_DATA__" type="application/json">`,
		end:   `</script>`,
	},
}

var (
	nuxtSourceMapRe = regexp.MustCompile(`/_nuxt/[^"'\s]+\.js\.map`)
)

// Module implements the Nuxt config audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Nuxt Config Audit module.
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
		ds: dedup.LazyDiskSet("nuxt_config_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts HTML responses or JS/JSON responses with "nuxt" in the URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return true
	}

	if strings.Contains(ct, "javascript") || strings.Contains(ct, "json") {
		if u, err := ctx.URL(); err == nil {
			pathLower := strings.ToLower(u.Path)
			if strings.Contains(pathLower, "nuxt") {
				return true
			}
		}
	}

	return false
}

// ScanPerRequest scans for insecure Nuxt configuration patterns and sensitive data in Nuxt state.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by host
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var results []*output.ResultEvent

	// Check for sensitive data in Nuxt state blobs
	for _, blob := range nuxtStateBlobs {
		stateData := extractState(body, blob)
		if stateData == "" {
			continue
		}

		signals := stateexposure.Analyze(stateData)
		if len(signals) == 0 {
			continue
		}
		candidateCount := 0
		evidence := []string{fmt.Sprintf("State blob: %s", blob.name)}
		for _, signal := range signals {
			evidence = append(evidence, fmt.Sprintf("%s: %s", signal.Category, signal.Evidence))
			if signal.Candidate {
				candidateCount++
			}
		}

		kind := output.RecordKindObservation
		grade := output.EvidenceGradeObservation
		sev := severity.Info
		conf := severity.Tentative
		name := "Nuxt State Security Signals"
		description := "Nuxt state contains identity, role, public-identifier, service, or internal-network context. These patterns are observations without secret validity or authorization proof."
		if candidateCount > 0 {
			kind = output.RecordKindCandidate
			grade = output.EvidenceGradeCandidate
			sev = ModuleSeverity
			conf = ModuleConfidence
			name = "Potential Nuxt State Data Exposure"
			description = fmt.Sprintf("Nuxt state contains %d substantive private credential or password-bearing service URL candidate(s). Credential validity, anonymous reachability, and cross-user authorization were not tested.", candidateCount)
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"nuxt", "data-exposure", "information-disclosure"},
				Reference:   []string{"https://nuxt.com/docs/api/nuxt-config#runtimeconfig"},
			},
			Metadata: map[string]any{
				"stateBlob":             blob.name,
				"signals":               signals,
				"candidateCount":        candidateCount,
				"credentialValidated":   false,
				"authorizationCompared": false,
			},
		})
	}

	// Check each regex-based config pattern. A nuxt.config option is never served
	// from the immutable /_nuxt/ build directory, so skip this branch for client
	// build artifacts: a `runtimeConfig`/`debug:true`/`devtools:true` string inside
	// a minified runtime bundle is a framework-machinery false positive (same hash
	// across every Nuxt site). The __NUXT__ state-blob branch above still runs —
	// that state IS legitimately served in the page.
	configIsBuildArtifact := jsframework.IsClientBuildArtifact(urlx.Path)
	for _, pat := range configPatterns {
		if configIsBuildArtifact {
			break
		}
		match := pat.re.FindString(body)
		if match == "" {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Pattern: %s", pat.name),
				fmt.Sprintf("Matched: %s", modkit.Truncate(match, 120)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Nuxt Config: %s", pat.name),
				Description: pat.desc + ". This is a source/configuration observation; runtime exposure or exploit impact was not tested.",
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"nuxt", "misconfiguration", "source-analysis"},
				Reference:   []string{fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(pat.cwe, "CWE-"))},
			},
			Metadata: map[string]any{
				"cwe":                   pat.cwe,
				"pattern":               pat.name,
				"configured_severity":   pat.severity.String(),
				"runtime_impact_tested": false,
			},
		})
	}

	// Check for /_nuxt/ source map exposure
	if match := nuxtSourceMapRe.FindString(body); match != "" {
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Source map reference: %s", modkit.Truncate(match, 120)),
			},
			Info: output.Info{
				Name:        "Nuxt Source Map Exposure",
				Description: "A /_nuxt/ source-map reference is present. The map was not fetched or parsed here, so source availability and sensitive content are unconfirmed.",
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"nuxt", "sourcemap", "information-disclosure"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/540.html"},
			},
			Metadata: map[string]any{
				"cwe":             "CWE-540",
				"pattern":         "nuxt-source-map",
				"map_retrieved":   false,
				"content_checked": false,
			},
		})
	}

	return results, nil
}

// extractState extracts the state data from a blob definition.
func extractState(body string, blob nuxtStateBlob) string {
	idx := strings.Index(body, blob.start)
	if idx == -1 {
		return ""
	}
	start := idx + len(blob.start)
	remaining := body[start:]

	endIdx := strings.Index(remaining, blob.end)
	if endIdx == -1 {
		// Limit extraction to avoid processing huge chunks
		if len(remaining) > 50000 {
			remaining = remaining[:50000]
		}
		return remaining
	}

	return remaining[:endIdx]
}
