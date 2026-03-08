package express_fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// nestJSErrorRegex matches the default NestJS error response shape:
// {"statusCode":NNN,"message":"...","error":"..."}
var nestJSErrorRegex = regexp.MustCompile(`\{\s*"statusCode"\s*:\s*\d{3}\s*,\s*"message"\s*:\s*"[^"]*"\s*,\s*"error"\s*:\s*"[^"]*"\s*\}`)

// Module implements the Express/NestJS fingerprinting passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express/NestJS Fingerprint module.
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
		ds: dedup.LazyDiskSet("express_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to fingerprint Express.js and NestJS.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	host := urlx.Host

	// Dedup by host — only fingerprint once
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	hdr := func(name string) string { return ctx.Response().Header(name) }
	statusCode := ctx.Response().StatusCode()

	var results []*output.ResultEvent

	// Signal 1: X-Powered-By: Express header
	poweredBy := hdr("X-Powered-By")
	if strings.EqualFold(poweredBy, "Express") {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				"X-Powered-By: Express",
			},
			Info: output.Info{
				Name:        "Express.js Application Detected",
				Description: "Express.js confirmed via X-Powered-By header",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"express", "node", "fingerprint"},
			},
			Metadata: map[string]any{
				"platform":  "express",
				"detection": "x-powered-by",
			},
		})
	}

	// Signal 2: NestJS default error shape on 4xx/5xx responses
	if statusCode >= 400 && statusCode < 600 {
		ct := strings.ToLower(hdr("Content-Type"))
		if strings.Contains(ct, "application/json") {
			body := ctx.Response().BodyToString()
			if nestJSErrorRegex.MatchString(body) {
				results = append(results, &output.ResultEvent{
					ModuleID: ModuleID,
					Host:     host,
					URL:      urlx.String(),
					Matched:  urlx.String(),
					ExtractedResults: []string{
						fmt.Sprintf("NestJS error shape detected (HTTP %d)", statusCode),
					},
					Info: output.Info{
						Name:        "NestJS Application Detected",
						Description: fmt.Sprintf("NestJS confirmed via default error response shape on HTTP %d", statusCode),
						Severity:    severity.Info,
						Confidence:  severity.Certain,
						Tags:        []string{"nestjs", "express", "node", "fingerprint"},
					},
					Metadata: map[string]any{
						"platform":  "nestjs",
						"detection": "error-shape",
					},
				})
			}
		}
	}

	// Signal 3: connect.sid session cookie
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.Contains(h.Value, "connect.sid=") {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					"Session cookie: connect.sid",
				},
				Info: output.Info{
					Name:        "Express Session Detected",
					Description: "Express session middleware detected via connect.sid cookie",
					Severity:    severity.Info,
					Confidence:  severity.Certain,
					Tags:        []string{"express", "node", "session", "fingerprint"},
				},
				Metadata: map[string]any{
					"platform":  "express",
					"detection": "connect-sid",
				},
			})
			break
		}
	}

	// Signal 4: ETag format — Express default weak ETags (W/"...")
	etag := hdr("ETag")
	if strings.HasPrefix(etag, `W/"`) {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("ETag: %s", etag),
			},
			Info: output.Info{
				Name:        "Express.js Likely (Weak ETag)",
				Description: "Express.js likely detected via default weak ETag format",
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"express", "node", "fingerprint", "etag"},
			},
			Metadata: map[string]any{
				"platform":  "express",
				"detection": "weak-etag",
			},
		})
	}

	return results, nil
}
