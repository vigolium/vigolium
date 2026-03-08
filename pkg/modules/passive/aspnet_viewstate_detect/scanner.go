package aspnet_viewstate_detect

import (
	"encoding/base64"
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

var viewstateValueRe = regexp.MustCompile(`name="__VIEWSTATE"[^>]*value="([^"]*)"`)

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
		ds: dedup.LazyDiskSet("aspnet_viewstate_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
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

	body := ctx.Response().BodyToString()

	// Check for ViewState presence
	if !strings.Contains(body, "__VIEWSTATE") {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Extract ViewState value
	vsMatch := viewstateValueRe.FindStringSubmatch(body)
	if len(vsMatch) > 1 {
		vsValue := vsMatch[1]
		vsLen := len(vsValue)

		// Check if ViewState is unencrypted
		// Encrypted ViewState typically starts with /wEP (base64 for encrypted prefix)
		if vsLen > 0 {
			decoded, err := base64.StdEncoding.DecodeString(vsValue)
			if err == nil && len(decoded) > 2 {
				// Check for encryption: encrypted ViewState starts with bytes 0xFF 0x01 0x10 (base64: /wEQ)
				// or the purpose-prefixed format. Unencrypted starts with 0xFF 0x01 followed by serialized data
				isEncrypted := strings.HasPrefix(vsValue, "/wEP") || strings.HasPrefix(vsValue, "/wEQ")
				if !isEncrypted && vsLen > 20 {
					results = append(results, &output.ResultEvent{
						ModuleID: ModuleID,
						Host:     host,
						URL:      urlx.String(),
						Matched:  urlx.String(),
						ExtractedResults: []string{
							"ViewState appears unencrypted",
							fmt.Sprintf("ViewState size: %d bytes", vsLen),
						},
						Info: output.Info{
							Name:        "ASP.NET ViewState Not Encrypted",
							Description: "The ASP.NET ViewState is not encrypted, potentially exposing application state data to clients. ViewState may contain sensitive information that should be protected.",
							Severity:    severity.Low,
							Confidence:  severity.Firm,
							Tags:        []string{"aspnet", "viewstate", "encryption", "information-disclosure"},
							Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.viewstateencryptionmode"},
						},
					})
				}
			}
		}

		// Flag large ViewState (>4KB base64 = ~3KB decoded)
		if vsLen > 4096 {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("ViewState size: %d bytes (base64)", vsLen),
				},
				Info: output.Info{
					Name:        "ASP.NET Large ViewState Detected",
					Description: fmt.Sprintf("The ASP.NET ViewState is %d bytes (base64-encoded), which may indicate sensitive data stored in the ViewState payload.", vsLen),
					Severity:    severity.Info,
					Confidence:  severity.Firm,
					Tags:        []string{"aspnet", "viewstate", "performance", "information-disclosure"},
				},
			})
		}
	}

	// Check for missing EventValidation on pages with ViewState
	hasViewState := strings.Contains(body, `name="__VIEWSTATE"`)
	hasPostBack := strings.Contains(body, "__doPostBack(") || strings.Contains(body, `method="post"`)
	hasEventValidation := strings.Contains(body, "__EVENTVALIDATION")

	if hasViewState && hasPostBack && !hasEventValidation {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				"Missing __EVENTVALIDATION on postback form",
			},
			Info: output.Info{
				Name:        "ASP.NET EventValidation Missing",
				Description: "The page has ViewState and postback functionality but lacks EventValidation, which helps prevent parameter tampering attacks.",
				Severity:    severity.Low,
				Confidence:  severity.Firm,
				Tags:        []string{"aspnet", "viewstate", "event-validation", "tampering"},
				Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.enableeventvalidation"},
			},
		})
	}

	// Check for missing anti-CSRF token on forms with ViewState
	hasRequestVerification := strings.Contains(body, "__RequestVerificationToken")
	if hasViewState && hasPostBack && !hasRequestVerification {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				"Missing __RequestVerificationToken on postback form",
			},
			Info: output.Info{
				Name:        "ASP.NET Anti-CSRF Token Missing",
				Description: "The page has a postback form but lacks __RequestVerificationToken, indicating the anti-forgery token is not implemented.",
				Severity:    severity.Low,
				Confidence:  severity.Tentative,
				Tags:        []string{"aspnet", "csrf", "anti-forgery"},
				Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks"},
			},
		})
	}

	return results, nil
}
