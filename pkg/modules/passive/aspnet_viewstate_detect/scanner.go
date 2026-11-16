package aspnet_viewstate_detect

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/viewstateutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/vulnclass"
)

var viewstateValueRe = regexp.MustCompile(`name="__VIEWSTATE"[^>]*value="([^"]*)"`)

// viewstateGeneratorRe reads the __VIEWSTATEGENERATOR hidden field: the page's
// client-state identifier as eight hex digits (Page.cs renders it with "X8"),
// the modifier the legacy ViewState MAC covers.
var viewstateGeneratorRe = regexp.MustCompile(`name="__VIEWSTATEGENERATOR"[^>]*value="([0-9A-Fa-f]{8})"`)

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
	body := ctx.Response().BodyToString()

	// Check for ViewState presence
	if !strings.Contains(body, "__VIEWSTATE") {
		return nil, nil
	}

	// The known-key check keeps its own per-host claim: the host claim below
	// is taken by the first page with any configuration finding, and a later
	// page may be the first whose ViewState can be checked.
	keyClaim := "known-key:" + host
	checkKey := diskSet == nil || !diskSet.Contains(keyClaim)
	checkHost := diskSet == nil || !diskSet.Contains(host)
	if !checkKey && !checkHost {
		return nil, nil
	}

	// Extract the ViewState value once for both checks.
	vsMatch := viewstateValueRe.FindStringSubmatch(body)

	var keyResults []*output.ResultEvent
	if checkKey && len(vsMatch) > 1 {
		if ev := m.knownKeyFinding(ctx, body, vsMatch[1], host, urlx.String()); ev != nil {
			if diskSet == nil || diskSet.ClaimOnMatch(keyClaim) {
				keyResults = append(keyResults, ev)
			}
		}
	}

	if !checkHost {
		return keyResults, nil
	}

	var results []*output.ResultEvent

	if len(vsMatch) > 1 {
		vsValue := vsMatch[1]
		vsLen := len(vsValue)

		// Unencrypted ViewState is the plain ObjectStateFormatter stream: it opens
		// with the formatter header 0xFF 0x01 whatever type token follows (/wEP is
		// a Pair, /wEQ a Triplet, /wEW an array). Ciphertext carries no header.
		if vsLen > 0 {
			decoded, err := base64.StdEncoding.DecodeString(vsValue)
			if err == nil && len(decoded) > 2 {
				if viewstateutil.IsSerialized(decoded) && vsLen > 20 {
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
				Severity:    severity.Suspect,
				Confidence:  severity.Tentative,
				Tags:        []string{"aspnet", "csrf", "anti-forgery"},
				Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks"},
			},
		})
	}

	// Claim the host only now that it matched: a host whose
	// first response showed nothing stays open for later responses.
	if len(results) > 0 && diskSet != nil && !diskSet.ClaimOnMatch(host) {
		return keyResults, nil
	}
	return append(keyResults, results...), nil
}

// knownKeyFinding recomputes the page's legacy ViewState MAC (vs is the
// __VIEWSTATE value) under every published key, offline. It needs an
// unencrypted ViewState carrying a MAC and the __VIEWSTATEGENERATOR modifier;
// anything else is not checkable and yields nil. The embedded key list is a
// handful of keys, so the check costs a few HMACs over the ViewState and is
// not memoised.
func (m *Module) knownKeyFinding(ctx *httpmsg.HttpRequestResponse, body, vs, host, pageURL string) *output.ResultEvent {
	// An encrypted ViewState carries no ObjectStateFormatter header: skip it
	// before decoding the whole value.
	if !viewstateutil.HasSerializedHeader(vs) {
		return nil
	}
	gen := viewstateGeneratorRe.FindStringSubmatch(body)
	if len(gen) < 2 {
		return nil
	}
	keys, err := viewstateutil.PublishedKeys()
	if err != nil || len(keys) == 0 {
		return nil
	}
	decoded, err := viewstateutil.DecodeViewState(vs)
	if err != nil {
		return nil
	}
	modifier, err := viewstateutil.GeneratorModifier(gen[1])
	if err != nil {
		return nil
	}
	match, ok := viewstateutil.CrackLegacy(decoded, modifier, keys)
	if !ok {
		return nil
	}
	keyHex := match.Key.Hex()
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindFinding,
		EvidenceGrade: output.EvidenceGradeImpact,
		VulnClass:     string(vulnclass.Deserialization),
		Host:          host,
		URL:           pageURL,
		Matched:       pageURL,
		Request:       string(ctx.Request().Raw()),
		Response:      string(ctx.Response().Raw()),
		ExtractedResults: []string{
			fmt.Sprintf("Validation algorithm: %s (legacy, pre-4.5 MAC)", match.Algorithm),
			fmt.Sprintf("__VIEWSTATEGENERATOR: %s", strings.ToUpper(gen[1])),
			fmt.Sprintf("Published validationKey: %s… (%d bytes)", keyHex[:16], len(match.Key.ValidationKey)),
			"Key source: " + match.Key.Source,
		},
		Info: output.Info{
			Name: "ASP.NET ViewState Signed with a Published machineKey",
			Description: fmt.Sprintf("The page's __VIEWSTATE MAC recomputes, offline, under a publicly documented validationKey "+
				"(%s) with %s in the legacy (pre-4.5) MAC mode. Anyone holding that key can sign a ViewState the server "+
				"accepts, and a forged ViewState is deserialized by ObjectStateFormatter, which leads to remote code "+
				"execution. The check covers only the legacy MAC with the __VIEWSTATEGENERATOR modifier; a 4.5+ "+
				"purpose-based MAC, MD5 validation, a ViewStateUserKey or an encrypted ViewState is not tested, so a "+
				"page without this finding is not shown to use a private key.", match.Key.Source, match.Algorithm),
			Severity:   severity.Critical,
			Confidence: severity.Certain,
			Tags:       []string{"aspnet", "viewstate", "machinekey", "deserialization", "rce"},
			Reference: []string{
				"https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/w8h3skw9(v=vs.100)",
				"https://support.microsoft.com/en-us/topic/resolving-view-state-message-authentication-code-mac-errors-6c0e9fd3-f8a8-c953-8fbe-ce840446a9f3",
			},
		},
		Metadata: map[string]any{
			"validation_algorithm":       match.Algorithm,
			"key_source":                 match.Key.Source,
			"viewstate_generator":        strings.ToUpper(gen[1]),
			"mac_mode":                   "legacy",
			"signature_verified":         true,
			"purpose_based_mac_tested":   false,
			"server_acceptance_tested":   false,
			"view_state_user_key_tested": false,
		},
	}
}
