package mixed_content_detect

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"golang.org/x/net/html"
)

const maxExamples = 10

var cssHTTPURLPattern = regexp.MustCompile(`(?i)(?:url\(|@import\s+)[\s"']*(http://[^\s"') ;]+)`)

type mixedReferences struct {
	blockable   []string
	upgradeable []string
	forms       []string
	sensitive   bool
}

// Module implements the Mixed Content Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Mixed Content Detect module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("passive_mixed_content_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) RequiredContentClasses() []string { return []string{"html"} }

// ScanPerRequest distinguishes loaded subresources from top-level navigation.
// Ordinary <a href=http://...> links are not mixed content. HTTP form actions
// are reported separately as a submission downgrade rather than being labeled
// mixed content.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !strings.EqualFold(urlx.Scheme, "https") || utils.IsMediaAndJSURL(urlx.Path) || ctx.Response() == nil {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html") {
		return nil, nil
	}

	pageURL, err := url.Parse(urlx.String())
	if err != nil {
		return nil, nil
	}
	references := classifyMixedReferences(ctx.Response().BodyToString(), pageURL)
	if len(references.blockable) == 0 && len(references.upgradeable) == 0 && len(references.forms) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	base := output.ResultEvent{
		ModuleID: ModuleID,
		Host:     urlx.Host,
		URL:      urlx.String(),
		Matched:  urlx.String(),
		Request:  string(ctx.Request().Raw()),
	}
	var results []*output.ResultEvent

	if len(references.blockable) > 0 {
		result := base
		result.RecordKind = output.RecordKindCandidate
		result.EvidenceGrade = output.EvidenceGradeCandidate
		result.ExtractedResults = references.blockable
		result.Info = output.Info{
			Name:        "HTTPS Page References Blockable HTTP Subresource",
			Description: fmt.Sprintf("The page references %d executable or embedded subresource(s) over HTTP. Modern browsers normally block these requests, so this is a deployment candidate rather than proof that attacker-controlled content executed.", len(references.blockable)),
			Severity:    severity.Low,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		}
		result.Metadata = map[string]any{"mixed_content_class": "blockable", "browser_behavior": "normally blocked"}
		results = append(results, &result)
	}

	if len(references.upgradeable) > 0 {
		result := base
		result.RecordKind = output.RecordKindObservation
		result.EvidenceGrade = output.EvidenceGradeObservation
		result.ExtractedResults = references.upgradeable
		result.Info = output.Info{
			Name:        "HTTPS Page References Upgradeable HTTP Media",
			Description: fmt.Sprintf("The page references %d image, audio, or video resource(s) with HTTP URLs. Current browsers generally upgrade these requests to HTTPS or block them; this is an informational deployment observation.", len(references.upgradeable)),
			Severity:    severity.Info,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		}
		result.Metadata = map[string]any{"mixed_content_class": "upgradeable", "browser_behavior": "auto-upgraded or blocked"}
		results = append(results, &result)
	}

	if len(references.forms) > 0 {
		result := base
		result.ExtractedResults = references.forms
		result.RecordKind = output.RecordKindObservation
		result.EvidenceGrade = output.EvidenceGradeObservation
		sev := severity.Low
		kindDescription := "The page contains a form that submits to HTTP. This is a separate transport-downgrade observation, not mixed content."
		if references.sensitive {
			result.RecordKind = output.RecordKindCandidate
			result.EvidenceGrade = output.EvidenceGradeCandidate
			sev = severity.Medium
			kindDescription = "The page contains a POST or credential-bearing form that submits to HTTP, potentially exposing submitted data in transit. Submission and server handling should be verified."
		}
		result.Info = output.Info{
			Name:        "HTTPS Form Submits to HTTP",
			Description: kindDescription,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        append(append([]string{}, ModuleTags...), "form-downgrade"),
		}
		result.Metadata = map[string]any{"classification": "insecure-form-submission", "sensitive_form": references.sensitive}
		results = append(results, &result)
	}

	return results, nil
}

func classifyMixedReferences(body string, pageURL *url.URL) mixedReferences {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return mixedReferences{}
	}

	result := mixedReferences{}
	seenBlockable := make(map[string]bool)
	seenUpgradeable := make(map[string]bool)
	seenForms := make(map[string]bool)

	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			attrs := mixedAttributeMap(node.Attr)
			switch node.Data {
			case "script", "iframe", "embed", "track":
				addHTTPReference(&result.blockable, seenBlockable, node.Data+" src", attrs["src"], pageURL)
			case "object":
				addHTTPReference(&result.blockable, seenBlockable, "object data", attrs["data"], pageURL)
			case "link":
				classifyLinkReference(&result, seenBlockable, seenUpgradeable, attrs, pageURL)
			case "img":
				addHTTPReference(&result.upgradeable, seenUpgradeable, "img src", attrs["src"], pageURL)
				addSrcsetReferences(&result.upgradeable, seenUpgradeable, "img srcset", attrs["srcset"], pageURL)
			case "audio", "video", "source":
				addHTTPReference(&result.upgradeable, seenUpgradeable, node.Data+" src", attrs["src"], pageURL)
				addSrcsetReferences(&result.upgradeable, seenUpgradeable, node.Data+" srcset", attrs["srcset"], pageURL)
				if node.Data == "video" {
					addHTTPReference(&result.upgradeable, seenUpgradeable, "video poster", attrs["poster"], pageURL)
				}
			case "input":
				if strings.EqualFold(attrs["type"], "image") {
					addHTTPReference(&result.upgradeable, seenUpgradeable, "input src", attrs["src"], pageURL)
				}
				classifyFormActionOverride(&result, seenForms, node, attrs, pageURL)
			case "button":
				classifyFormActionOverride(&result, seenForms, node, attrs, pageURL)
			case "form":
				if raw := attrs["action"]; isInsecureHTTPURL(raw, pageURL) {
					entry := "form action=" + raw
					appendUnique(&result.forms, seenForms, entry)
					if strings.EqualFold(attrs["method"], "post") || formContainsSensitiveControl(node) {
						result.sensitive = true
					}
				}
			}

			for _, match := range cssHTTPURLPattern.FindAllStringSubmatch(attrs["style"], -1) {
				addHTTPReference(&result.blockable, seenBlockable, "style url", match[1], pageURL)
			}
			if node.Data == "style" && node.FirstChild != nil {
				for _, match := range cssHTTPURLPattern.FindAllStringSubmatch(node.FirstChild.Data, -1) {
					addHTTPReference(&result.blockable, seenBlockable, "style url", match[1], pageURL)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return result
}

func classifyLinkReference(result *mixedReferences, blockableSeen, upgradeableSeen map[string]bool, attrs map[string]string, pageURL *url.URL) {
	rel := mixedTokenSet(attrs["rel"])
	href := attrs["href"]
	switch {
	case rel["stylesheet"], rel["modulepreload"], rel["preload"] && attrs["as"] != "image":
		addHTTPReference(&result.blockable, blockableSeen, "link href", href, pageURL)
	case rel["icon"], rel["apple-touch-icon"], rel["preload"] && attrs["as"] == "image":
		addHTTPReference(&result.upgradeable, upgradeableSeen, "link href", href, pageURL)
	}
}

func classifyFormActionOverride(result *mixedReferences, seen map[string]bool, node *html.Node, attrs map[string]string, pageURL *url.URL) {
	if raw := attrs["formaction"]; isInsecureHTTPURL(raw, pageURL) {
		appendUnique(&result.forms, seen, "control formaction="+raw)
		method := attrs["formmethod"]
		form := nearestAncestorForm(node)
		if method == "" && form != nil {
			method = mixedAttributeMap(form.Attr)["method"]
		}
		if strings.EqualFold(method, "post") || (form != nil && formContainsSensitiveControl(form)) {
			result.sensitive = true
		}
	}
}

func nearestAncestorForm(node *html.Node) *html.Node {
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == "form" {
			return parent
		}
	}
	return nil
}

func formContainsSensitiveControl(form *html.Node) bool {
	var sensitive bool
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if sensitive {
			return
		}
		if node != form && node.Type == html.ElementNode && node.Data == "form" {
			return
		}
		if node.Type == html.ElementNode && (node.Data == "input" || node.Data == "textarea") {
			attrs := mixedAttributeMap(node.Attr)
			identity := strings.ToLower(attrs["name"] + " " + attrs["id"])
			if strings.EqualFold(attrs["type"], "password") {
				sensitive = true
				return
			}
			for _, marker := range []string{"password", "passwd", "secret", "token", "credit", "card", "cvv", "cvc"} {
				if strings.Contains(identity, marker) {
					sensitive = true
					return
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(form)
	return sensitive
}

func addSrcsetReferences(dst *[]string, seen map[string]bool, context, raw string, pageURL *url.URL) {
	for _, candidate := range strings.Split(raw, ",") {
		fields := strings.Fields(candidate)
		if len(fields) > 0 {
			addHTTPReference(dst, seen, context, fields[0], pageURL)
		}
	}
}

func addHTTPReference(dst *[]string, seen map[string]bool, context, raw string, pageURL *url.URL) {
	if !isInsecureHTTPURL(raw, pageURL) || len(*dst) >= maxExamples {
		return
	}
	appendUnique(dst, seen, context+"="+raw)
}

func appendUnique(dst *[]string, seen map[string]bool, value string) {
	if value == "" || seen[value] || len(*dst) >= maxExamples {
		return
	}
	seen[value] = true
	*dst = append(*dst, value)
}

func isInsecureHTTPURL(raw string, pageURL *url.URL) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || pageURL == nil {
		return false
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return false
	}
	resolved := pageURL.ResolveReference(reference)
	return strings.EqualFold(resolved.Scheme, "http") && !isPotentiallyTrustworthyHTTPHost(resolved.Hostname())
}

func isPotentiallyTrustworthyHTTPHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func mixedAttributeMap(attrs []html.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		result[strings.ToLower(attr.Key)] = strings.TrimSpace(attr.Val)
	}
	return result
}

func mixedTokenSet(raw string) map[string]bool {
	result := make(map[string]bool)
	for _, token := range strings.Fields(strings.ToLower(raw)) {
		result[token] = true
	}
	return result
}
