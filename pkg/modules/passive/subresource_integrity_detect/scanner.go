package subresource_integrity_detect

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"golang.org/x/net/html"
)

const maxExamples = 10

// Module implements the Subresource Integrity Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Subresource Integrity Detect module.
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
		ds: dedup.LazyDiskSet("passive_subresource_integrity_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	return strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html")
}

// ScanPerRequest records an informational supply-chain hardening observation
// for truly cross-origin executable resources without usable integrity metadata.
// An absolute URL is not external merely because it is absolute: origin includes
// scheme, hostname, and effective port.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil || ctx.Response() == nil {
		return nil, nil
	}
	pageURL, err := url.Parse(urlx.String())
	if err != nil {
		return nil, nil
	}

	missing := resourcesWithoutSRI(ctx.Response().BodyToString(), pageURL)
	if len(missing) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: missing,
		Info: output.Info{
			Name:        "Cross-Origin Executable Resource Without Valid SRI",
			Description: fmt.Sprintf("Found %d cross-origin script or stylesheet reference(s) without valid Subresource Integrity metadata. This is a supply-chain hardening observation, not proof that the provider or resource is compromised; SRI is most appropriate for immutable, version-pinned assets.", len(missing)),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{
			"resource_count":  len(missing),
			"security_impact": "third-party compromise not established",
		},
	}}, nil
}

func resourcesWithoutSRI(body string, pageURL *url.URL) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	baseURL := documentBaseURL(doc, pageURL)
	seen := make(map[string]bool)
	var missing []string

	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if len(missing) >= maxExamples {
			return
		}
		if node.Type == html.ElementNode {
			attrs := sriAttributeMap(node.Attr)
			resource := ""
			kind := ""
			switch node.Data {
			case "script":
				if isExecutableScriptType(attrs["type"]) {
					resource, kind = attrs["src"], "script"
				}
			case "link":
				if sriTokenSet(attrs["rel"])["stylesheet"] {
					resource, kind = attrs["href"], "stylesheet"
				}
			}

			if resource != "" && isCrossOriginResource(resource, baseURL, pageURL) && !hasValidIntegrity(attrs["integrity"]) {
				key := kind + "\x00" + resource
				if !seen[key] {
					seen[key] = true
					status := "missing integrity"
					if strings.TrimSpace(attrs["integrity"]) != "" {
						status = "invalid integrity"
					}
					missing = append(missing, fmt.Sprintf("%s: %s (%s)", kind, resource, status))
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return missing
}

func documentBaseURL(doc *html.Node, pageURL *url.URL) *url.URL {
	baseURL := pageURL
	var find func(*html.Node) bool
	find = func(node *html.Node) bool {
		if node.Type == html.ElementNode && node.Data == "base" {
			href := sriAttributeMap(node.Attr)["href"]
			if parsed, err := url.Parse(href); err == nil && href != "" {
				baseURL = pageURL.ResolveReference(parsed)
			}
			return true
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if find(child) {
				return true
			}
		}
		return false
	}
	find(doc)
	return baseURL
}

func isCrossOriginResource(raw string, baseURL, pageURL *url.URL) bool {
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || reference.String() == "" || baseURL == nil || pageURL == nil {
		return false
	}
	resolved := baseURL.ResolveReference(reference)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return false
	}
	return sriOrigin(resolved) != sriOrigin(pageURL)
}

func sriOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port
}

func isExecutableScriptType(raw string) bool {
	typeValue := strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
	switch typeValue {
	case "", "module", "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript":
		return true
	default:
		return false
	}
}

func hasValidIntegrity(raw string) bool {
	for _, token := range strings.Fields(raw) {
		// Integrity options follow a '?' and are not part of the digest.
		digestToken := strings.SplitN(token, "?", 2)[0]
		algorithm, encoded, ok := strings.Cut(digestToken, "-")
		if !ok {
			continue
		}
		expected := 0
		switch strings.ToLower(algorithm) {
		case "sha256":
			expected = 32
		case "sha384":
			expected = 48
		case "sha512":
			expected = 64
		default:
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && len(decoded) == expected {
			return true
		}
	}
	return false
}

func sriAttributeMap(attrs []html.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		result[strings.ToLower(attr.Key)] = attr.Val
	}
	return result
}

func sriTokenSet(raw string) map[string]bool {
	result := make(map[string]bool)
	for _, token := range strings.Fields(strings.ToLower(raw)) {
		result[token] = true
	}
	return result
}
