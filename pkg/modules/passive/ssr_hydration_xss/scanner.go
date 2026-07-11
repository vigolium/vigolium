package ssr_hydration_xss

import (
	"fmt"
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

var (
	scriptOpenPattern  = regexp.MustCompile(`(?is)<script\b[^>]*>`)
	scriptClosePattern = regexp.MustCompile(`(?is)</script\s*>`)
	hydrationPrefix    = regexp.MustCompile(`(?is)^\s*(?:self\.__next_f\.push\s*\(|(?:window\.)?__NEXT_DATA__\s*=|window\.__(?:PRELOADED_STATE|INITIAL_STATE|APOLLO_STATE|NUXT)__\s*=|window\.__remixContext\s*=)`)
)

const suspiciousTailLimit = 1024

type hydrationBreakout struct {
	content        string
	tail           string
	reflectedParam string
}

// Module implements the SSR hydration XSS passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new SSR Hydration XSS Detection module.
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
		ds: dedup.LazyDiskSet("ssr_hydration_xss"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil || len(ctx.Response().Body()) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html")
}

// ScanPerRequest looks for a hydration serialization cut off while inside a
// string or bracketed value at the browser's first </script> boundary, followed
// by executable HTML. Raw '<' in an otherwise valid JSON string is not enough:
// it does not escape the script element unless it forms an end-tag sequence.
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

	breakouts := findHydrationBreakouts(ctx.Response().BodyToString(), extractParamValues(ctx))
	if len(breakouts) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	breakout := breakouts[0]
	sev := severity.Medium
	confidence := severity.Tentative
	description := "A hydration serialization ends inside a quoted or bracketed value at a script end-tag boundary, and executable markup follows. This is a passive XSS candidate; replay with a fresh marker is required to prove attacker control."
	if breakout.reflectedParam != "" {
		sev = severity.High
		confidence = severity.Firm
		description = fmt.Sprintf("Request parameter %q containing a script-end sequence is reflected across a truncated hydration script boundary and followed by executable markup. Browser execution still requires active confirmation.", breakout.reflectedParam)
	}

	extracted := []string{
		"truncated_hydration=" + modkit.Truncate(breakout.content, 220),
		"executable_tail=" + modkit.Truncate(breakout.tail, 220),
	}
	if breakout.reflectedParam != "" {
		extracted = append(extracted, "reflected_parameter="+breakout.reflectedParam)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindCandidate,
		EvidenceGrade:    output.EvidenceGradeCandidate,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Hydration Serialization Truncated by Script Boundary",
			Description: description,
			Severity:    sev,
			Confidence:  confidence,
			Tags:        []string{"xss", "ssr", "hydration", "json-injection"},
			Reference:   []string{"https://html.spec.whatwg.org/multipage/scripting.html#restrictions-for-contents-of-script-elements", "https://cwe.mitre.org/data/definitions/79.html"},
		},
		Metadata: map[string]any{
			"cwe":                 "CWE-79",
			"reflected_param":     breakout.reflectedParam,
			"confirmation_needed": "fresh-marker replay and browser execution",
		},
	}}, nil
}

func findHydrationBreakouts(body string, paramValues map[string]string) []hydrationBreakout {
	var results []hydrationBreakout
	offset := 0
	for offset < len(body) {
		open := scriptOpenPattern.FindStringIndex(body[offset:])
		if open == nil {
			break
		}
		openStart := offset + open[0]
		contentStart := offset + open[1]
		closeMatch := scriptClosePattern.FindStringIndex(body[contentStart:])
		if closeMatch == nil {
			break
		}
		closeStart := contentStart + closeMatch[0]
		closeEnd := contentStart + closeMatch[1]
		openTag := body[openStart:contentStart]
		content := body[contentStart:closeStart]

		if isHydrationScript(openTag, content) && serializationAppearsTruncated(content) {
			tailEnd := closeEnd + suspiciousTailLimit
			if tailEnd > len(body) {
				tailEnd = len(body)
			}
			tail := body[closeEnd:tailEnd]
			if containsExecutableMarkup(tail) {
				results = append(results, hydrationBreakout{
					content:        content,
					tail:           tail,
					reflectedParam: reflectedBreakoutParameter(body[openStart:tailEnd], paramValues),
				})
			}
		}
		offset = closeEnd
	}
	return results
}

func isHydrationScript(openTag, content string) bool {
	attrs := parseScriptAttributes(openTag)
	id := strings.ToUpper(strings.TrimSpace(attrs["id"]))
	if id == "__NEXT_DATA__" || id == "__NUXT_DATA__" {
		return true
	}
	return hydrationPrefix.MatchString(content)
}

func parseScriptAttributes(openTag string) map[string]string {
	tokenizer := html.NewTokenizer(strings.NewReader(openTag))
	if tokenizer.Next() != html.StartTagToken {
		return nil
	}
	token := tokenizer.Token()
	attrs := make(map[string]string, len(token.Attr))
	for _, attr := range token.Attr {
		attrs[strings.ToLower(attr.Key)] = attr.Val
	}
	return attrs
}

// serializationAppearsTruncated is deliberately lexical. It does not claim to
// parse arbitrary JavaScript; it only asks whether the script boundary arrived
// while a quoted value or (), [], or {} group was still open.
func serializationAppearsTruncated(content string) bool {
	var stack []byte
	var quote byte
	escaped := false

	for i := 0; i < len(content); i++ {
		char := content[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}

		switch char {
		case '\'', '"', '`':
			quote = char
		case '(', '[', '{':
			stack = append(stack, char)
		case ')', ']', '}':
			if len(stack) == 0 || !matchingDelimiter(stack[len(stack)-1], char) {
				continue
			}
			stack = stack[:len(stack)-1]
		}
	}
	return quote != 0 || escaped || len(stack) > 0
}

func matchingDelimiter(open, close byte) bool {
	return open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}'
}

func containsExecutableMarkup(tail string) bool {
	tokenizer := html.NewTokenizer(strings.NewReader(tail))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			return false
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		attrs := make(map[string]string, len(token.Attr))
		for _, attr := range token.Attr {
			key := strings.ToLower(attr.Key)
			value := strings.TrimSpace(attr.Val)
			attrs[key] = value
			if strings.HasPrefix(key, "on") && len(key) > 2 && value != "" {
				return true
			}
			if (key == "href" || key == "src" || key == "action" || key == "formaction") && strings.HasPrefix(strings.ToLower(value), "javascript:") {
				return true
			}
		}
		if token.Data == "script" && strings.TrimSpace(attrs["src"]) == "" {
			return true
		}
		if token.Data == "iframe" && strings.TrimSpace(attrs["srcdoc"]) != "" {
			return true
		}
	}
}

func reflectedBreakoutParameter(region string, paramValues map[string]string) string {
	regionLower := strings.ToLower(region)
	for param, value := range paramValues {
		value = strings.TrimSpace(value)
		if len(value) < 8 || !strings.Contains(strings.ToLower(value), "</script") {
			continue
		}
		if strings.Contains(regionLower, strings.ToLower(value)) {
			return param
		}
	}
	return ""
}

// extractParamValues collects parameter values from the request URL query.
func extractParamValues(ctx *httpmsg.HttpRequestResponse) map[string]string {
	params := make(map[string]string)
	urlx, err := ctx.URL()
	if err != nil {
		return params
	}
	if urlx.Params != nil {
		urlx.Params.Iterate(func(key string, values []string) bool {
			if len(values) > 0 {
				value := values[0]
				for range 2 {
					decoded, decodeErr := url.QueryUnescape(value)
					if decodeErr != nil || decoded == value {
						break
					}
					value = decoded
				}
				params[key] = value
			}
			return true
		})
	}
	return params
}
