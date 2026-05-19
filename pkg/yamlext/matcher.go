package yamlext

import (
	"regexp"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// EvalMatcher evaluates a single matcher against a response.
// Returns (matched, matchedValue).
func EvalMatcher(m *MatcherDef, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	matched, value := evalMatcherInner(m, resp, ctx)
	if m.Negate {
		return !matched, value
	}
	return matched, value
}

func evalMatcherInner(m *MatcherDef, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	matchType := m.Type
	if matchType == "" {
		matchType = "body"
	}

	switch matchType {
	case "body":
		return evalBodyMatcher(m, resp, ctx)
	case "header":
		return evalHeaderMatcher(m, resp, ctx)
	case "status":
		return evalStatusMatcher(m, resp)
	case "js":
		return evalJSMatcher(m, resp)
	default:
		return false, ""
	}
}

func evalBodyMatcher(m *MatcherDef, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	if resp == nil {
		return false, ""
	}
	body := resp.BodyToString()

	if m.Contains != "" {
		needle := Render(m.Contains, ctx)
		if strings.Contains(body, needle) {
			return true, needle
		}
		return false, ""
	}

	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return false, ""
		}
		match := re.FindString(body)
		if match != "" {
			return true, match
		}
		return false, ""
	}

	return false, ""
}

func evalHeaderMatcher(m *MatcherDef, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	if resp == nil || m.Name == "" {
		return false, ""
	}

	headerVal, found := httpmsg.FindHttpHeader(resp.Headers(), m.Name)
	if !found {
		return false, ""
	}

	// Header exists — if no contains/regex, just check existence
	if m.Contains == "" && m.Regex == "" {
		return true, m.Name + ": " + headerVal
	}

	if m.Contains != "" {
		needle := Render(m.Contains, ctx)
		if strings.Contains(headerVal, needle) {
			return true, m.Name + ": " + headerVal
		}
		return false, ""
	}

	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return false, ""
		}
		match := re.FindString(headerVal)
		if match != "" {
			return true, m.Name + ": " + headerVal
		}
		return false, ""
	}

	return false, ""
}

func evalStatusMatcher(m *MatcherDef, resp *httpmsg.HttpResponse) (bool, string) {
	if resp == nil || len(m.Codes) == 0 {
		return false, ""
	}
	status := resp.StatusCode()
	for _, code := range m.Codes {
		if status == code {
			return true, ""
		}
	}
	return false, ""
}

func evalJSMatcher(m *MatcherDef, resp *httpmsg.HttpResponse) (bool, string) {
	if m.Code == "" {
		return false, ""
	}

	vm := sobek.New()

	// Set up response object in scope
	respObj := vm.NewObject()
	if resp != nil {
		_ = respObj.Set("status", resp.StatusCode())
		_ = respObj.Set("body", resp.BodyToString())

		headersObj := vm.NewObject()
		for _, h := range resp.Headers() {
			_ = headersObj.Set(h.Name, h.Value)
		}
		_ = respObj.Set("headers", headersObj)
	}
	_ = vm.Set("response", respObj)

	result, err := vm.RunString(m.Code)
	if err != nil {
		return false, ""
	}

	if result == nil || sobek.IsUndefined(result) || sobek.IsNull(result) {
		return false, ""
	}

	return result.ToBoolean(), result.String()
}

// EvalMatchers evaluates multiple matchers with AND/OR logic.
// Default condition is "or".
func EvalMatchers(matchers []MatcherDef, condition string, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	if len(matchers) == 0 {
		return false, ""
	}

	isAnd := strings.ToLower(strings.TrimSpace(condition)) == "and"

	var lastValue string
	for i := range matchers {
		matched, value := EvalMatcher(&matchers[i], resp, ctx)
		if matched {
			lastValue = value
		}

		if isAnd {
			if !matched {
				return false, ""
			}
		} else {
			// OR: first match wins
			if matched {
				return true, value
			}
		}
	}

	if isAnd {
		return true, lastValue
	}
	return false, ""
}

// EvalRuleMatch evaluates a rule's match conditions against a response.
func EvalRuleMatch(match *RuleMatchDef, resp *httpmsg.HttpResponse, ctx *TemplateContext) (bool, string) {
	if resp == nil {
		return false, ""
	}

	// Check response_header
	if match.ResponseHeader != "" {
		headerVal, found := httpmsg.FindHttpHeader(resp.Headers(), match.ResponseHeader)
		if !found {
			return false, ""
		}

		// If regex or contains specified, check value
		if match.Regex != "" {
			re, err := regexp.Compile(match.Regex)
			if err != nil {
				return false, ""
			}
			m := re.FindString(headerVal)
			if m == "" {
				return false, ""
			}
			return true, match.ResponseHeader + ": " + headerVal
		}
		if match.Contains != "" {
			needle := Render(match.Contains, ctx)
			if !strings.Contains(headerVal, needle) {
				return false, ""
			}
			return true, match.ResponseHeader + ": " + headerVal
		}

		// Header exists is enough
		return true, match.ResponseHeader + ": " + headerVal
	}

	// Check body_contains
	if match.BodyContains != "" {
		body := resp.BodyToString()
		needle := Render(match.BodyContains, ctx)
		if strings.Contains(body, needle) {
			return true, needle
		}
		return false, ""
	}

	// Check body_regex
	if match.BodyRegex != "" {
		body := resp.BodyToString()
		re, err := regexp.Compile(match.BodyRegex)
		if err != nil {
			return false, ""
		}
		m := re.FindString(body)
		if m != "" {
			return true, m
		}
		return false, ""
	}

	// Check status codes
	if len(match.Status) > 0 {
		status := resp.StatusCode()
		for _, code := range match.Status {
			if status == code {
				return true, ""
			}
		}
		return false, ""
	}

	return false, ""
}
