package yamlext

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/stretchr/testify/assert"
)

func makeResponse(status int, headers map[string]string, body string) *httpmsg.HttpResponse {
	raw := fmt.Sprintf("HTTP/1.1 %d OK\r\n", status)
	for k, v := range headers {
		raw += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	raw += "\r\n" + body
	return httpmsg.NewHttpResponse([]byte(raw))
}

func TestEvalMatcher_BodyContains(t *testing.T) {
	resp := makeResponse(200, nil, "hello world canary123 goodbye")
	m := MatcherDef{Type: "body", Contains: "canary123"}
	matched, value := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Equal(t, "canary123", value)
}

func TestEvalMatcher_BodyContains_NoMatch(t *testing.T) {
	resp := makeResponse(200, nil, "hello world")
	m := MatcherDef{Type: "body", Contains: "notfound"}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatcher_BodyContains_WithTemplate(t *testing.T) {
	resp := makeResponse(200, nil, "reflected: CANARY42")
	m := MatcherDef{Type: "body", Contains: "{{payload}}"}
	ctx := &TemplateContext{Payload: "CANARY42"}
	matched, value := EvalMatcher(&m, resp, ctx)
	assert.True(t, matched)
	assert.Equal(t, "CANARY42", value)
}

func TestEvalMatcher_BodyRegex(t *testing.T) {
	resp := makeResponse(200, nil, "error at line 42 in foo.java:123")
	m := MatcherDef{Type: "body", Regex: `foo\.java:\d+`}
	matched, value := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Equal(t, "foo.java:123", value)
}

func TestEvalMatcher_BodyRegex_NoMatch(t *testing.T) {
	resp := makeResponse(200, nil, "all good here")
	m := MatcherDef{Type: "body", Regex: `SQLSTATE\[`}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatcher_HeaderExists(t *testing.T) {
	resp := makeResponse(200, map[string]string{"X-Powered-By": "Express"}, "")
	m := MatcherDef{Type: "header", Name: "X-Powered-By"}
	matched, value := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Contains(t, value, "Express")
}

func TestEvalMatcher_HeaderNotExists(t *testing.T) {
	resp := makeResponse(200, map[string]string{"Content-Type": "text/html"}, "")
	m := MatcherDef{Type: "header", Name: "X-Powered-By"}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatcher_HeaderContains(t *testing.T) {
	resp := makeResponse(200, map[string]string{"Server": "Apache/2.4.51"}, "")
	m := MatcherDef{Type: "header", Name: "Server", Contains: "Apache"}
	matched, value := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Contains(t, value, "Apache/2.4.51")
}

func TestEvalMatcher_HeaderRegex(t *testing.T) {
	resp := makeResponse(200, map[string]string{"Server": "nginx/1.18.0"}, "")
	m := MatcherDef{Type: "header", Name: "Server", Regex: `[0-9]+\.[0-9]+`}
	matched, value := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Contains(t, value, "nginx/1.18.0")
}

func TestEvalMatcher_StatusCodes(t *testing.T) {
	resp := makeResponse(500, nil, "error")
	m := MatcherDef{Type: "status", Codes: []int{500, 502, 503}}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalMatcher_StatusCodes_NoMatch(t *testing.T) {
	resp := makeResponse(200, nil, "ok")
	m := MatcherDef{Type: "status", Codes: []int{500, 502}}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatcher_Negate(t *testing.T) {
	resp := makeResponse(200, nil, "safe content")
	m := MatcherDef{Type: "body", Contains: "error", Negate: true}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched, "negated matcher should be true when content is absent")
}

func TestEvalMatcher_Negate_PresenceBecomeFalse(t *testing.T) {
	resp := makeResponse(200, nil, "has error in body")
	m := MatcherDef{Type: "body", Contains: "error", Negate: true}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched, "negated matcher should be false when content is present")
}

func TestEvalMatcher_JSExpression(t *testing.T) {
	resp := makeResponse(200, nil, `{"admin": true}`)
	m := MatcherDef{Type: "js", Code: `response.body.indexOf('"admin": true') !== -1`}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalMatcher_JSExpression_False(t *testing.T) {
	resp := makeResponse(200, nil, `{"user": "normal"}`)
	m := MatcherDef{Type: "js", Code: `response.body.indexOf('"admin"') !== -1`}
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatcher_DefaultTypeIsBody(t *testing.T) {
	resp := makeResponse(200, nil, "contains needle")
	m := MatcherDef{Contains: "needle"} // Type is empty, defaults to "body"
	matched, _ := EvalMatcher(&m, resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalMatchers_OR_FirstMatchWins(t *testing.T) {
	resp := makeResponse(200, nil, "found second pattern")
	matchers := []MatcherDef{
		{Type: "body", Contains: "not here"},
		{Type: "body", Contains: "second pattern"},
	}
	matched, value := EvalMatchers(matchers, "or", resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Equal(t, "second pattern", value)
}

func TestEvalMatchers_OR_NoneMatch(t *testing.T) {
	resp := makeResponse(200, nil, "nothing interesting")
	matchers := []MatcherDef{
		{Type: "body", Contains: "not here"},
		{Type: "body", Contains: "also not here"},
	}
	matched, _ := EvalMatchers(matchers, "or", resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatchers_AND_AllMatch(t *testing.T) {
	resp := makeResponse(500, nil, "error occurred")
	matchers := []MatcherDef{
		{Type: "body", Contains: "error"},
		{Type: "status", Codes: []int{500}},
	}
	matched, _ := EvalMatchers(matchers, "and", resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalMatchers_AND_OneFailsAll(t *testing.T) {
	resp := makeResponse(200, nil, "error occurred")
	matchers := []MatcherDef{
		{Type: "body", Contains: "error"},
		{Type: "status", Codes: []int{500}},
	}
	matched, _ := EvalMatchers(matchers, "and", resp, &TemplateContext{})
	assert.False(t, matched)
}

func TestEvalMatchers_DefaultIsOR(t *testing.T) {
	resp := makeResponse(200, nil, "has keyword")
	matchers := []MatcherDef{
		{Type: "body", Contains: "keyword"},
	}
	matched, _ := EvalMatchers(matchers, "", resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalRuleMatch_ResponseHeader(t *testing.T) {
	resp := makeResponse(200, map[string]string{"X-Debug": "true"}, "")
	match := RuleMatchDef{ResponseHeader: "X-Debug"}
	matched, value := EvalRuleMatch(&match, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Contains(t, value, "X-Debug")
}

func TestEvalRuleMatch_ResponseHeader_WithRegex(t *testing.T) {
	resp := makeResponse(200, map[string]string{"Server": "Apache/2.4.51"}, "")
	match := RuleMatchDef{ResponseHeader: "Server", Regex: `[0-9]+\.[0-9]+`}
	matched, value := EvalRuleMatch(&match, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Contains(t, value, "Apache/2.4.51")
}

func TestEvalRuleMatch_BodyContains(t *testing.T) {
	resp := makeResponse(200, nil, "some debug_mode=true here")
	match := RuleMatchDef{BodyContains: "debug_mode=true"}
	matched, value := EvalRuleMatch(&match, resp, &TemplateContext{})
	assert.True(t, matched)
	assert.Equal(t, "debug_mode=true", value)
}

func TestEvalRuleMatch_BodyRegex(t *testing.T) {
	resp := makeResponse(200, nil, "Traceback (most recent call last)")
	match := RuleMatchDef{BodyRegex: `(?i)traceback \(most recent`}
	matched, _ := EvalRuleMatch(&match, resp, &TemplateContext{})
	assert.True(t, matched)
}

func TestEvalRuleMatch_Status(t *testing.T) {
	resp := makeResponse(403, nil, "forbidden")
	match := RuleMatchDef{Status: []int{401, 403}}
	matched, _ := EvalRuleMatch(&match, resp, &TemplateContext{})
	assert.True(t, matched)
}
