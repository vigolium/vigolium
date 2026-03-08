package yamlext

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_Payload(t *testing.T) {
	ctx := &TemplateContext{Payload: "test-value"}
	result := Render("injected: {{payload}}", ctx)
	assert.Equal(t, "injected: test-value", result)
}

func TestRender_Matched(t *testing.T) {
	ctx := &TemplateContext{Matched: "found-it"}
	result := Render("Match: {{matched}}", ctx)
	assert.Equal(t, "Match: found-it", result)
}

func TestRender_Rand(t *testing.T) {
	ctx := &TemplateContext{}
	result := Render("prefix-{{rand(8)}}-suffix", ctx)

	assert.True(t, strings.HasPrefix(result, "prefix-"))
	assert.True(t, strings.HasSuffix(result, "-suffix"))
	// 8 random chars between prefix- and -suffix
	middle := result[len("prefix-") : len(result)-len("-suffix")]
	assert.Len(t, middle, 8)
}

func TestRender_Rand_DifferentEachTime(t *testing.T) {
	ctx := &TemplateContext{}
	r1 := Render("{{rand(16)}}", ctx)
	r2 := Render("{{rand(16)}}", ctx)
	// Extremely unlikely to be equal with 16 random chars
	assert.NotEqual(t, r1, r2)
}

func TestRender_ConfigVar(t *testing.T) {
	ctx := &TemplateContext{
		ConfigVars: map[string]string{
			"auth_token": "secret123",
		},
	}
	result := Render("Bearer {{config.auth_token}}", ctx)
	assert.Equal(t, "Bearer secret123", result)
}

func TestRender_ConfigVar_Missing(t *testing.T) {
	ctx := &TemplateContext{ConfigVars: map[string]string{}}
	result := Render("value: {{config.missing}}", ctx)
	assert.Equal(t, "value: ", result)
}

func TestRender_Insertion(t *testing.T) {
	ctx := &TemplateContext{
		Insertion: &InsertionCtx{
			Name:      "username",
			BaseValue: "admin",
			Type:      "URL_PARAM",
		},
	}
	result := Render("param {{insertion.name}} was {{insertion.base_value}} ({{insertion.type}})", ctx)
	assert.Equal(t, "param username was admin (URL_PARAM)", result)
}

func TestRender_Request(t *testing.T) {
	ctx := &TemplateContext{
		Request: &RequestCtx{
			URL:    "https://example.com/path",
			Method: "POST",
		},
	}
	result := Render("{{request.method}} {{request.url}}", ctx)
	assert.Equal(t, "POST https://example.com/path", result)
}

func TestRender_ResponseHeaders(t *testing.T) {
	ctx := &TemplateContext{
		Response: &ResponseCtx{
			Status: 200,
			Body:   "hello",
			Headers: map[string]string{
				"X-Powered-By": "Express",
			},
		},
	}
	result := Render("Status: {{response.status}}, Tech: {{response.headers.X-Powered-By}}", ctx)
	assert.Equal(t, "Status: 200, Tech: Express", result)
}

func TestRender_UnrecognizedPassthrough(t *testing.T) {
	ctx := &TemplateContext{}
	result := Render("keep {{unknown.token}} intact", ctx)
	assert.Equal(t, "keep {{unknown.token}} intact", result)
}

func TestRender_NilContext(t *testing.T) {
	result := Render("no context {{payload}}", nil)
	assert.Equal(t, "no context {{payload}}", result)
}

func TestRender_NoTemplates(t *testing.T) {
	ctx := &TemplateContext{Payload: "test"}
	result := Render("no templates here", ctx)
	assert.Equal(t, "no templates here", result)
}

func TestRender_Multiple(t *testing.T) {
	ctx := &TemplateContext{
		Payload: "canary",
		Request: &RequestCtx{URL: "https://example.com"},
	}
	result := Render("{{payload}} at {{request.url}}", ctx)
	assert.Equal(t, "canary at https://example.com", result)
}

func TestRender_NilInsertionReturnsEmpty(t *testing.T) {
	ctx := &TemplateContext{}
	result := Render("{{insertion.name}}", ctx)
	assert.Equal(t, "", result)
}

func TestRandomAlphanumeric(t *testing.T) {
	s := randomAlphanumeric(32)
	require.Len(t, s, 32)
	for _, c := range s {
		assert.Contains(t, alphanumeric, string(c))
	}
}
