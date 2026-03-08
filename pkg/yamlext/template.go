package yamlext

import (
	"crypto/rand"
	"regexp"
	"strconv"
	"strings"
)

var templatePattern = regexp.MustCompile(`\{\{([^}]+)\}\}`)
var randPattern = regexp.MustCompile(`^rand\((\d+)\)$`)

// InsertionCtx holds insertion point data for template rendering.
type InsertionCtx struct {
	Name      string
	BaseValue string
	Type      string
}

// RequestCtx holds request data for template rendering.
type RequestCtx struct {
	URL    string
	Method string
}

// ResponseCtx holds response data for template rendering.
type ResponseCtx struct {
	Status  int
	Body    string
	Headers map[string]string
}

// TemplateContext provides all variables available to {{...}} templates.
type TemplateContext struct {
	Payload    string
	Insertion  *InsertionCtx
	Request    *RequestCtx
	Response   *ResponseCtx
	ConfigVars map[string]string
	Matched    string
}

// Render resolves all {{...}} expressions in input using the given context.
func Render(input string, ctx *TemplateContext) string {
	if ctx == nil || !strings.Contains(input, "{{") {
		return input
	}

	return templatePattern.ReplaceAllStringFunc(input, func(match string) string {
		// Extract expression between {{ and }}
		expr := strings.TrimSpace(match[2 : len(match)-2])
		return resolveExpr(expr, ctx)
	})
}

func resolveExpr(expr string, ctx *TemplateContext) string {
	// Simple tokens
	switch expr {
	case "payload":
		return ctx.Payload
	case "matched":
		return ctx.Matched
	}

	// rand(N)
	if m := randPattern.FindStringSubmatch(expr); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			return ""
		}
		return randomAlphanumeric(n)
	}

	// Dotted paths
	parts := strings.SplitN(expr, ".", 2)
	if len(parts) < 2 {
		return "{{" + expr + "}}"
	}

	prefix, rest := parts[0], parts[1]

	switch prefix {
	case "insertion":
		if ctx.Insertion == nil {
			return ""
		}
		switch rest {
		case "name":
			return ctx.Insertion.Name
		case "base_value":
			return ctx.Insertion.BaseValue
		case "type":
			return ctx.Insertion.Type
		}

	case "request":
		if ctx.Request == nil {
			return ""
		}
		switch rest {
		case "url":
			return ctx.Request.URL
		case "method":
			return ctx.Request.Method
		}

	case "response":
		if ctx.Response == nil {
			return ""
		}
		switch rest {
		case "status":
			return strconv.Itoa(ctx.Response.Status)
		case "body":
			return ctx.Response.Body
		default:
			// response.headers.X-Something
			if strings.HasPrefix(rest, "headers.") {
				headerName := rest[len("headers."):]
				if ctx.Response.Headers != nil {
					return ctx.Response.Headers[headerName]
				}
				return ""
			}
		}

	case "config":
		if ctx.ConfigVars != nil {
			return ctx.ConfigVars[rest]
		}
		return ""
	}

	// Unrecognized — pass through unchanged
	return "{{" + expr + "}}"
}

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomAlphanumeric(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback to all 'a' on error (extremely unlikely)
		for i := range b {
			b[i] = 'a'
		}
		return string(b)
	}
	for i := range b {
		b[i] = alphanumeric[int(b[i])%len(alphanumeric)]
	}
	return string(b)
}

// RenderAll renders all strings in a slice.
func RenderAll(inputs []string, ctx *TemplateContext) []string {
	out := make([]string, len(inputs))
	for i, s := range inputs {
		out[i] = Render(s, ctx)
	}
	return out
}

// FormatPayload renders a payload template (e.g. "CANARY{{rand(8)}}").
func FormatPayload(payload string, ctx *TemplateContext) string {
	return Render(payload, ctx)
}

// BuildResponseCtx creates a ResponseCtx from status, body, and headers map.
func BuildResponseCtx(status int, body string, headers map[string]string) *ResponseCtx {
	return &ResponseCtx{
		Status:  status,
		Body:    body,
		Headers: headers,
	}
}

// BuildResponseCtxFromRaw builds a ResponseCtx from an httpmsg.HttpResponse.
// This is a convenience used in module implementations.
func BuildResponseCtxFromRaw(statusCode int, bodyStr string, headerPairs [][2]string) *ResponseCtx {
	hdrs := make(map[string]string, len(headerPairs))
	for _, pair := range headerPairs {
		hdrs[pair[0]] = pair[1]
	}
	return &ResponseCtx{
		Status:  statusCode,
		Body:    bodyStr,
		Headers: hdrs,
	}
}

