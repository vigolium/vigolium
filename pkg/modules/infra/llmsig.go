package infra

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// LooksLikeLLMEndpoint reports whether a request/response pair is an application-
// level LLM chat/completion endpoint. It matches on the request or response BODY
// SHAPE (not merely a path), so it fails closed on ordinary endpoints — the strict
// technology gate the LLM modules require before probing. Detection signals mirror
// the OpenAI-compatible / chat-completion conventions most providers follow.
func LooksLikeLLMEndpoint(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	// Request shape: a chat "messages" array with roles, or a prompt/input alongside
	// an LLM generation parameter.
	reqBody := strings.ToLower(ctx.Request().BodyToString())
	if reqBody != "" {
		if strings.Contains(reqBody, `"messages"`) && strings.Contains(reqBody, `"role"`) {
			return true
		}
		hasPrompt := strings.Contains(reqBody, `"prompt"`) || strings.Contains(reqBody, `"input"`) || strings.Contains(reqBody, `"inputs"`)
		hasGenParam := strings.Contains(reqBody, `"max_tokens"`) || strings.Contains(reqBody, `"temperature"`) ||
			strings.Contains(reqBody, `"top_p"`) || strings.Contains(reqBody, `"model"`) || strings.Contains(reqBody, `"stream"`)
		if hasPrompt && hasGenParam {
			return true
		}
	}

	// Response shape: a chat-completion object, a choices array with a message/delta,
	// or a server-sent-events stream carrying delta chunks.
	resp := ctx.Response()
	if resp == nil {
		return false
	}
	respBody := resp.BodyToString()
	if strings.Contains(respBody, `"chat.completion"`) || strings.Contains(respBody, `"text_completion"`) {
		return true
	}
	if strings.Contains(respBody, `"choices"`) &&
		(strings.Contains(respBody, `"delta"`) || strings.Contains(respBody, `"message"`) || strings.Contains(respBody, `"finish_reason"`)) {
		return true
	}
	ct := strings.ToLower(resp.Header("Content-Type"))
	if strings.Contains(ct, "text/event-stream") && strings.Contains(respBody, `"delta"`) {
		return true
	}
	return false
}
