// Package llm provides a minimal OpenAI-compatible chat client and a
// dependency-free secret matcher shared by the LLM-aware active scanner modules
// (currently llm_boundary_probe). It mints fresh raw requests off a seed
// HttpRequestResponse — reusing its service/cookies/auth — so the underlying
// request pipeline (rate limiting, host-error tracking) is unchanged, mirroring
// the pattern used by pkg/modules/infra/mcp.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/mcp"
)

// Client speaks an OpenAI-compatible chat/completions protocol over a vigolium
// http.Requester, reusing the connection identity of a seed request discovered
// to be an LLM endpoint. It POSTs a {"model","messages"} body and reconstructs
// the assistant text from either a JSON completion object or an SSE delta stream.
type Client struct {
	seed       *httpmsg.HttpRequestResponse
	httpClient *http.Requester
	url        string
	model      string
}

// NewClient builds a Client that targets the URL of seed (expected to be an
// LLM chat endpoint). The seed's method/path/headers are reused; only the body
// and the content-negotiation headers are rewritten per Chat call.
func NewClient(seed *httpmsg.HttpRequestResponse, httpClient *http.Requester) *Client {
	url := ""
	if seed != nil {
		if u, err := seed.URL(); err == nil {
			url = u.String()
		}
	}
	return &Client{seed: seed, httpClient: httpClient, url: url, model: modelFromSeed(seed)}
}

// URL returns the seed endpoint URL the client targets.
func (c *Client) URL() string { return c.url }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

// chatResponse covers both the non-streamed completion shape
// (choices[].message.content) and the streamed delta shape
// (choices[].delta.content). Missing fields decode to "".
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

// Chat POSTs a single-turn user message to the seed endpoint and returns the
// reconstructed assistant text along with the raw request sent and the raw
// response body, so the caller can attach both to a finding's evidence.
//
// NOTE ON THE RETURN SHAPE: rather than handing back a *ResponseChain the caller
// must remember to Close() (and whose pooled FullResponse buffer must never be
// touched — see the respChain FullResponse leak guard), Chat drains and closes
// the chain internally and returns copied strings. This keeps evidence capture
// leak-free and the call sites trivial.
func (c *Client) Chat(ctx context.Context, userPrompt string) (assistant, rawRequest, respBody string, err error) {
	body, mErr := json.Marshal(chatRequest{
		Model:    c.model,
		Messages: []chatMessage{{Role: "user", Content: userPrompt}},
	})
	if mErr != nil {
		return "", "", "", mErr
	}

	resp, rawReq, sErr := c.send(ctx, body)
	rawRequest = rawReq
	if sErr != nil {
		return "", rawRequest, "", sErr
	}
	defer resp.Close()

	isSSE := mcp.HasSSEContentType(resp)
	respBody = resp.BodyString()
	if isSSE {
		assistant = assistantFromSSE(respBody)
	} else {
		assistant = assistantFromJSON(respBody)
	}
	return assistant, rawRequest, respBody, nil
}

// modelFromSeed echoes the model named in the seed request body when present,
// else falls back to a generic "gpt" so the endpoint still accepts the request.
// Computed once in NewClient and cached on the Client (the seed body is fixed).
func modelFromSeed(seed *httpmsg.HttpRequestResponse) string {
	if seed != nil && seed.Request() != nil {
		var probe struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal([]byte(seed.Request().BodyToString()), &probe); err == nil {
			if m := strings.TrimSpace(probe.Model); m != "" {
				return m
			}
		}
	}
	return "gpt"
}

// send mints a fresh raw POST request off the seed, applying the JSON body and
// content-negotiation headers, then executes it. The returned ResponseChain is
// the caller's to Close(); on error it is nil (any partial chain is closed here).
func (c *Client) send(ctx context.Context, body []byte) (*httpUtils.ResponseChain, string, error) {
	if c.seed == nil || c.seed.Request() == nil {
		return nil, "", fmt.Errorf("llm client has no seed request")
	}
	raw := c.seed.Request().Raw()

	raw, err := httpmsg.SetMethod(raw, "POST")
	if err != nil {
		return nil, "", err
	}
	raw, err = httpmsg.SetBodyString(raw, string(body))
	if err != nil {
		return nil, "", err
	}
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", "application/json")
	if err != nil {
		return nil, "", err
	}
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Accept", "application/json, text/event-stream")
	if err != nil {
		return nil, "", err
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, string(raw), err
	}
	req = req.WithService(c.seed.Service())

	resp, _, err := c.httpClient.ExecuteContext(ctx, req, http.Options{})
	if err != nil {
		return nil, string(raw), err
	}
	if resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return nil, string(raw), fmt.Errorf("no response")
	}
	return resp, string(raw), nil
}

// assistantFromJSON parses a non-streamed completion object and returns
// choices[0].message.content, or "" when the body is empty/malformed/fieldless.
func assistantFromJSON(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	var cr chatResponse
	if err := json.Unmarshal([]byte(body), &cr); err != nil {
		return ""
	}
	if len(cr.Choices) == 0 {
		return ""
	}
	return cr.Choices[0].Message.Content
}

// assistantFromSSE reconstructs the assistant text from a streamed response by
// concatenating choices[0].delta.content across every JSON `data:` event. The
// terminal "[DONE]" sentinel and non-JSON events are skipped.
func assistantFromSSE(body string) string {
	var sb strings.Builder
	for _, ev := range mcp.ParseSSE(body) {
		data := strings.TrimSpace(ev.Data)
		if data == "" || data == "[DONE]" || data[0] != '{' {
			continue
		}
		var cr chatResponse
		if err := json.Unmarshal([]byte(data), &cr); err != nil {
			continue
		}
		if len(cr.Choices) == 0 {
			continue
		}
		sb.WriteString(cr.Choices[0].Delta.Content)
	}
	return sb.String()
}
