package mcp

import (
	"fmt"
	"strings"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Client speaks MCP JSON-RPC over a vigolium http.Requester, reusing the
// service/cookies/auth from a seed HttpRequestResponse. It mints fresh raw
// requests for every call so the underlying request pipeline is unchanged.
type Client struct {
	seed       *httpmsg.HttpRequestResponse
	httpClient *http.Requester
	path       string
	sessionID  string
	// extraHeaders are added to every outgoing request (e.g. fixation tests).
	extraHeaders map[string]string
}

// NewClient builds a Client targeted at `path` (defaulting to /mcp) on the
// host of `seed`. The seed is expected to come from a discovered MCP endpoint
// (or a probe candidate).
func NewClient(seed *httpmsg.HttpRequestResponse, httpClient *http.Requester, path string) *Client {
	if path == "" {
		path = "/mcp"
	}
	return &Client{seed: seed, httpClient: httpClient, path: path}
}

// SessionID returns the captured Mcp-Session-Id, or "" if none.
func (c *Client) SessionID() string { return c.sessionID }

// SetSessionID overrides the session ID (used by fixation tests).
func (c *Client) SetSessionID(id string) { c.sessionID = id }

// Path returns the current endpoint path.
func (c *Client) Path() string { return c.path }

// SetPath swaps the endpoint path (used after legacy SSE handshake).
func (c *Client) SetPath(p string) { c.path = p }

// SetExtraHeaders sets per-call headers added to every request. Pass nil to clear.
func (c *Client) SetExtraHeaders(h map[string]string) { c.extraHeaders = h }

// Initialize negotiates protocol version and captures the session ID.
func (c *Client) Initialize() (*InitializeResult, error) {
	body, resp, err := c.PostJSONRPC(BuildInitializeRequest())
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Response() != nil {
		if sid := resp.Response().Header.Get("Mcp-Session-Id"); sid != "" {
			c.sessionID = sid
		}
	}
	return ParseInitializeResponse(body)
}

// SendInitializedNotification sends notifications/initialized post-handshake.
func (c *Client) SendInitializedNotification() error {
	_, _, err := c.PostJSONRPC(BuildInitializedNotification())
	return err
}

// ListTools enumerates tools.
func (c *Client) ListTools() (*ToolsListResult, error) {
	body, _, err := c.PostJSONRPC(BuildToolsListRequest())
	if err != nil {
		return nil, err
	}
	return ParseToolsListResponse(body)
}

// CallTool invokes a tool with the supplied arguments.
func (c *Client) CallTool(id int, name string, args map[string]any) (*ToolsCallResult, string, error) {
	body, _, err := c.PostJSONRPC(BuildToolsCallRequest(id, name, args))
	if err != nil {
		return nil, body, err
	}
	res, perr := ParseToolsCallResponse(body)
	return res, body, perr
}

// ListResources enumerates resources.
func (c *Client) ListResources() (*ResourcesListResult, error) {
	body, _, err := c.PostJSONRPC(BuildResourcesListRequest())
	if err != nil {
		return nil, err
	}
	return ParseResourcesListResponse(body)
}

// ListResourceTemplates enumerates resource templates.
func (c *Client) ListResourceTemplates() (*ResourceTemplatesListResult, error) {
	body, _, err := c.PostJSONRPC(BuildResourceTemplatesListRequest())
	if err != nil {
		return nil, err
	}
	return ParseResourceTemplatesListResponse(body)
}

// ReadResource fetches a single resource by URI.
func (c *Client) ReadResource(id int, uri string) (*ResourcesReadResult, string, error) {
	body, _, err := c.PostJSONRPC(BuildResourcesReadRequest(id, uri))
	if err != nil {
		return nil, body, err
	}
	res, perr := ParseResourcesReadResponse(body)
	return res, body, perr
}

// ListPrompts enumerates prompts.
func (c *Client) ListPrompts() (*PromptsListResult, error) {
	body, _, err := c.PostJSONRPC(BuildPromptsListRequest())
	if err != nil {
		return nil, err
	}
	return ParsePromptsListResponse(body)
}

// GetPrompt invokes a prompt with arguments.
func (c *Client) GetPrompt(id int, name string, args map[string]string) (*PromptsGetResult, string, error) {
	body, _, err := c.PostJSONRPC(BuildPromptsGetRequest(id, name, args))
	if err != nil {
		return nil, body, err
	}
	res, perr := ParsePromptsGetResponse(body)
	return res, body, perr
}

// CompletePrompt asks completion/complete for a prompt argument value.
func (c *Client) CompletePrompt(id int, promptName, argName, partial string) (*CompleteResult, string, error) {
	body, _, err := c.PostJSONRPC(BuildCompletePromptRequest(id, promptName, argName, partial))
	if err != nil {
		return nil, body, err
	}
	res, perr := ParseCompleteResponse(body)
	return res, body, perr
}

// CompleteResource asks completion/complete for a resource URI argument.
func (c *Client) CompleteResource(id int, uri, argName, partial string) (*CompleteResult, string, error) {
	body, _, err := c.PostJSONRPC(BuildCompleteResourceRequest(id, uri, argName, partial))
	if err != nil {
		return nil, body, err
	}
	res, perr := ParseCompleteResponse(body)
	return res, body, perr
}

// PostRaw sends an arbitrary JSON-RPC body (allowing custom methods, batches,
// or malformed payloads) to the endpoint and returns the response body, the
// raw response chain, and the marshalled raw request for logging.
func (c *Client) PostRaw(body []byte) (string, *httpUtils.ResponseChain, error) {
	return c.PostJSONRPC(body)
}

// PostJSONRPC is the canonical "send a JSON-RPC body" helper.
func (c *Client) PostJSONRPC(body []byte) (string, *httpUtils.ResponseChain, error) {
	respChain, _, err := c.send("POST", c.path, body, "application/json", "application/json, text/event-stream")
	if err != nil {
		return "", nil, err
	}
	defer respChain.Close()
	if respChain.Response() == nil {
		return "", nil, fmt.Errorf("no response")
	}
	return respChain.Body().String(), respChain, nil
}

// Get sends an HTTP GET to a path on the endpoint host. Used for legacy SSE
// transport handshake.
func (c *Client) Get(path, accept string) (*httpUtils.ResponseChain, error) {
	resp, _, err := c.send("GET", path, nil, "", accept)
	return resp, err
}

// send is the low-level transport helper. The returned ResponseChain is the
// caller's responsibility to Close().
func (c *Client) send(method, path string, body []byte, contentType, accept string) (*httpUtils.ResponseChain, []byte, error) {
	if c.seed == nil || c.seed.Request() == nil {
		return nil, nil, fmt.Errorf("client has no seed request")
	}
	raw := c.seed.Request().Raw()

	raw, err := httpmsg.SetMethod(raw, method)
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return nil, nil, err
	}
	if method == "GET" {
		raw, err = httpmsg.ClearBody(raw)
		if err != nil {
			return nil, nil, err
		}
	} else {
		raw, err = httpmsg.SetBodyString(raw, string(body))
		if err != nil {
			return nil, nil, err
		}
	}
	if contentType != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", contentType)
		if err != nil {
			return nil, nil, err
		}
	}
	if accept != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Accept", accept)
		if err != nil {
			return nil, nil, err
		}
	}
	if c.sessionID != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Mcp-Session-Id", c.sessionID)
		if err != nil {
			return nil, nil, err
		}
	}
	for k, v := range c.extraHeaders {
		raw, err = httpmsg.AddOrReplaceHeader(raw, k, v)
		if err != nil {
			return nil, nil, err
		}
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, nil, err
	}
	req = req.WithService(c.seed.Service())

	resp, _, err := c.httpClient.Execute(req, http.Options{})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return nil, nil, fmt.Errorf("no response")
	}
	return resp, raw, nil
}

// PathOk indicates whether the response chain is a likely-successful MCP
// response (HTTP 2xx, JSON-RPC body, or SSE stream). Helper for probing loops.
func PathOk(resp *httpUtils.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	sc := resp.Response().StatusCode
	return sc >= 200 && sc < 300
}

// HasSSEContentType reports whether the response Content-Type indicates SSE.
func HasSSEContentType(resp *httpUtils.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Response().Header.Get("Content-Type")), "text/event-stream")
}
