package jsext

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grafana/sobek"
	gohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"go.uber.org/zap"
)

// jsMCPClient owns per-call state for a single vigolium.mcp.client(...) handle.
type jsMCPClient struct {
	vm         *sobek.Runtime
	httpClient *gohttp.Requester
	baseURL    string
	path       string
	headers    map[string]string
	sessionID  string
	nextID     int
}

// mcpFuncDefs returns declarative definitions for vigolium.mcp.* functions.
// They wrap the shared pkg/modules/infra/mcp helpers so JS extensions can
// speak Model Context Protocol from inside vigolium scans.
func mcpFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsMCP, Name: "client",
			Category:  CatHTTP,
			Signature: ".client(url: string, opts?: {path?, headers?, sessionId?})",
			Returns:   "MCPClient",
			Description: "Build an MCP client over the given base URL. The client tracks " +
				"Mcp-Session-Id automatically and exposes initialize, list/call tools, " +
				"read resources, get prompts, completion/complete, and raw request helpers.",
			Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					if urlStr == "" {
						return sobek.Undefined()
					}
					path := ""
					headers := map[string]string{}
					sessionID := ""
					if optsVal := call.Argument(1); !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						o := optsVal.ToObject(vm)
						if v := o.Get("path"); v != nil && !sobek.IsUndefined(v) {
							path = v.String()
						}
						if v := o.Get("headers"); v != nil && !sobek.IsUndefined(v) {
							ho := v.ToObject(vm)
							for _, k := range ho.Keys() {
								headers[k] = ho.Get(k).String()
							}
						}
						if v := o.Get("sessionId"); v != nil && !sobek.IsUndefined(v) {
							sessionID = v.String()
						}
					}
					base, p := splitMCPBase(urlStr, path)
					c := &jsMCPClient{
						vm:         vm,
						httpClient: opts.HTTPClient,
						baseURL:    base,
						path:       p,
						headers:    headers,
						sessionID:  sessionID,
						nextID:     1,
					}
					return c.toJSObject()
				}
			},
		},
		{
			Namespace: NsMCP, Name: "parseSse",
			Category:  CatHTTP,
			Signature: ".parseSse(body: string)",
			Returns:   "MCPSSEEvent[]",
			Description: "Parse an SSE-formatted body into an array of {event, id, data} " +
				"objects. JSON `data` payloads are returned verbatim as strings.",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					body := call.Argument(0).String()
					events := mcpinfra.ParseSSE(body)
					arr := make([]any, 0, len(events))
					for _, ev := range events {
						o := vm.NewObject()
						_ = o.Set("event", ev.Event)
						_ = o.Set("id", ev.ID)
						_ = o.Set("data", ev.Data)
						arr = append(arr, o)
					}
					return vm.ToValue(arr)
				}
			},
		},
		{
			Namespace: NsMCP, Name: "detect",
			Category:  CatHTTP,
			Signature: ".detect(req: {url, headers}, resp: {headers, body})",
			Returns:   "boolean",
			Description: "Return true if the (request, response) pair carries strong " +
				"indicators of an MCP endpoint (Mcp-Session-Id, JSON-RPC envelope, " +
				"SSE stream with MCP method names).",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					reqHeaders := map[string]string{}
					urlPath := ""
					if v := call.Argument(0); !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						o := v.ToObject(vm)
						if u := o.Get("url"); u != nil && !sobek.IsUndefined(u) {
							urlPath = u.String()
						}
						if h := o.Get("headers"); h != nil && !sobek.IsUndefined(h) {
							ho := h.ToObject(vm)
							for _, k := range ho.Keys() {
								reqHeaders[k] = ho.Get(k).String()
							}
						}
					}
					respHeaders := map[string]string{}
					respBody := ""
					if v := call.Argument(1); !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						o := v.ToObject(vm)
						if h := o.Get("headers"); h != nil && !sobek.IsUndefined(h) {
							ho := h.ToObject(vm)
							for _, k := range ho.Keys() {
								respHeaders[k] = ho.Get(k).String()
							}
						}
						if b := o.Get("body"); b != nil && !sobek.IsUndefined(b) {
							respBody = b.String()
						}
					}
					flags := mcpinfra.DetectFromParts(reqHeaders, urlPath, respHeaders, respBody)
					return vm.ToValue(flags.Strong())
				}
			},
		},
		{
			Namespace: NsMCP, Name: "buildRequest",
			Category:  CatHTTP,
			Signature: ".buildRequest(method: string, params?: any, opts?: {id?, notification?})",
			Returns:   "string",
			Description: "Marshal a JSON-RPC 2.0 envelope. When opts.notification is true, " +
				"the result has no id field. Useful with vigolium.http.send() for " +
				"unsupported transports.",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					method := call.Argument(0).String()
					params := jsValueToGo(vm, call.Argument(1))
					id := 1
					notification := false
					if v := call.Argument(2); !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						o := v.ToObject(vm)
						if iv := o.Get("id"); iv != nil && !sobek.IsUndefined(iv) {
							id = int(iv.ToInteger())
						}
						if nv := o.Get("notification"); nv != nil && !sobek.IsUndefined(nv) {
							notification = nv.ToBoolean()
						}
					}
					if notification {
						return vm.ToValue(string(mcpinfra.MarshalNotification(method, params)))
					}
					return vm.ToValue(string(mcpinfra.MarshalRequest(id, method, params)))
				}
			},
		},
	}
}

// toJSObject exposes the MCPClient methods to the JS runtime.
func (c *jsMCPClient) toJSObject() sobek.Value {
	obj := c.vm.NewObject()

	_ = obj.Set("getSessionId", func(call sobek.FunctionCall) sobek.Value {
		return c.vm.ToValue(c.sessionID)
	})
	_ = obj.Set("setSessionId", func(call sobek.FunctionCall) sobek.Value {
		c.sessionID = call.Argument(0).String()
		return sobek.Undefined()
	})
	_ = obj.Set("setHeader", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		c.headers[name] = value
		return sobek.Undefined()
	})

	_ = obj.Set("initialize", func(call sobek.FunctionCall) sobek.Value {
		body, sid, resp := c.postJSONRPC(mcpinfra.BuildInitializeRequest())
		if sid != "" {
			c.sessionID = sid
		}
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("notifyInitialized", func(call sobek.FunctionCall) sobek.Value {
		c.postJSONRPC(mcpinfra.BuildInitializedNotification())
		return sobek.Undefined()
	})

	_ = obj.Set("listTools", func(call sobek.FunctionCall) sobek.Value {
		body, _, resp := c.postJSONRPC(mcpinfra.BuildToolsListRequest())
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("callTool", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		args := goMapStringAny(jsValueToGo(c.vm, call.Argument(1)))
		body, _, resp := c.postJSONRPC(mcpinfra.BuildToolsCallRequest(c.takeID(), name, args))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("listResources", func(call sobek.FunctionCall) sobek.Value {
		body, _, resp := c.postJSONRPC(mcpinfra.BuildResourcesListRequest())
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("listResourceTemplates", func(call sobek.FunctionCall) sobek.Value {
		body, _, resp := c.postJSONRPC(mcpinfra.BuildResourceTemplatesListRequest())
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("readResource", func(call sobek.FunctionCall) sobek.Value {
		uri := call.Argument(0).String()
		body, _, resp := c.postJSONRPC(mcpinfra.BuildResourcesReadRequest(c.takeID(), uri))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("listPrompts", func(call sobek.FunctionCall) sobek.Value {
		body, _, resp := c.postJSONRPC(mcpinfra.BuildPromptsListRequest())
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("getPrompt", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		args := goMapStringString(jsValueToGo(c.vm, call.Argument(1)))
		body, _, resp := c.postJSONRPC(mcpinfra.BuildPromptsGetRequest(c.takeID(), name, args))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("completePrompt", func(call sobek.FunctionCall) sobek.Value {
		promptName := call.Argument(0).String()
		argName := call.Argument(1).String()
		partial := call.Argument(2).String()
		body, _, resp := c.postJSONRPC(mcpinfra.BuildCompletePromptRequest(c.takeID(), promptName, argName, partial))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("completeResource", func(call sobek.FunctionCall) sobek.Value {
		uri := call.Argument(0).String()
		argName := call.Argument(1).String()
		partial := call.Argument(2).String()
		body, _, resp := c.postJSONRPC(mcpinfra.BuildCompleteResourceRequest(c.takeID(), uri, argName, partial))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("request", func(call sobek.FunctionCall) sobek.Value {
		method := call.Argument(0).String()
		params := jsValueToGo(c.vm, call.Argument(1))
		body, _, resp := c.postJSONRPC(mcpinfra.MarshalRequest(c.takeID(), method, params))
		return wrapMCPResponse(c.vm, resp, body)
	})

	_ = obj.Set("notify", func(call sobek.FunctionCall) sobek.Value {
		method := call.Argument(0).String()
		params := jsValueToGo(c.vm, call.Argument(1))
		c.postJSONRPC(mcpinfra.MarshalNotification(method, params))
		return sobek.Undefined()
	})

	_ = obj.Set("send", func(call sobek.FunctionCall) sobek.Value {
		raw := call.Argument(0).String()
		body, _, resp := c.postJSONRPC([]byte(raw))
		return wrapMCPResponse(c.vm, resp, body)
	})

	return obj
}

func (c *jsMCPClient) takeID() int {
	c.nextID++
	return c.nextID
}

// postJSONRPC dispatches a single JSON-RPC body to the configured endpoint and
// returns (body, sessionID, raw response object). On error every return is
// zero-valued.
func (c *jsMCPClient) postJSONRPC(body []byte) (string, string, *parsedJSResponse) {
	if c.httpClient == nil {
		return "", "", nil
	}
	rawReq := c.buildRawRequest(body)
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	if host := req.Header("Host"); host != "" {
		svc, err := httpmsg.ParseService(c.scheme() + "://" + host)
		if err == nil {
			req = httpmsg.NewHttpRequestWithService(svc, []byte(rawReq))
		}
	}
	hrr := httpmsg.NewHttpRequestResponse(req, nil)
	start := time.Now()
	respChain, _, err := c.httpClient.Execute(hrr, gohttp.Options{})
	elapsedMs := time.Since(start).Milliseconds()
	if err != nil {
		zap.L().Debug("vigolium.mcp request failed", zap.Error(err))
		return "", "", nil
	}
	defer respChain.Close()
	if respChain.Response() == nil {
		return "", "", nil
	}
	bodyBytes := respChain.Body().Bytes()
	headers := map[string]string{}
	for k, v := range respChain.Response().Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	sid := headers["mcp-session-id"]
	parsed := &parsedJSResponse{
		status:    respChain.Response().StatusCode,
		headers:   headers,
		bodyBytes: bodyBytes,
		elapsedMs: elapsedMs,
	}
	return string(bodyBytes), sid, parsed
}

func (c *jsMCPClient) buildRawRequest(body []byte) string {
	host := extractHost(c.baseURL)
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s HTTP/1.1\r\n", c.path)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)
	sb.WriteString("Content-Type: application/json\r\n")
	sb.WriteString("Accept: application/json, text/event-stream\r\n")
	if c.sessionID != "" {
		fmt.Fprintf(&sb, "Mcp-Session-Id: %s\r\n", c.sessionID)
	}
	for k, v := range c.headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-type") ||
			strings.EqualFold(k, "accept") || strings.EqualFold(k, "content-length") {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

func (c *jsMCPClient) scheme() string {
	if strings.HasPrefix(c.baseURL, "https://") {
		return "https"
	}
	return "http"
}

// parsedJSResponse is the minimum response surface we need to expose to JS.
type parsedJSResponse struct {
	status    int
	headers   map[string]string
	bodyBytes []byte
	elapsedMs int64
}

func wrapMCPResponse(vm *sobek.Runtime, resp *parsedJSResponse, body string) sobek.Value {
	if resp == nil {
		return sobek.Undefined()
	}
	out := vm.NewObject()
	_ = out.Set("status", resp.status)
	_ = out.Set("body", string(resp.bodyBytes))
	_ = out.Set("elapsed_ms", resp.elapsedMs)

	headersObj := vm.NewObject()
	for k, v := range resp.headers {
		_ = headersObj.Set(k, v)
	}
	_ = out.Set("headers", headersObj)

	// Attempt to surface parsed result/error for convenience.
	if parsed, err := mcpinfra.ParseResponse(body); err == nil && parsed != nil {
		if parsed.Error != nil {
			errObj := vm.NewObject()
			_ = errObj.Set("code", parsed.Error.Code)
			_ = errObj.Set("message", parsed.Error.Message)
			_ = out.Set("error", errObj)
		}
		if len(parsed.Result) > 0 {
			var anyResult any
			if jerr := json.Unmarshal(parsed.Result, &anyResult); jerr == nil {
				_ = out.Set("result", anyResult)
			} else {
				_ = out.Set("result", string(parsed.Result))
			}
		}
	}
	return out
}

// helpers -------------------------------------------------------------------

func splitMCPBase(rawURL, path string) (string, string) {
	base := rawURL
	defaultPath := "/mcp"
	if idx := strings.Index(rawURL, "://"); idx > 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			base = rawURL[:idx+3+slash]
			tailPath := rest[slash:]
			if path == "" && tailPath != "/" {
				path = tailPath
			}
		}
	}
	if path == "" {
		path = defaultPath
	}
	return base, path
}

func jsValueToGo(vm *sobek.Runtime, v sobek.Value) any {
	if sobek.IsUndefined(v) || sobek.IsNull(v) {
		return nil
	}
	return v.Export()
}

func goMapStringAny(in any) map[string]any {
	if in == nil {
		return nil
	}
	if m, ok := in.(map[string]any); ok {
		return m
	}
	if mi, ok := in.(map[string]interface{}); ok {
		out := map[string]any{}
		for k, v := range mi {
			out[k] = v
		}
		return out
	}
	return nil
}

func goMapStringString(in any) map[string]string {
	out := map[string]string{}
	if in == nil {
		return out
	}
	if m, ok := in.(map[string]any); ok {
		for k, v := range m {
			out[k] = fmt.Sprintf("%v", v)
		}
		return out
	}
	if mi, ok := in.(map[string]interface{}); ok {
		for k, v := range mi {
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}
