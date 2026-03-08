package xss_light_scanner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// defaultMoreParams contains common parameter names to test for reflection.
var defaultMoreParams = []string{
	// Common debug/test params
	"debug", "test", "q", "s", "search", "query", "keyword",
	// URL/redirect params
	"url", "uri", "path", "next", "redirect", "return", "returnUrl", "returnTo",
	"goto", "target", "dest", "destination", "continue", "callback",
	// Page/view params
	"page", "view", "action", "do", "type", "mode", "format", "template",
	// Content params
	"content", "text", "message", "msg", "body", "data", "input", "value",
	"title", "name", "description", "comment", "note",
	// File params
	"file", "filename", "dir", "folder", "src", "source",
	// ID params
	"id", "uid", "pid", "sid", "ref", "key", "token",
	// User input params
	"email", "user", "username", "login",
	// Error/status params
	"error", "err", "status", "code", "reason", "alert",
	// Misc
	"lang", "locale", "theme", "style", "color", "font",
	"width", "height", "size", "limit", "offset", "sort", "order",
}

// ParameterDiscovery handles discovery of parameters that echo in response.
type ParameterDiscovery struct {
	params []string
}

// NewParameterDiscovery creates a new ParameterDiscovery with default params.
func NewParameterDiscovery() *ParameterDiscovery {
	return &ParameterDiscovery{
		params: defaultMoreParams,
	}
}

// NewParameterDiscoveryWithParams creates a ParameterDiscovery with custom params.
func NewParameterDiscoveryWithParams(params []string) *ParameterDiscovery {
	return &ParameterDiscovery{
		params: params,
	}
}

// EchoParam represents a discovered parameter that echoes in response.
type EchoParam struct {
	Name     string
	Canary   string
	EchoType string // "full" or "partial"
}

// DiscoverEchoParams finds parameters that reflect their value in the response.
// It sends a request with canary values for multiple params and checks which ones echo.
func (pd *ParameterDiscovery) DiscoverEchoParams(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	existingParams map[string]bool,
) ([]EchoParam, error) {
	// Filter out params that already exist in the request
	testParams := make([]string, 0, len(pd.params))
	for _, p := range pd.params {
		if !existingParams[p] {
			testParams = append(testParams, p)
		}
	}

	if len(testParams) == 0 {
		return nil, nil
	}

	// Build canaries and query parts with unique values for each param
	canaries := make(map[string]string)
	queryParts := make([]string, 0, len(testParams))
	for i, param := range testParams {
		canary := generateCanaryForParam(i, param)
		canaries[param] = canary
		queryParts = append(queryParts, httpmsg.EncodeQueryValue(param)+"="+httpmsg.EncodeQueryValue(canary))
	}

	// Build modified request with new query string
	baseRequest := ctx.Request().Raw()
	existingQuery, _ := httpmsg.GetQueryString(baseRequest)

	var newQuery string
	if existingQuery != "" {
		newQuery = existingQuery + "&" + strings.Join(queryParts, "&")
	} else {
		newQuery = strings.Join(queryParts, "&")
	}

	modifiedRequest, err := httpmsg.SetQueryString(baseRequest, newQuery)
	if err != nil {
		return nil, err
	}

	// Send request
	parsedReq, err := httpmsg.ParseRawRequest(string(modifiedRequest))
	if err != nil {
		return nil, err
	}
	parsedReq = parsedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(parsedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Close()

	// Check response for echoed canaries
	body := resp.Body().String()
	var echoParams []EchoParam

	for param, canary := range canaries {
		if strings.Contains(body, canary) {
			echoParams = append(echoParams, EchoParam{
				Name:     param,
				Canary:   canary,
				EchoType: "full",
			})
		}
	}

	return echoParams, nil
}

// CreateInsertionPointForParam creates an insertion point for a new parameter.
// Returns the insertion point and the modified request with the parameter added.
func (pd *ParameterDiscovery) CreateInsertionPointForParam(
	request []byte,
	paramName string,
) (httpmsg.InsertionPoint, []byte, error) {
	// Add the parameter to the request
	modifiedRequest, err := httpmsg.AppendURLParameter(request, paramName, "")
	if err != nil {
		return nil, nil, err
	}

	// Find the parameter position in the modified request
	info, err := httpmsg.AnalyzeRequest(modifiedRequest)
	if err != nil {
		return nil, nil, err
	}

	// Find our added parameter
	for _, param := range info.Parameters {
		if param.Name() == paramName && param.Type() == httpmsg.ParamURL {
			ip := httpmsg.NewParameterInsertionPoint(modifiedRequest, param)
			return ip, modifiedRequest, nil
		}
	}

	return nil, nil, nil
}

// DiscoverAndCreatePoints discovers echo params and returns insertion points for them.
// It modifies the original request to include the discovered parameters.
func (pd *ParameterDiscovery) DiscoverAndCreatePoints(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) ([]httpmsg.InsertionPoint, []byte, error) {
	// Get existing params
	info, err := httpmsg.AnalyzeRequest(ctx.Request().Raw())
	if err != nil {
		return nil, nil, err
	}

	existingParams := make(map[string]bool)
	for _, p := range info.Parameters {
		existingParams[p.Name()] = true
	}

	// Discover echo params
	echoParams, err := pd.DiscoverEchoParams(ctx, httpClient, existingParams)
	if err != nil {
		return nil, nil, err
	}

	if len(echoParams) == 0 {
		return nil, nil, nil
	}

	// Create insertion points for echo params
	var points []httpmsg.InsertionPoint
	modifiedRequest := ctx.Request().Raw()

	for _, ep := range echoParams {
		ip, newReq, err := pd.CreateInsertionPointForParam(modifiedRequest, ep.Name)
		if err != nil || ip == nil {
			continue
		}
		points = append(points, ip)
		modifiedRequest = newReq
	}

	return points, modifiedRequest, nil
}

// generateCanaryForParam creates a unique canary for parameter discovery.
// Format: "pd" + index + first char of param name
// Example: param "title" at index 0 -> "pd0t"
func generateCanaryForParam(index int, paramName string) string {
	firstChar := "x"
	if len(paramName) > 0 {
		firstChar = string(paramName[0])
	}
	return fmt.Sprintf("pd%d%s", index, firstChar)
}
