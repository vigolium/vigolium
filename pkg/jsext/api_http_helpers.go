package jsext

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/jsext/api/parse"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// Common CSRF field names to search for in forms, meta tags, and headers.
var commonCSRFFieldNames = []string{
	"csrf_token", "csrftoken", "_csrf", "csrf",
	"csrfmiddlewaretoken", "_token", "token",
	"__requestverificationtoken", "requestverificationtoken",
	"authenticity_token", "_csrf_token",
	"x-csrf-token", "x-xsrf-token", "xsrf-token",
}

// httpHelperFuncDefs returns JSFuncDefs for csrf, followAuth, and retry.
func httpHelperFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsHTTP,
			Name:        "csrf",
			Category:    CatHTTP,
			Signature:   ".csrf(url: string, opts?: {session?, field_names?, source?})",
			Returns:     "{token, field_name, source} | null",
			Description: "Fetch a page and extract a CSRF token from forms, meta tags, headers, or cookies.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					if urlStr == "" {
						zap.L().Debug("http.csrf: url is required")
						return sobek.Null()
					}

					// Parse options
					var sess *jsSession
					var fieldNames []string
					sourceHint := "" // "form", "meta", "header", "cookie"

					if optsVal := call.Argument(1); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						o := optsVal.ToObject(vm)

						if v := o.Get("session"); v != nil && !sobek.IsUndefined(v) {
							// Use session for the fetch -- extract headers from it
							sessHeaders := extractSessionHeadersMap(vm, v.ToObject(vm))
							sess = newJSSession(vm, opts.HTTPClient, sessHeaders, nil)
						}

						if v := o.Get("field_names"); v != nil && !sobek.IsUndefined(v) {
							arr := v.ToObject(vm)
							length := int(arr.Get("length").ToInteger())
							fieldNames = make([]string, 0, length)
							for i := range length {
								fieldNames = append(fieldNames, arr.Get(fmt.Sprintf("%d", i)).String())
							}
						}

						if v := o.Get("source"); v != nil && !sobek.IsUndefined(v) {
							sourceHint = strings.ToLower(v.String())
						}
					}

					if len(fieldNames) == 0 {
						fieldNames = commonCSRFFieldNames
					}

					// Fetch the page
					var resp sobek.Value
					if sess != nil {
						resp = sess.doSessionHTTP("GET", urlStr, "", nil)
					} else {
						resp = doRequest(vm, opts.HTTPClient, "GET", urlStr, "", nil)
					}

					if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
						return sobek.Null()
					}

					respObj := resp.ToObject(vm)
					respBody := ""
					if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
						respBody = v.String()
					}
					respRaw := ""
					if v := respObj.Get("raw"); v != nil && !sobek.IsUndefined(v) {
						respRaw = v.String()
					}
					respHeaders := make(map[string]string)
					if v := respObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
						headersObj := v.ToObject(vm)
						for _, key := range headersObj.Keys() {
							respHeaders[key] = headersObj.Get(key).String()
						}
					}

					// Build lowercase lookup set for field names
					fieldNameSet := make(map[string]bool, len(fieldNames))
					for _, fn := range fieldNames {
						fieldNameSet[strings.ToLower(fn)] = true
					}

					// Try extraction from different sources based on hint
					type csrfResult struct {
						token     string
						fieldName string
						source    string
					}

					tryForm := func() *csrfResult {
						doc, err := html.Parse(strings.NewReader(respBody))
						if err != nil {
							return nil
						}
						var result *csrfResult
						var walk func(*html.Node)
						walk = func(n *html.Node) {
							if result != nil {
								return
							}
							if n.Type == html.ElementNode && n.Data == "input" {
								name := strings.ToLower(parse.GetAttr(n, "name"))
								if fieldNameSet[name] {
									value := parse.GetAttr(n, "value")
									if value != "" {
										result = &csrfResult{token: value, fieldName: parse.GetAttr(n, "name"), source: "form"}
									}
								}
							}
							for c := n.FirstChild; c != nil; c = c.NextSibling {
								walk(c)
							}
						}
						walk(doc)
						return result
					}

					tryMeta := func() *csrfResult {
						doc, err := html.Parse(strings.NewReader(respBody))
						if err != nil {
							return nil
						}
						var result *csrfResult
						var walk func(*html.Node)
						walk = func(n *html.Node) {
							if result != nil {
								return
							}
							if n.Type == html.ElementNode && n.Data == "meta" {
								name := strings.ToLower(parse.GetAttr(n, "name"))
								if fieldNameSet[name] {
									content := parse.GetAttr(n, "content")
									if content != "" {
										result = &csrfResult{token: content, fieldName: parse.GetAttr(n, "name"), source: "meta"}
									}
								}
							}
							for c := n.FirstChild; c != nil; c = c.NextSibling {
								walk(c)
							}
						}
						walk(doc)
						return result
					}

					tryHeader := func() *csrfResult {
						for hName, hVal := range respHeaders {
							if fieldNameSet[strings.ToLower(hName)] && hVal != "" {
								return &csrfResult{token: hVal, fieldName: hName, source: "header"}
							}
						}
						return nil
					}

					tryCookie := func() *csrfResult {
						// Parse Set-Cookie headers from raw response
						headerSection, _ := parse.SplitHTTPMessage(respRaw)
						lines := parse.SplitHeaderLines(headerSection)
						for _, line := range lines {
							if idx := strings.IndexByte(line, ':'); idx > 0 {
								hName := strings.TrimSpace(line[:idx])
								if strings.EqualFold(hName, "Set-Cookie") {
									cookieStr := strings.TrimSpace(line[idx+1:])
									if eqIdx := strings.IndexByte(cookieStr, '='); eqIdx > 0 {
										cName := cookieStr[:eqIdx]
										if fieldNameSet[strings.ToLower(cName)] {
											rest := cookieStr[eqIdx+1:]
											if semiIdx := strings.IndexByte(rest, ';'); semiIdx >= 0 {
												rest = rest[:semiIdx]
											}
											if rest != "" {
												return &csrfResult{token: rest, fieldName: cName, source: "cookie"}
											}
										}
									}
								}
							}
						}
						return nil
					}

					var found *csrfResult

					if sourceHint != "" {
						// Try only the hinted source
						switch sourceHint {
						case "form":
							found = tryForm()
						case "meta":
							found = tryMeta()
						case "header":
							found = tryHeader()
						case "cookie":
							found = tryCookie()
						}
					}

					// If no hint or hint didn't find anything, try all sources
					if found == nil {
						found = tryForm()
					}
					if found == nil {
						found = tryMeta()
					}
					if found == nil {
						found = tryHeader()
					}
					if found == nil {
						found = tryCookie()
					}

					if found == nil {
						return sobek.Null()
					}

					result := vm.NewObject()
					_ = result.Set("token", found.token)
					_ = result.Set("field_name", found.fieldName)
					_ = result.Set("source", found.source)
					return result
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "followAuth",
			Category:    CatHTTP,
			Signature:   ".followAuth(opts: {type, token_url, client_id?, client_secret?, username?, password?, scope?, code?, redirect_uri?})",
			Returns:     "HttpSession",
			Description: "Follow an OAuth2 authentication flow and return a session with the access token.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					optsVal := call.Argument(0)
					if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
						zap.L().Debug("http.followAuth: missing options")
						return sobek.Undefined()
					}
					o := optsVal.ToObject(vm)

					authType := ""
					if v := o.Get("type"); v != nil && !sobek.IsUndefined(v) {
						authType = v.String()
					}

					tokenURL := ""
					if v := o.Get("token_url"); v != nil && !sobek.IsUndefined(v) {
						tokenURL = v.String()
					}
					if tokenURL == "" {
						zap.L().Debug("http.followAuth: token_url is required")
						return sobek.Undefined()
					}

					clientID := ""
					if v := o.Get("client_id"); v != nil && !sobek.IsUndefined(v) {
						clientID = v.String()
					}
					clientSecret := ""
					if v := o.Get("client_secret"); v != nil && !sobek.IsUndefined(v) {
						clientSecret = v.String()
					}
					username := ""
					if v := o.Get("username"); v != nil && !sobek.IsUndefined(v) {
						username = v.String()
					}
					password := ""
					if v := o.Get("password"); v != nil && !sobek.IsUndefined(v) {
						password = v.String()
					}
					scope := ""
					if v := o.Get("scope"); v != nil && !sobek.IsUndefined(v) {
						scope = v.String()
					}

					// Build token request based on grant type
					var bodyParams url.Values
					switch authType {
					case "oauth2_client_credentials":
						bodyParams = url.Values{
							"grant_type":    {"client_credentials"},
							"client_id":     {clientID},
							"client_secret": {clientSecret},
						}
						if scope != "" {
							bodyParams.Set("scope", scope)
						}

					case "oauth2_password":
						bodyParams = url.Values{
							"grant_type": {"password"},
							"client_id":  {clientID},
							"username":   {username},
							"password":   {password},
						}
						if clientSecret != "" {
							bodyParams.Set("client_secret", clientSecret)
						}
						if scope != "" {
							bodyParams.Set("scope", scope)
						}

					case "oauth2_code":
						// For authorization code flow, we need a code.
						// The user must provide it or we fetch from auth_url.
						code := ""
						if v := o.Get("code"); v != nil && !sobek.IsUndefined(v) {
							code = v.String()
						}
						redirectURI := ""
						if v := o.Get("redirect_uri"); v != nil && !sobek.IsUndefined(v) {
							redirectURI = v.String()
						}

						if code == "" {
							zap.L().Debug("http.followAuth: oauth2_code requires 'code' parameter")
							return sobek.Undefined()
						}

						bodyParams = url.Values{
							"grant_type":   {"authorization_code"},
							"code":         {code},
							"client_id":    {clientID},
							"redirect_uri": {redirectURI},
						}
						if clientSecret != "" {
							bodyParams.Set("client_secret", clientSecret)
						}

					default:
						zap.L().Debug("http.followAuth: unsupported type", zap.String("type", authType))
						return sobek.Undefined()
					}

					body := bodyParams.Encode()
					headers := map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					}

					resp := doRequest(vm, opts.HTTPClient, "POST", tokenURL, body, headers)
					if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
						zap.L().Debug("http.followAuth: token request failed")
						return sobek.Undefined()
					}

					respObj := resp.ToObject(vm)
					respBody := ""
					if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
						respBody = v.String()
					}

					// Parse JSON response to extract access_token
					var tokenResp map[string]interface{}
					if err := json.Unmarshal([]byte(respBody), &tokenResp); err != nil {
						zap.L().Debug("http.followAuth: failed to parse token response", zap.Error(err))
						return sobek.Undefined()
					}

					accessToken := ""
					if v, ok := tokenResp["access_token"]; ok {
						accessToken = fmt.Sprintf("%v", v)
					}
					if accessToken == "" {
						zap.L().Debug("http.followAuth: no access_token in response")
						return sobek.Undefined()
					}

					tokenType := "Bearer"
					if v, ok := tokenResp["token_type"]; ok {
						tokenType = fmt.Sprintf("%v", v)
						// Capitalize first letter
						if len(tokenType) > 0 {
							tokenType = strings.ToUpper(tokenType[:1]) + tokenType[1:]
						}
					}

					// Create session with the token
					sessionHeaders := map[string]string{
						"Authorization": tokenType + " " + accessToken,
					}
					sess := newJSSession(vm, opts.HTTPClient, sessionHeaders, nil)
					sessObj := sess.toJSObject().ToObject(vm)
					registerInterceptorsOnSession(vm, sessObj, sess)

					// Expose token metadata on the session
					_ = sessObj.Set("access_token", accessToken)
					_ = sessObj.Set("token_type", tokenType)
					if v, ok := tokenResp["refresh_token"]; ok {
						_ = sessObj.Set("refresh_token", fmt.Sprintf("%v", v))
					}
					if v, ok := tokenResp["expires_in"]; ok {
						_ = sessObj.Set("expires_in", v)
					}

					return sessObj
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "retry",
			Category:    CatHTTP,
			Signature:   ".retry(request: string | FullRequestOptions, opts?: {max_retries?, backoff_ms?, retry_on?, until?})",
			Returns:     "{status, headers, body, raw} | null",
			Description: "Send an HTTP request with automatic retries and exponential backoff.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					reqVal := call.Argument(0)
					if sobek.IsUndefined(reqVal) || sobek.IsNull(reqVal) {
						return sobek.Null()
					}

					// Defaults
					maxRetries := 3
					backoffMs := 1000
					retryOn := map[int]bool{429: true, 502: true, 503: true}
					var untilFn sobek.Callable

					if optsVal := call.Argument(1); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						o := optsVal.ToObject(vm)

						if v := o.Get("max_retries"); v != nil && !sobek.IsUndefined(v) {
							mr := int(v.ToInteger())
							if mr > 0 && mr <= 10 {
								maxRetries = mr
							}
						}
						if v := o.Get("backoff_ms"); v != nil && !sobek.IsUndefined(v) {
							bm := int(v.ToInteger())
							if bm > 0 && bm <= 30000 {
								backoffMs = bm
							}
						}
						if v := o.Get("retry_on"); v != nil && !sobek.IsUndefined(v) {
							arr := v.ToObject(vm)
							length := int(arr.Get("length").ToInteger())
							retryOn = make(map[int]bool, length)
							for i := range length {
								code := int(arr.Get(fmt.Sprintf("%d", i)).ToInteger())
								retryOn[code] = true
							}
						}
						if v := o.Get("until"); v != nil && !sobek.IsUndefined(v) {
							fn, ok := sobek.AssertFunction(v)
							if ok {
								untilFn = fn
							}
						}
					}

					// Determine request type: raw string or structured request object
					isRaw := false
					rawReq := ""
					var reqMethod, reqURL, reqBody string
					reqHeaders := make(map[string]string)

					// Check if it's a string (raw HTTP request)
					exported := reqVal.Export()
					if s, ok := exported.(string); ok {
						isRaw = true
						rawReq = s
					} else {
						reqObj := reqVal.ToObject(vm)
						reqMethod = "GET"
						if v := reqObj.Get("method"); v != nil && !sobek.IsUndefined(v) {
							reqMethod = strings.ToUpper(v.String())
						}
						if v := reqObj.Get("url"); v != nil && !sobek.IsUndefined(v) {
							reqURL = v.String()
						}
						if v := reqObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
							reqBody = v.String()
						}
						if v := reqObj.Get("headers"); v != nil && !sobek.IsUndefined(v) {
							hObj := v.ToObject(vm)
							for _, key := range hObj.Keys() {
								reqHeaders[key] = hObj.Get(key).String()
							}
						}
					}

					httpClient := opts.HTTPClient

					sendRequest := func() sobek.Value {
						if isRaw {
							return doRawRequest(vm, httpClient, rawReq)
						}
						return doRequest(vm, httpClient, reqMethod, reqURL, reqBody, reqHeaders)
					}

					currentBackoff := backoffMs

					for attempt := 0; attempt <= maxRetries; attempt++ {
						if attempt > 0 {
							time.Sleep(time.Duration(currentBackoff) * time.Millisecond)
							currentBackoff *= 2 // exponential backoff
							if currentBackoff > 30000 {
								currentBackoff = 30000
							}
						}

						resp := sendRequest()

						if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
							continue // request failed entirely, retry
						}

						// Check custom until condition
						if untilFn != nil {
							result, err := untilFn(sobek.Undefined(), resp)
							if err == nil && result.ToBoolean() {
								return resp // success condition met
							}
							continue // condition not met, retry
						}

						// Check status code
						respObj := resp.ToObject(vm)
						statusVal := respObj.Get("status")
						if statusVal != nil && !sobek.IsUndefined(statusVal) {
							status := int(statusVal.ToInteger())
							if !retryOn[status] {
								return resp // not a retryable status, return
							}
						}
					}

					// All retries exhausted, return last attempt
					return sendRequest()
				}
			},
		},
	}
}
