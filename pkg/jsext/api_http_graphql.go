package jsext

import (
	"encoding/json"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// httpGraphQLFuncDefs returns JSFuncDefs for the GraphQL HTTP functions.
func httpGraphQLFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsHTTP,
			Name:        "graphql",
			Category:    CatHTTP,
			Signature:   ".graphql(url: string, opts: {query, variables?, operation?, headers?, session?})",
			Returns:     "{data, errors, raw}",
			Description: "Send a GraphQL query and return parsed data, errors, and raw response.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					optsVal := call.Argument(1)
					if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
						zap.L().Debug("http.graphql: opts is required")
						return sobek.Null()
					}
					o := optsVal.ToObject(vm)

					query := ""
					if v := o.Get("query"); v != nil && !sobek.IsUndefined(v) {
						query = v.String()
					}
					if query == "" {
						zap.L().Debug("http.graphql: query is required")
						return sobek.Null()
					}

					// Build GraphQL request body
					gqlBody := map[string]interface{}{
						"query": query,
					}

					if v := o.Get("variables"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						gqlBody["variables"] = v.Export()
					}
					if v := o.Get("operation"); v != nil && !sobek.IsUndefined(v) {
						gqlBody["operationName"] = v.String()
					}

					bodyBytes, err := json.Marshal(gqlBody)
					if err != nil {
						zap.L().Debug("http.graphql: failed to marshal body", zap.Error(err))
						return sobek.Null()
					}

					headers := map[string]string{
						"Content-Type": "application/json",
					}

					// Merge custom headers
					if v := o.Get("headers"); v != nil && !sobek.IsUndefined(v) {
						headersObj := v.ToObject(vm)
						for _, key := range headersObj.Keys() {
							headers[key] = headersObj.Get(key).String()
						}
					}

					// Use session if provided
					var resp sobek.Value
					if v := o.Get("session"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						sessObj := v.ToObject(vm)
						// Call session.request({method, url, body, headers})
						requestFn, ok := sobek.AssertFunction(sessObj.Get("request"))
						if ok {
							reqOpts := vm.NewObject()
							_ = reqOpts.Set("method", "POST")
							_ = reqOpts.Set("url", urlStr)
							_ = reqOpts.Set("body", string(bodyBytes))
							headersJSObj := vm.NewObject()
							for k, v := range headers {
								_ = headersJSObj.Set(k, v)
							}
							_ = reqOpts.Set("headers", headersJSObj)
							resp, err = requestFn(sessObj, reqOpts)
							if err != nil {
								zap.L().Debug("http.graphql: session request failed", zap.Error(err))
								return sobek.Null()
							}
						}
					}

					if resp == nil || sobek.IsUndefined(resp) || sobek.IsNull(resp) {
						resp = doRequest(vm, opts.HTTPClient, "POST", urlStr, string(bodyBytes), headers)
					}

					if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
						return sobek.Null()
					}

					// Parse response
					respObj := resp.ToObject(vm)
					respBody := ""
					if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
						respBody = v.String()
					}

					result := vm.NewObject()

					var gqlResp map[string]interface{}
					if err := json.Unmarshal([]byte(respBody), &gqlResp); err != nil {
						// Return raw response even if not valid JSON
						_ = result.Set("data", sobek.Null())
						_ = result.Set("errors", vm.NewArray())
						_ = result.Set("raw", resp)
						return result
					}

					if data, ok := gqlResp["data"]; ok {
						_ = result.Set("data", vm.ToValue(data))
					} else {
						_ = result.Set("data", sobek.Null())
					}

					if errors, ok := gqlResp["errors"]; ok {
						_ = result.Set("errors", vm.ToValue(errors))
					} else {
						_ = result.Set("errors", vm.NewArray())
					}

					_ = result.Set("raw", resp)
					return result
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "graphqlSchema",
			Category:    CatHTTP,
			Signature:   ".graphqlSchema(url: string, opts?: {headers?, session?})",
			Returns:     "object | null",
			Description: "Fetch a GraphQL schema via introspection query.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()
					if urlStr == "" {
						return sobek.Null()
					}

					introspectionQuery := `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        isDeprecated deprecationReason
      }
      inputFields { name description type { kind name ofType { kind name } } }
      interfaces { kind name }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { kind name }
    }
    directives { name description locations args { name description type { kind name ofType { kind name } } } }
  }
}`

					headers := map[string]string{
						"Content-Type": "application/json",
					}

					// Use session if provided
					if optsVal := call.Argument(1); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						o := optsVal.ToObject(vm)
						if v := o.Get("headers"); v != nil && !sobek.IsUndefined(v) {
							headersObj := v.ToObject(vm)
							for _, key := range headersObj.Keys() {
								headers[key] = headersObj.Get(key).String()
							}
						}

						if v := o.Get("session"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
							sessObj := v.ToObject(vm)
							requestFn, ok := sobek.AssertFunction(sessObj.Get("request"))
							if ok {
								gqlBody := map[string]interface{}{
									"query": introspectionQuery,
								}
								bodyBytes, _ := json.Marshal(gqlBody)
								reqOpts := vm.NewObject()
								_ = reqOpts.Set("method", "POST")
								_ = reqOpts.Set("url", urlStr)
								_ = reqOpts.Set("body", string(bodyBytes))
								headersJSObj := vm.NewObject()
								for k, v := range headers {
									_ = headersJSObj.Set(k, v)
								}
								_ = reqOpts.Set("headers", headersJSObj)
								resp, err := requestFn(sessObj, reqOpts)
								if err == nil && !sobek.IsUndefined(resp) && !sobek.IsNull(resp) {
									return parseGraphQLSchemaResponse(vm, resp)
								}
							}
						}
					}

					gqlBody := map[string]interface{}{
						"query": introspectionQuery,
					}
					bodyBytes, _ := json.Marshal(gqlBody)
					resp := doRequest(vm, opts.HTTPClient, "POST", urlStr, string(bodyBytes), headers)
					if sobek.IsUndefined(resp) || sobek.IsNull(resp) {
						return sobek.Null()
					}
					return parseGraphQLSchemaResponse(vm, resp)
				}
			},
		},
	}
}

// parseGraphQLSchemaResponse extracts the __schema from an introspection response.
func parseGraphQLSchemaResponse(vm *sobek.Runtime, resp sobek.Value) sobek.Value {
	respObj := resp.ToObject(vm)
	respBody := ""
	if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
		respBody = v.String()
	}

	var gqlResp map[string]interface{}
	if err := json.Unmarshal([]byte(respBody), &gqlResp); err != nil {
		return sobek.Null()
	}

	data, ok := gqlResp["data"]
	if !ok {
		return sobek.Null()
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return sobek.Null()
	}

	schema, ok := dataMap["__schema"]
	if !ok {
		return sobek.Null()
	}

	return vm.ToValue(schema)
}
