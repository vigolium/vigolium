package jsext

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/grafana/sobek"
)

// multipartUtilsFuncDefs returns the JSFuncDef entries for the multipart builder in vigolium.utils.*.
func multipartUtilsFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsUtils, Name: "multipart",
			Category: "Utils", Signature: ".multipart(fields: object[])", Returns: "{body: string, contentType: string}",
			Description: "Build a multipart/form-data body from an array of field objects.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					fieldsVal := call.Argument(0)
					if sobek.IsUndefined(fieldsVal) || sobek.IsNull(fieldsVal) {
						result := vm.NewObject()
						_ = result.Set("body", "")
						_ = result.Set("contentType", "")
						return result
					}

					fieldsArr := fieldsVal.ToObject(vm)
					length := int(fieldsArr.Get("length").ToInteger())
					if length == 0 {
						result := vm.NewObject()
						_ = result.Set("body", "")
						_ = result.Set("contentType", "")
						return result
					}

					boundary := "----VigoliumBoundary" + randomBoundary()

					var sb strings.Builder
					for i := range length {
						field := fieldsArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)

						name := ""
						if v := field.Get("name"); v != nil && !sobek.IsUndefined(v) {
							name = v.String()
						}

						filename := ""
						if v := field.Get("filename"); v != nil && !sobek.IsUndefined(v) {
							filename = v.String()
						}

						contentType := ""
						if v := field.Get("contentType"); v != nil && !sobek.IsUndefined(v) {
							contentType = v.String()
						}

						// Use data field for file content, value for text
						content := ""
						if v := field.Get("data"); v != nil && !sobek.IsUndefined(v) {
							content = v.String()
						} else if v := field.Get("value"); v != nil && !sobek.IsUndefined(v) {
							content = v.String()
						}

						sb.WriteString("--")
						sb.WriteString(boundary)
						sb.WriteString("\r\n")

						if filename != "" {
							// File upload part
							fmt.Fprintf(&sb, "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n", name, filename)
							if contentType == "" {
								contentType = "application/octet-stream"
							}
							fmt.Fprintf(&sb, "Content-Type: %s\r\n", contentType)
						} else {
							// Text field
							fmt.Fprintf(&sb, "Content-Disposition: form-data; name=\"%s\"\r\n", name)
							if contentType != "" {
								fmt.Fprintf(&sb, "Content-Type: %s\r\n", contentType)
							}
						}

						sb.WriteString("\r\n")
						sb.WriteString(content)
						sb.WriteString("\r\n")
					}

					sb.WriteString("--")
					sb.WriteString(boundary)
					sb.WriteString("--\r\n")

					result := vm.NewObject()
					_ = result.Set("body", sb.String())
					_ = result.Set("contentType", "multipart/form-data; boundary="+boundary)
					return result
				}
			},
		},
	}
}

// randomBoundary generates a short random string for multipart boundaries.
func randomBoundary() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = chars[fastRandInt(len(chars))]
	}
	return string(b)
}

// fastRandInt returns a random int in [0, n) using math/rand.
func fastRandInt(n int) int {
	return rand.Intn(n)
}
