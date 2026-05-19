package jsext

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
	"time"

	"github.com/grafana/sobek"
)

// jwtUtilsFuncDefs returns the JSFuncDef entries for JWT utilities in vigolium.utils.*.
func jwtUtilsFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsUtils, Name: "jwtDecode",
			Category: "JWT", Signature: ".jwtDecode(token: string)", Returns: "{header, payload, signature} | null",
			Description: "Decode a JWT token into its header, payload, and signature parts.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					token := call.Argument(0).String()
					parts := strings.SplitN(token, ".", 3)
					if len(parts) != 3 {
						return sobek.Null()
					}

					headerJSON, err := base64URLDecode(parts[0])
					if err != nil {
						return sobek.Null()
					}
					payloadJSON, err := base64URLDecode(parts[1])
					if err != nil {
						return sobek.Null()
					}

					var header interface{}
					if err := json.Unmarshal(headerJSON, &header); err != nil {
						return sobek.Null()
					}
					var payload interface{}
					if err := json.Unmarshal(payloadJSON, &payload); err != nil {
						return sobek.Null()
					}

					result := vm.NewObject()
					_ = result.Set("header", vm.ToValue(header))
					_ = result.Set("payload", vm.ToValue(payload))
					_ = result.Set("signature", parts[2])
					return result
				}
			},
		},
		{
			Namespace: NsUtils, Name: "jwtEncode",
			Category: "JWT", Signature: ".jwtEncode(payload: object, opts?: {algorithm?: string, secret?: string})", Returns: "string",
			Description: "Encode a payload as a JWT token.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					payloadVal := call.Argument(0)
					if sobek.IsUndefined(payloadVal) || sobek.IsNull(payloadVal) {
						return vm.ToValue("")
					}

					algorithm := "HS256"
					secret := ""

					if optsVal := call.Argument(1); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						optsObj := optsVal.ToObject(vm)
						if v := optsObj.Get("algorithm"); v != nil && !sobek.IsUndefined(v) {
							algorithm = strings.ToUpper(v.String())
						}
						if v := optsObj.Get("secret"); v != nil && !sobek.IsUndefined(v) {
							secret = v.String()
						}
					}

					// Build header
					header := map[string]string{
						"alg": algorithm,
						"typ": "JWT",
					}
					headerJSON, err := json.Marshal(header)
					if err != nil {
						return vm.ToValue("")
					}

					// Marshal payload
					payloadJSON, err := json.Marshal(payloadVal.Export())
					if err != nil {
						return vm.ToValue("")
					}

					headerB64 := base64URLEncode(headerJSON)
					payloadB64 := base64URLEncode(payloadJSON)
					signingInput := headerB64 + "." + payloadB64

					var signature string
					switch algorithm {
					case "NONE":
						signature = ""
					case "HS256":
						signature = base64URLEncode(hmacSign(sha256.New, []byte(secret), []byte(signingInput)))
					case "HS384":
						signature = base64URLEncode(hmacSign(sha512.New384, []byte(secret), []byte(signingInput)))
					case "HS512":
						signature = base64URLEncode(hmacSign(sha512.New, []byte(secret), []byte(signingInput)))
					default:
						// Unsupported algorithm — produce unsigned token
						signature = ""
					}

					return vm.ToValue(signingInput + "." + signature)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "jwtExpired",
			Category: "JWT", Signature: ".jwtExpired(token: string)", Returns: "bool",
			Description: "Check if a JWT token is expired.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					token := call.Argument(0).String()
					parts := strings.SplitN(token, ".", 3)
					if len(parts) != 3 {
						return vm.ToValue(true) // malformed = treat as expired
					}

					payloadJSON, err := base64URLDecode(parts[1])
					if err != nil {
						return vm.ToValue(true)
					}

					var claims map[string]interface{}
					if err := json.Unmarshal(payloadJSON, &claims); err != nil {
						return vm.ToValue(true)
					}

					expVal, ok := claims["exp"]
					if !ok {
						return vm.ToValue(false) // no exp claim = never expires
					}

					expFloat, ok := expVal.(float64)
					if !ok {
						return vm.ToValue(true)
					}

					return vm.ToValue(time.Now().Unix() > int64(expFloat))
				}
			},
		},
	}
}

// base64URLDecode decodes a base64url string (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// hmacSign computes HMAC with the given hash function.
func hmacSign(hashFunc func() hash.Hash, key, data []byte) []byte {
	h := hmac.New(hashFunc, key)
	h.Write(data)
	return h.Sum(nil)
}
