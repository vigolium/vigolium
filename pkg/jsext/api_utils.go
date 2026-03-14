package jsext

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/anomaly"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// utilsFuncDefs returns the JSFuncDef entries for vigolium.utils.*.
func utilsFuncDefs() []JSFuncDef {
	defs := []JSFuncDef{
		{
			Namespace: NsUtils, Name: "base64Encode",
			Category: CatEncoding, Signature: ".base64Encode(s: string)", Returns: "string",
			Description: "Encode a string to base64.", Example: exBase64Encode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					return vm.ToValue(base64.StdEncoding.EncodeToString([]byte(s)))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "base64Decode",
			Category: CatEncoding, Signature: ".base64Decode(s: string)", Returns: "string",
			Description: "Decode a base64 string. Returns empty string on error.", Example: exBase64Decode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					decoded, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						return vm.ToValue("")
					}
					return vm.ToValue(string(decoded))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "urlEncode",
			Category: CatEncoding, Signature: ".urlEncode(s: string)", Returns: "string",
			Description: "URL-encode (percent-encode) a string.", Example: exURLEncode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					return vm.ToValue(url.QueryEscape(s))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "urlDecode",
			Category: CatEncoding, Signature: ".urlDecode(s: string)", Returns: "string",
			Description: "Decode a URL-encoded string.", Example: exURLDecode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					decoded, err := url.QueryUnescape(s)
					if err != nil {
						return vm.ToValue(s)
					}
					return vm.ToValue(decoded)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "htmlEncode",
			Category: CatEncoding, Signature: ".htmlEncode(s: string)", Returns: "string",
			Description: "HTML-escape a string.", Example: exHTMLEncode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					return vm.ToValue(html.EscapeString(s))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "htmlDecode",
			Category: CatEncoding, Signature: ".htmlDecode(s: string)", Returns: "string",
			Description: "Unescape HTML entities.", Example: exHTMLDecode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					return vm.ToValue(html.UnescapeString(s))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "sha1",
			Category: CatHashing, Signature: ".sha1(s: string)", Returns: "string",
			Description: "Compute SHA-1 hex digest.", Example: exSHA1,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					h := sha1.Sum([]byte(s))
					return vm.ToValue(hex.EncodeToString(h[:]))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "sha256",
			Category: CatHashing, Signature: ".sha256(s: string)", Returns: "string",
			Description: "Compute SHA-256 hex digest.", Example: exSHA256,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					h := sha256.Sum256([]byte(s))
					return vm.ToValue(hex.EncodeToString(h[:]))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "md5",
			Category: CatHashing, Signature: ".md5(s: string)", Returns: "string",
			Description: "Compute MD5 hex digest.", Example: exMD5,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					s := call.Argument(0).String()
					h := md5.Sum([]byte(s))
					return vm.ToValue(hex.EncodeToString(h[:]))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "randomString",
			Category: CatStrings, Signature: ".randomString(len: number)", Returns: "string",
			Description: "Generate a random alphanumeric string.", Example: exRandomString,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					n := int(call.Argument(0).ToInteger())
					if n <= 0 {
						n = 8
					}
					const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
					b := make([]byte, n)
					for i := range b {
						b[i] = chars[rand.Intn(len(chars))]
					}
					return vm.ToValue(string(b))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "sleep",
			Category: CatSystem, Signature: ".sleep(ms: number)", Returns: "void",
			Description: "Sleep for the given number of milliseconds (max 30000).", Example: exSleep,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					ms := call.Argument(0).ToInteger()
					if ms > 0 && ms <= 30000 { // cap at 30s
						time.Sleep(time.Duration(ms) * time.Millisecond)
					}
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace: NsUtils, Name: "exec",
			Category: CatSystem, Signature: ".exec(cmd: string)", Returns: "{stdout, stderr, exitCode}",
			Description: "Execute a shell command.", Example: exExec,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					if !opts.AllowExec {
						zap.L().Warn("exec() blocked: extensions.allow_exec is false",
							zap.String("ext", opts.ScriptID))
						result := vm.NewObject()
						_ = result.Set("stdout", "")
						_ = result.Set("stderr", "exec() is disabled; set extensions.allow_exec: true")
						_ = result.Set("exitCode", -1)
						return result
					}

					cmd := call.Argument(0).String()
					timeout := opts.ExecTimeout
					if timeout <= 0 {
						timeout = 30
					}
					if timeout > 120 {
						timeout = 120
					}

					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
					defer cancel()

					c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
					var stdout, stderr strings.Builder
					c.Stdout = &stdout
					c.Stderr = &stderr

					err := c.Run()
					exitCode := 0
					if err != nil {
						if exitErr, ok := err.(*exec.ExitError); ok {
							exitCode = exitErr.ExitCode()
						} else {
							exitCode = -1
						}
					}

					result := vm.NewObject()
					_ = result.Set("stdout", stdout.String())
					_ = result.Set("stderr", stderr.String())
					_ = result.Set("exitCode", exitCode)
					return result
				}
			},
		},
		{
			Namespace: NsUtils, Name: "getEnv",
			Category: CatSystem, Signature: ".getEnv(name: string)", Returns: "string",
			Description: "Read an environment variable.", Example: exGetEnv,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					name := call.Argument(0).String()
					return vm.ToValue(os.Getenv(name))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "setEnv",
			Category: CatSystem, Signature: ".setEnv(name: string, val: string)", Returns: "bool",
			Description: "Set an environment variable.", Example: exSetEnv,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					if !opts.AllowExec {
						zap.L().Warn("setEnv() blocked: extensions.allow_exec is false",
							zap.String("ext", opts.ScriptID))
						return vm.ToValue(false)
					}
					name := call.Argument(0).String()
					value := call.Argument(1).String()
					if err := os.Setenv(name, value); err != nil {
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "glob",
			Category: CatFileIO, Signature: ".glob(pattern: string)", Returns: "string[]",
			Description: "Find files matching a glob pattern.", Example: exGlob,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					pattern := call.Argument(0).String()
					resolved, err := resolveSandboxPath(pattern, opts.SandboxDir)
					if err != nil {
						return vm.NewArray()
					}
					matches, err := filepath.Glob(resolved)
					if err != nil {
						return vm.NewArray()
					}
					jsArr := make([]interface{}, len(matches))
					for i, m := range matches {
						jsArr[i] = m
					}
					return vm.ToValue(jsArr)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "readFile",
			Category: CatFileIO, Signature: ".readFile(path: string)", Returns: "string",
			Description: "Read a file's contents.", Example: exReadFile,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					resolved, err := resolveSandboxPath(path, opts.SandboxDir)
					if err != nil {
						return vm.ToValue("")
					}
					data, err := os.ReadFile(resolved)
					if err != nil {
						return vm.ToValue("")
					}
					return vm.ToValue(string(data))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "readLines",
			Category: CatFileIO, Signature: ".readLines(path: string)", Returns: "string[]",
			Description: "Read a file as an array of lines.", Example: exReadLines,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					resolved, err := resolveSandboxPath(path, opts.SandboxDir)
					if err != nil {
						return vm.NewArray()
					}
					data, err := os.ReadFile(resolved)
					if err != nil {
						return vm.NewArray()
					}
					lines := strings.Split(string(data), "\n")
					jsArr := make([]interface{}, len(lines))
					for i, l := range lines {
						jsArr[i] = l
					}
					return vm.ToValue(jsArr)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "writeFile",
			Category: CatFileIO, Signature: ".writeFile(path: string, data: string)", Returns: "bool",
			Description: "Write data to a file.", Example: exWriteFile,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					data := call.Argument(1).String()
					resolved, err := resolveSandboxPath(path, opts.SandboxDir)
					if err != nil {
						return vm.ToValue(false)
					}
					if err := os.WriteFile(resolved, []byte(data), 0644); err != nil {
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "mkdir",
			Category: CatFileIO, Signature: ".mkdir(path: string)", Returns: "bool",
			Description: "Create a directory.", Example: exMkdir,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					resolved, err := resolveSandboxPath(path, opts.SandboxDir)
					if err != nil {
						return vm.ToValue(false)
					}
					if err := os.MkdirAll(resolved, 0755); err != nil {
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "jsonExtract",
			Category: CatExtract, Signature: ".jsonExtract(json: string, path: string)", Returns: "any",
			Description: "Extract a value from JSON.", Example: exJSONExtract,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					jsonStr := call.Argument(0).String()
					path := call.Argument(1).String()

					var data interface{}
					if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
						return sobek.Undefined()
					}

					result := walkJSONPath(data, path)
					if result == nil {
						return sobek.Undefined()
					}
					return vm.ToValue(result)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "regexMatch",
			Category: CatExtract, Signature: ".regexMatch(str: string, pattern: string)", Returns: "bool",
			Description: "Test regex match.", Example: exRegexMatch,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					str := call.Argument(0).String()
					pattern := call.Argument(1).String()
					matched, err := regexp.MatchString(pattern, str)
					if err != nil {
						return vm.ToValue(false)
					}
					return vm.ToValue(matched)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "regexExtract",
			Category: CatExtract, Signature: ".regexExtract(str: string, pattern: string)", Returns: "string | string[] | null",
			Description: "Extract regex match.", Example: exRegexExtract,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					str := call.Argument(0).String()
					pattern := call.Argument(1).String()
					re, err := regexp.Compile(pattern)
					if err != nil {
						return sobek.Null()
					}
					matches := re.FindStringSubmatch(str)
					if matches == nil {
						return sobek.Null()
					}
					// Return first capture group if present, or full match
					if len(matches) > 1 {
						if len(matches) == 2 {
							return vm.ToValue(matches[1])
						}
						// Multiple capture groups: return array of groups (excluding full match)
						groups := make([]interface{}, len(matches)-1)
						for i, m := range matches[1:] {
							groups[i] = m
						}
						return vm.ToValue(groups)
					}
					return vm.ToValue(matches[0])
				}
			},
		},
		{
			Namespace: NsUtils, Name: "regexFindAll",
			Category: CatExtract, Signature: ".regexFindAll(str: string, pattern: string)", Returns: "string[] | null",
			Description: "Return all non-overlapping matches of pattern in str.", Example: exRegexFindAll,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					str := call.Argument(0).String()
					pattern := call.Argument(1).String()
					re, err := regexp.Compile(pattern)
					if err != nil {
						return sobek.Null()
					}
					matches := re.FindAllString(str, -1)
					if matches == nil {
						return sobek.Null()
					}
					result := make([]interface{}, len(matches))
					for i, m := range matches {
						result[i] = m
					}
					return vm.ToValue(result)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "parse_url",
			Category: CatExtract, Signature: ".parse_url(url: string, format: string)", Returns: "string",
			Description: "Parse a URL.", Example: exParseURL,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					rawURL := call.Argument(0).String()
					format := call.Argument(1).String()
					return vm.ToValue(formatURL(rawURL, format))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "parse_url_file",
			Category: CatExtract, Signature: ".parse_url_file(input: string, format: string, output: string)", Returns: "bool",
			Description: "Parse URLs from file.", Example: exParseURLFile,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					input := call.Argument(0).String()
					format := call.Argument(1).String()
					output := call.Argument(2).String()

					resolvedInput, err := resolveSandboxPath(input, opts.SandboxDir)
					if err != nil {
						return vm.ToValue(false)
					}
					resolvedOutput, err := resolveSandboxPath(output, opts.SandboxDir)
					if err != nil {
						return vm.ToValue(false)
					}

					data, err := os.ReadFile(resolvedInput)
					if err != nil {
						return vm.ToValue(false)
					}

					seen := make(map[string]struct{})
					var results []string
					for _, line := range strings.Split(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						formatted := formatURL(line, format)
						if _, ok := seen[formatted]; !ok {
							seen[formatted] = struct{}{}
							results = append(results, formatted)
						}
					}

					if err := os.WriteFile(resolvedOutput, []byte(strings.Join(results, "\n")+"\n"), 0644); err != nil {
						return vm.ToValue(false)
					}
					return vm.ToValue(true)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "pathToTemplate",
			Category: "Utils", Signature: ".pathToTemplate(path: string)", Returns: "string",
			Description: "Convert a URL path to a template with dynamic segments replaced.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					return vm.ToValue(database.PathToTemplate(path))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "hasDynamicSegment",
			Category: "Utils", Signature: ".hasDynamicSegment(path: string)", Returns: "bool",
			Description: "Check if a URL path contains dynamic segments.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					path := call.Argument(0).String()
					return vm.ToValue(database.HasDynamicSegment(path))
				}
			},
		},
		{
			Namespace: NsUtils, Name: "toSet",
			Category: "Utils", Signature: ".toSet(csv: string)", Returns: "object",
			Description: "Convert a comma-separated string to a set object.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					csv := call.Argument(0).String()
					obj := vm.NewObject()
					for _, part := range strings.Split(csv, ",") {
						part = strings.TrimSpace(part)
						if part != "" {
							_ = obj.Set(part, true)
						}
					}
					return obj
				}
			},
		},
		{
			Namespace: NsUtils, Name: "extractParamNames",
			Category: "Utils", Signature: ".extractParamNames(str: string)", Returns: "string[]",
			Description: "Extract parameter names from a query string.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					str := call.Argument(0).String()
					if str == "" {
						return vm.NewArray()
					}
					re := regexp.MustCompile(`(?:^|[&?])([A-Za-z0-9_.\-\[\]]+)=`)
					matches := re.FindAllStringSubmatch(str, -1)
					seen := make(map[string]struct{}, len(matches))
					var names []interface{}
					for _, m := range matches {
						name := strings.ToLower(m[1])
						if _, ok := seen[name]; !ok {
							seen[name] = struct{}{}
							names = append(names, name)
						}
					}
					if len(names) == 0 {
						return vm.NewArray()
					}
					return vm.ToValue(names)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "detectAnomaly",
			Category: CatDetection, Signature: ".detectAnomaly(responses: object[])", Returns: "{index, score}[]",
			Description: "Rank responses by anomaly.", Example: exDetectAnomaly,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					arg := call.Argument(0)
					if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
						return vm.NewArray()
					}

					arr := arg.ToObject(vm)
					length := arr.Get("length")
					if length == nil || sobek.IsUndefined(length) {
						return vm.NewArray()
					}
					n := int(length.ToInteger())
					if n < 2 {
						return vm.NewArray() // need at least 2 responses to compare
					}

					// Build ResponseRecords from JS array
					engine := anomaly.NewDefaultEngine()
					records := make([]*anomaly.ResponseRecord, 0, n)
					for i := range n {
						item := arr.Get(fmt.Sprintf("%d", i)).ToObject(vm)
						statusCode := 0
						body := ""
						headers := make(map[string][]string)

						if v := item.Get("status"); v != nil && !sobek.IsUndefined(v) {
							statusCode = int(v.ToInteger())
						}
						if v := item.Get("body"); v != nil && !sobek.IsUndefined(v) {
							body = v.String()
						}
						if v := item.Get("headers"); v != nil && !sobek.IsUndefined(v) {
							headersObj := v.ToObject(vm)
							for _, key := range headersObj.Keys() {
								headers[key] = []string{headersObj.Get(key).String()}
							}
						}

						attrs, err := anomaly.ExtractAttributesFromRaw(statusCode, body, headers)
						if err != nil {
							continue
						}
						records = append(records, anomaly.NewResponseRecord(*attrs, i))
					}

					if len(records) < 2 {
						return vm.NewArray()
					}

					// Rank and sort
					if err := engine.RankAndSort(records); err != nil {
						return vm.NewArray()
					}

					// Build result array
					results := make([]interface{}, len(records))
					for i, rec := range records {
						result := map[string]interface{}{
							"index": rec.Metadata,
							"score": rec.Score,
						}
						results[i] = result
					}
					return vm.ToValue(results)
				}
			},
		},
		{
			Namespace: NsUtils, Name: "diff",
			Category: "Utils", Signature: ".diff(a: string, b: string)", Returns: "{added: string[], removed: string[], similarity: number}",
			Description: "Compute line-level diff between two strings.", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					a := call.Argument(0).String()
					b := call.Argument(1).String()

					// Cap input size at 1MB
					const maxSize = 1 << 20
					if len(a) > maxSize {
						a = a[:maxSize]
					}
					if len(b) > maxSize {
						b = b[:maxSize]
					}

					linesA := strings.Split(a, "\n")
					linesB := strings.Split(b, "\n")

					setA := make(map[string]bool, len(linesA))
					setB := make(map[string]bool, len(linesB))
					for _, l := range linesA {
						setA[l] = true
					}
					for _, l := range linesB {
						setB[l] = true
					}

					var added, removed []interface{}
					for _, l := range linesB {
						if !setA[l] {
							added = append(added, l)
						}
					}
					for _, l := range linesA {
						if !setB[l] {
							removed = append(removed, l)
						}
					}

					// Dice coefficient on lines
					common := 0
					for l := range setA {
						if setB[l] {
							common++
						}
					}
					similarity := 0.0
					if len(setA)+len(setB) > 0 {
						similarity = float64(2*common) / float64(len(setA)+len(setB))
					}

					result := vm.NewObject()
					if added == nil {
						added = []interface{}{}
					}
					if removed == nil {
						removed = []interface{}{}
					}
					_ = result.Set("added", vm.ToValue(added))
					_ = result.Set("removed", vm.ToValue(removed))
					_ = result.Set("similarity", similarity)
					return result
				}
			},
		},
		{
			Namespace: NsUtils, Name: "similarity",
			Category: "Utils", Signature: ".similarity(a: string, b: string)", Returns: "number",
			Description: "Compute Jaccard similarity on word-level tokens (0.0 to 1.0).", Example: "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					a := call.Argument(0).String()
					b := call.Argument(1).String()

					wordRe := regexp.MustCompile(`\w+`)
					tokensA := wordRe.FindAllString(a, -1)
					tokensB := wordRe.FindAllString(b, -1)

					setA := make(map[string]bool, len(tokensA))
					for _, t := range tokensA {
						setA[strings.ToLower(t)] = true
					}
					setB := make(map[string]bool, len(tokensB))
					for _, t := range tokensB {
						setB[strings.ToLower(t)] = true
					}

					intersection := 0
					for t := range setA {
						if setB[t] {
							intersection++
						}
					}

					// Union = |A| + |B| - |intersection|
					union := len(setA) + len(setB) - intersection
					if union == 0 {
						return vm.ToValue(1.0) // both empty = identical
					}

					return vm.ToValue(float64(intersection) / float64(union))
				}
			},
		},
	}

	// Append sub-file func defs
	defs = append(defs, jwtUtilsFuncDefs()...)
	defs = append(defs, multipartUtilsFuncDefs()...)
	defs = append(defs, responseUtilsFuncDefs()...)
	defs = append(defs, tokenUtilsFuncDefs()...)

	return defs
}

// resolveSandboxPath validates that a path is within the sandbox directory.
func resolveSandboxPath(path, sandboxDir string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if sandboxDir == "" {
		return abs, nil
	}
	sandboxAbs, err := filepath.Abs(sandboxDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, sandboxAbs+string(filepath.Separator)) && abs != sandboxAbs {
		return "", fmt.Errorf("path outside sandbox: %s", path)
	}
	return abs, nil
}

// formatURL parses rawURL and formats it using printf-style directives.
func formatURL(rawURL, format string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		return ""
	}

	hostname := u.Hostname()
	port := u.Port()

	// Determine if port is default for the scheme.
	defaultPort := ""
	switch u.Scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	}
	displayPort := port
	if port == defaultPort {
		displayPort = ""
	}

	// Split hostname into parts for subdomain/root/TLD extraction.
	parts := strings.Split(hostname, ".")
	var tld, rootDomain, subdomain string
	switch {
	case len(parts) >= 3:
		tld = parts[len(parts)-1]
		rootDomain = parts[len(parts)-2] + "." + tld
		subdomain = strings.Join(parts[:len(parts)-2], ".")
	case len(parts) == 2:
		tld = parts[1]
		rootDomain = hostname
	case len(parts) == 1:
		rootDomain = hostname
	}

	// File extension: last segment of path after final dot.
	ext := ""
	base := filepath.Base(u.Path)
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		ext = base[idx+1:]
	}

	// Authority: host or host:port.
	authority := hostname
	if port != "" && displayPort != "" {
		authority = hostname + ":" + port
	}

	// Walk format string and replace directives.
	var buf strings.Builder
	buf.Grow(len(format) + 32)
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			i++
			switch format[i] {
			case 's':
				buf.WriteString(u.Scheme)
			case 'd':
				buf.WriteString(hostname)
			case 'S':
				buf.WriteString(subdomain)
			case 'r':
				buf.WriteString(rootDomain)
			case 't':
				buf.WriteString(tld)
			case 'P':
				buf.WriteString(displayPort)
			case 'p':
				buf.WriteString(u.Path)
			case 'e':
				buf.WriteString(ext)
			case 'q':
				buf.WriteString(u.RawQuery)
			case 'f':
				buf.WriteString(u.Fragment)
			case 'a':
				buf.WriteString(authority)
			case '%':
				buf.WriteByte('%')
			default:
				buf.WriteByte('%')
				buf.WriteByte(format[i])
			}
		} else {
			buf.WriteByte(format[i])
		}
	}
	return buf.String()
}

// walkJSONPath walks a parsed JSON value with a dot-path like "a.b.0.c".
func walkJSONPath(data interface{}, path string) interface{} {
	if path == "" {
		return data
	}
	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if current == nil {
			return nil
		}
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case []interface{}:
			idx := 0
			if _, err := fmt.Sscanf(part, "%d", &idx); err != nil || idx < 0 || idx >= len(v) {
				return nil
			}
			current = v[idx]
		default:
			return nil
		}
	}
	return current
}
