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

// setupUtilsAPI registers vigolium.utils.* functions on the VM.
func setupUtilsAPI(vm *sobek.Runtime, opts APIOptions) {
	utilsObj := vm.NewObject()

	// --- Existing encoding/hashing functions ---

	_ = utilsObj.Set("base64Encode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		return vm.ToValue(base64.StdEncoding.EncodeToString([]byte(s)))
	})

	_ = utilsObj.Set("base64Decode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return vm.ToValue("")
		}
		return vm.ToValue(string(decoded))
	})

	_ = utilsObj.Set("urlEncode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		return vm.ToValue(url.QueryEscape(s))
	})

	_ = utilsObj.Set("urlDecode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		decoded, err := url.QueryUnescape(s)
		if err != nil {
			return vm.ToValue(s)
		}
		return vm.ToValue(decoded)
	})

	_ = utilsObj.Set("sha1", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		h := sha1.Sum([]byte(s))
		return vm.ToValue(hex.EncodeToString(h[:]))
	})

	_ = utilsObj.Set("sha256", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		h := sha256.Sum256([]byte(s))
		return vm.ToValue(hex.EncodeToString(h[:]))
	})

	_ = utilsObj.Set("md5", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		h := md5.Sum([]byte(s))
		return vm.ToValue(hex.EncodeToString(h[:]))
	})

	_ = utilsObj.Set("randomString", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("htmlEncode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		return vm.ToValue(html.EscapeString(s))
	})

	_ = utilsObj.Set("htmlDecode", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		return vm.ToValue(html.UnescapeString(s))
	})

	_ = utilsObj.Set("sleep", func(call sobek.FunctionCall) sobek.Value {
		ms := call.Argument(0).ToInteger()
		if ms > 0 && ms <= 30000 { // cap at 30s
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		return sobek.Undefined()
	})

	// --- New shell/OS functions ---

	_ = utilsObj.Set("exec", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("glob", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("readFile", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("readLines", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("writeFile", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("mkdir", func(call sobek.FunctionCall) sobek.Value {
		path := call.Argument(0).String()
		resolved, err := resolveSandboxPath(path, opts.SandboxDir)
		if err != nil {
			return vm.ToValue(false)
		}
		if err := os.MkdirAll(resolved, 0755); err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(true)
	})

	_ = utilsObj.Set("getEnv", func(call sobek.FunctionCall) sobek.Value {
		name := call.Argument(0).String()
		return vm.ToValue(os.Getenv(name))
	})

	_ = utilsObj.Set("setEnv", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// --- Data processing functions ---

	_ = utilsObj.Set("jsonExtract", func(call sobek.FunctionCall) sobek.Value {
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
	})

	_ = utilsObj.Set("regexMatch", func(call sobek.FunctionCall) sobek.Value {
		str := call.Argument(0).String()
		pattern := call.Argument(1).String()
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(matched)
	})

	_ = utilsObj.Set("regexExtract", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// --- URL parsing ---

	_ = utilsObj.Set("parse_url", func(call sobek.FunctionCall) sobek.Value {
		rawURL := call.Argument(0).String()
		format := call.Argument(1).String()
		return vm.ToValue(formatURL(rawURL, format))
	})

	_ = utilsObj.Set("parse_url_file", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// --- Path utilities ---

	_ = utilsObj.Set("pathToTemplate", func(call sobek.FunctionCall) sobek.Value {
		path := call.Argument(0).String()
		return vm.ToValue(database.PathToTemplate(path))
	})

	_ = utilsObj.Set("hasDynamicSegment", func(call sobek.FunctionCall) sobek.Value {
		path := call.Argument(0).String()
		return vm.ToValue(database.HasDynamicSegment(path))
	})

	// --- String set / param helpers ---

	_ = utilsObj.Set("toSet", func(call sobek.FunctionCall) sobek.Value {
		csv := call.Argument(0).String()
		obj := vm.NewObject()
		for _, part := range strings.Split(csv, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				_ = obj.Set(part, true)
			}
		}
		return obj
	})

	_ = utilsObj.Set("extractParamNames", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// --- Anomaly detection ---

	_ = utilsObj.Set("detectAnomaly", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// --- Diff and similarity ---

	// vigolium.utils.diff(a, b) -> {added: string[], removed: string[], similarity: number}
	_ = utilsObj.Set("diff", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// vigolium.utils.similarity(a, b) -> number (0.0 to 1.0)
	// Jaccard similarity on word-level tokens
	_ = utilsObj.Set("similarity", func(call sobek.FunctionCall) sobek.Value {
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
	})

	// Register extractToken API
	registerUtilsTokenAPI(vm, utilsObj)

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("utils", utilsObj)
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
