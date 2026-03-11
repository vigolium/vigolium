package jsext

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"golang.org/x/net/html"
)

// setupParseAPI registers vigolium.parse.* functions on the VM.
// These functions provide structured parsing of URLs, raw HTTP messages,
// headers, cookies, query strings, JSON, and form bodies — making it
// easier to write concise extension scripts.
func setupParseAPI(vm *sobek.Runtime) {
	parseObj := vm.NewObject()

	// parse.url(urlStr) — parse a URL into its components.
	// Returns an object even for relative paths. Returns null only on hard parse error.
	_ = parseObj.Set("url", func(call sobek.FunctionCall) sobek.Value {
		rawURL := call.Argument(0).String()
		u, err := url.Parse(rawURL)
		if err != nil {
			return sobek.Null()
		}

		// Parse query parameters
		params := vm.NewObject()
		for k, vs := range u.Query() {
			if len(vs) > 0 {
				_ = params.Set(k, vs[0])
			}
		}

		// Build path segments (drop empty parts)
		segments := make([]interface{}, 0)
		for _, seg := range strings.Split(u.Path, "/") {
			if seg != "" {
				segments = append(segments, seg)
			}
		}

		obj := vm.NewObject()
		_ = obj.Set("scheme", u.Scheme)
		_ = obj.Set("host", u.Host)
		_ = obj.Set("hostname", u.Hostname())
		_ = obj.Set("port", u.Port())
		_ = obj.Set("path", u.Path)
		_ = obj.Set("query", u.RawQuery)
		_ = obj.Set("fragment", u.Fragment)
		_ = obj.Set("params", params)
		_ = obj.Set("segments", vm.ToValue(segments))
		_ = obj.Set("template", database.PathToTemplate(u.Path))
		return obj
	})

	// parse.request(raw) — parse a raw HTTP request into its components.
	// Handles both CRLF (\r\n) and LF-only (\n) line endings.
	// Returns null on empty input.
	_ = parseObj.Set("request", func(call sobek.FunctionCall) sobek.Value {
		raw := call.Argument(0).String()
		if raw == "" {
			return sobek.Null()
		}

		headerSection, body := splitHTTPMessage(raw)
		lines := splitHeaderLines(headerSection)
		if len(lines) == 0 {
			return sobek.Null()
		}

		// Parse request line: METHOD path HTTP/version
		method, fullPath, version := "", "", ""
		parts := strings.Fields(lines[0])
		if len(parts) >= 3 {
			method = parts[0]
			fullPath = parts[1]
			version = strings.TrimPrefix(parts[2], "HTTP/")
		} else if len(parts) >= 2 {
			method = parts[0]
			fullPath = parts[1]
		}

		// Split path and query string
		pathOnly, queryStr := splitPathQuery(fullPath)

		// Parse headers into a flat map; extract Host and Cookie along the way
		headers := vm.NewObject()
		host := ""
		cookieHeader := ""
		for i := 1; i < len(lines); i++ {
			if idx := strings.Index(lines[i], ":"); idx > 0 {
				name := strings.TrimSpace(lines[i][:idx])
				value := strings.TrimSpace(lines[i][idx+1:])
				if name == "" {
					continue
				}
				_ = headers.Set(name, value)
				if strings.EqualFold(name, "host") {
					host = value
				}
				if strings.EqualFold(name, "cookie") {
					cookieHeader = value
				}
			}
		}

		// Parse query params
		params := vm.NewObject()
		if queryStr != "" {
			if vals, err := url.ParseQuery(queryStr); err == nil {
				for k, vs := range vals {
					if len(vs) > 0 {
						_ = params.Set(k, vs[0])
					}
				}
			}
		}

		// Parse cookies from the Cookie header (name=value; name2=value2)
		cookies := vm.NewObject()
		for _, part := range strings.Split(cookieHeader, ";") {
			part = strings.TrimSpace(part)
			if idx := strings.IndexByte(part, '='); idx > 0 {
				name := strings.TrimSpace(part[:idx])
				value := strings.TrimSpace(part[idx+1:])
				if name != "" {
					_ = cookies.Set(name, value)
				}
			}
		}

		obj := vm.NewObject()
		_ = obj.Set("method", method)
		_ = obj.Set("path", pathOnly)
		_ = obj.Set("query", queryStr)
		_ = obj.Set("version", version)
		_ = obj.Set("headers", headers)
		_ = obj.Set("body", body)
		_ = obj.Set("host", host)
		_ = obj.Set("params", params)
		_ = obj.Set("cookies", cookies)
		return obj
	})

	// parse.response(raw) — parse a raw HTTP response into its components.
	// Handles both CRLF (\r\n) and LF-only (\n) line endings.
	// Returns null on empty input.
	_ = parseObj.Set("response", func(call sobek.FunctionCall) sobek.Value {
		raw := call.Argument(0).String()
		if raw == "" {
			return sobek.Null()
		}

		headerSection, body := splitHTTPMessage(raw)
		lines := splitHeaderLines(headerSection)
		if len(lines) == 0 {
			return sobek.Null()
		}

		// Parse status line: HTTP/version statusCode statusText
		version, statusText := "", ""
		statusCode := 0
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			version = strings.TrimPrefix(parts[0], "HTTP/")
			statusCode, _ = strconv.Atoi(parts[1])
			if len(parts) >= 3 {
				statusText = strings.Join(parts[2:], " ")
			}
		}

		// Parse headers; extract Content-Type and Set-Cookie along the way
		headers := vm.NewObject()
		cookies := vm.NewObject()
		contentType := ""
		for i := 1; i < len(lines); i++ {
			if idx := strings.Index(lines[i], ":"); idx > 0 {
				name := strings.TrimSpace(lines[i][:idx])
				value := strings.TrimSpace(lines[i][idx+1:])
				if name == "" {
					continue
				}
				_ = headers.Set(name, value)
				if strings.EqualFold(name, "content-type") {
					contentType = value
				}
				// Parse Set-Cookie: name=value[; attributes...]
				if strings.EqualFold(name, "set-cookie") {
					if eqIdx := strings.IndexByte(value, '='); eqIdx > 0 {
						cookieName := strings.TrimSpace(value[:eqIdx])
						rest := value[eqIdx+1:]
						if semiIdx := strings.IndexByte(rest, ';'); semiIdx >= 0 {
							rest = rest[:semiIdx]
						}
						if cookieName != "" {
							_ = cookies.Set(cookieName, strings.TrimSpace(rest))
						}
					}
				}
			}
		}

		obj := vm.NewObject()
		_ = obj.Set("status", statusCode)
		_ = obj.Set("statusText", statusText)
		_ = obj.Set("version", version)
		_ = obj.Set("headers", headers)
		_ = obj.Set("body", body)
		_ = obj.Set("cookies", cookies)
		_ = obj.Set("contentType", contentType)
		return obj
	})

	// parse.headers(str) — parse a newline-separated header block into a flat map.
	// Lines without a colon (e.g., request/status line) are skipped.
	// Last value wins when the same header name appears more than once.
	_ = parseObj.Set("headers", func(call sobek.FunctionCall) sobek.Value {
		result := vm.NewObject()
		arg := call.Argument(0)
		if sobek.IsNull(arg) || sobek.IsUndefined(arg) {
			return result
		}
		for _, line := range splitHeaderLines(arg.String()) {
			if idx := strings.Index(line, ":"); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				value := strings.TrimSpace(line[idx+1:])
				if name != "" {
					_ = result.Set(name, value)
				}
			}
		}
		return result
	})

	// parse.cookies(str) — parse a Cookie header value (or any semicolon-delimited
	// name=value string) into a map. Last value wins for duplicate names.
	_ = parseObj.Set("cookies", func(call sobek.FunctionCall) sobek.Value {
		result := vm.NewObject()
		for _, part := range strings.Split(call.Argument(0).String(), ";") {
			part = strings.TrimSpace(part)
			if idx := strings.IndexByte(part, '='); idx > 0 {
				name := strings.TrimSpace(part[:idx])
				value := strings.TrimSpace(part[idx+1:])
				if name != "" {
					_ = result.Set(name, value)
				}
			}
		}
		return result
	})

	// parse.query(str) — parse a URL query string (with or without leading "?")
	// into a flat map. First value wins for repeated keys.
	_ = parseObj.Set("query", func(call sobek.FunctionCall) sobek.Value {
		result := vm.NewObject()
		str := strings.TrimPrefix(call.Argument(0).String(), "?")
		if str == "" {
			return result
		}
		if vals, err := url.ParseQuery(str); err == nil {
			for k, vs := range vals {
				if len(vs) > 0 {
					_ = result.Set(k, vs[0])
				}
			}
		}
		return result
	})

	// parse.json(str) — parse a JSON string into a native JS value.
	// Returns null on parse error.
	_ = parseObj.Set("json", func(call sobek.FunctionCall) sobek.Value {
		var v interface{}
		if err := json.Unmarshal([]byte(call.Argument(0).String()), &v); err != nil {
			return sobek.Null()
		}
		return vm.ToValue(v)
	})

	// parse.form(body) — parse a URL-encoded form body into a flat map.
	// First value wins for repeated field names.
	_ = parseObj.Set("form", func(call sobek.FunctionCall) sobek.Value {
		result := vm.NewObject()
		body := call.Argument(0).String()
		if body == "" {
			return result
		}
		if vals, err := url.ParseQuery(body); err == nil {
			for k, vs := range vals {
				if len(vs) > 0 {
					_ = result.Set(k, vs[0])
				}
			}
		}
		return result
	})

	// parse.html(htmlStr) — parse HTML and extract forms, links, scripts, and meta tags.
	// Returns {forms: [...], links: [...], scripts: [...], meta: [...]}.
	_ = parseObj.Set("html", func(call sobek.FunctionCall) sobek.Value {
		htmlStr := call.Argument(0).String()

		// Cap input at 2MB
		const maxSize = 2 << 20
		if len(htmlStr) > maxSize {
			htmlStr = htmlStr[:maxSize]
		}

		doc, err := html.Parse(strings.NewReader(htmlStr))
		if err != nil {
			return sobek.Null()
		}

		var forms, links, scripts, metas []interface{}

		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				switch n.Data {
				case "form":
					forms = append(forms, extractForm(vm, n))
				case "a":
					href := getAttr(n, "href")
					text := extractText(n)
					obj := vm.NewObject()
					_ = obj.Set("href", href)
					_ = obj.Set("text", strings.TrimSpace(text))
					links = append(links, obj)
				case "script":
					obj := vm.NewObject()
					_ = obj.Set("src", getAttr(n, "src"))
					_ = obj.Set("content", extractText(n))
					scripts = append(scripts, obj)
				case "meta":
					name := getAttr(n, "name")
					if name == "" {
						name = getAttr(n, "property")
					}
					if name == "" {
						name = getAttr(n, "http-equiv")
					}
					content := getAttr(n, "content")
					if name != "" || content != "" {
						obj := vm.NewObject()
						_ = obj.Set("name", name)
						_ = obj.Set("content", content)
						metas = append(metas, obj)
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)

		if forms == nil {
			forms = []interface{}{}
		}
		if links == nil {
			links = []interface{}{}
		}
		if scripts == nil {
			scripts = []interface{}{}
		}
		if metas == nil {
			metas = []interface{}{}
		}

		result := vm.NewObject()
		_ = result.Set("forms", vm.ToValue(forms))
		_ = result.Set("links", vm.ToValue(links))
		_ = result.Set("scripts", vm.ToValue(scripts))
		_ = result.Set("meta", vm.ToValue(metas))
		return result
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("parse", parseObj)
}

// extractForm extracts form attributes and input fields from a <form> node.
func extractForm(vm *sobek.Runtime, n *html.Node) interface{} {
	obj := vm.NewObject()
	_ = obj.Set("action", getAttr(n, "action"))
	_ = obj.Set("method", strings.ToUpper(getAttr(n, "method")))

	var inputs []interface{}
	var walkInputs func(*html.Node)
	walkInputs = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "input", "textarea", "select":
				inp := vm.NewObject()
				_ = inp.Set("name", getAttr(node, "name"))
				_ = inp.Set("type", getAttr(node, "type"))
				_ = inp.Set("value", getAttr(node, "value"))
				inputs = append(inputs, inp)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(n)

	if inputs == nil {
		inputs = []interface{}{}
	}
	_ = obj.Set("inputs", vm.ToValue(inputs))
	return obj
}

// getAttr returns the value of an attribute on an HTML node, or empty string.
func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// extractText returns the concatenated text content of all descendant text nodes.
func extractText(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// splitHTTPMessage splits a raw HTTP message into its header section and body.
// Recognizes both CRLF (\r\n\r\n) and LF-only (\n\n) blank-line separators.
func splitHTTPMessage(raw string) (headerSection, body string) {
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, ""
}

// splitHeaderLines splits a header section into individual lines.
// Handles both CRLF (\r\n) and LF-only (\n) line endings; strips trailing CR.
// Empty lines are dropped.
func splitHeaderLines(headerSection string) []string {
	var lines []string
	for _, line := range strings.Split(headerSection, "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// splitPathQuery splits a full request path into the path and query string parts.
// The returned query string does NOT include the leading "?".
func splitPathQuery(fullPath string) (path, query string) {
	if idx := strings.IndexByte(fullPath, '?'); idx >= 0 {
		return fullPath[:idx], fullPath[idx+1:]
	}
	return fullPath, ""
}
