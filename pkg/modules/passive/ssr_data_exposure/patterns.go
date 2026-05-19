package ssr_data_exposure

import "regexp"

// ssrStateBlob defines where to find SSR state data in the HTML.
type ssrStateBlob struct {
	name    string
	start   string // start delimiter in HTML
	end     string // end delimiter
	jsonKey bool   // if true, extract JSON between { and }
}

// stateBlobs defines the SSR state injection points to scan.
var stateBlobs = []ssrStateBlob{
	{
		name:  "__NEXT_DATA__",
		start: `<script id="__NEXT_DATA__" type="application/json">`,
		end:   `</script>`,
	},
	{
		name:    "__NUXT__",
		start:   `window.__NUXT__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
	{
		name:    "__INITIAL_STATE__",
		start:   `window.__INITIAL_STATE__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
	{
		name:    "__APOLLO_STATE__",
		start:   `window.__APOLLO_STATE__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
}

// sensitivePattern defines a pattern to detect in SSR state data.
type sensitivePattern struct {
	name    string
	pattern *regexp.Regexp
	desc    string
}

// sensitivePatterns are the patterns to scan for in extracted SSR state.
var sensitivePatterns = []sensitivePattern{
	{
		name:    "API Key/Token",
		pattern: regexp.MustCompile(`"(?:api_?key|api_?token|access_?token|secret_?key|auth_?token)"\s*:\s*"([^"]{16,})"`),
		desc:    "API key or token found in SSR state",
	},
	{
		name:    "Admin Flag",
		pattern: regexp.MustCompile(`"(?:is_?[Aa]dmin|is_?[Ss]uperuser|is_?[Ss]taff|admin|role)"\s*:\s*(?:true|"admin"|"superuser")`),
		desc:    "Admin/privilege flag found in SSR state",
	},
	{
		name:    "Email Address",
		pattern: regexp.MustCompile(`"(?:email|mail|user_?email)"\s*:\s*"([^"]+@[^"]+\.[^"]+)"`),
		desc:    "Email address found in SSR state",
	},
	{
		name:    "Password Hash",
		pattern: regexp.MustCompile(`"(?:password|passwd|password_?hash|hashed_?password)"\s*:\s*"(\$2[aby]\$|pbkdf2|scrypt|argon2|sha256|sha512)[^"]*"`),
		desc:    "Password hash found in SSR state",
	},
	{
		name:    "Private IP",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^"]*)?"`),
		desc:    "Private/internal IP address found in SSR state",
	},
	{
		name:    "Database URL",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^"]+"`),
		desc:    "Database connection string found in SSR state",
	},
	{
		name:    "AWS Key",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"AKIA[0-9A-Z]{16}"`),
		desc:    "AWS access key found in SSR state",
	},
}

// knownPlaceholders are values to skip as likely non-sensitive (pre-lowercased).
var knownPlaceholders = []string{
	"undefined", "null", "true", "false",
	"change_me", "your_api_key", "xxx",
	"placeholder", "example",
}
