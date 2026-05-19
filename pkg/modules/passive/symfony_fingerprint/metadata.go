package symfony_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-fingerprint"
	ModuleName  = "Symfony Fingerprint"
	ModuleShort = "Identifies Symfony PHP framework installations from headers, cookies, and debug profiler markers"
)

var (
	ModuleDesc = `## Description
Passively identifies Symfony installations by inspecting the X-Powered-By
header, the sf_redirect / MOCKSESSID session cookies, and Symfony Web Debug
Toolbar / Profiler markers in HTML responses.

## Signals
- X-Powered-By contains "Symfony"
- X-Debug-Token header (Symfony Profiler)
- Set-Cookie: sf_redirect= or MOCKSESSID=
- Body contains "/_wdt/" (Web Debug Toolbar) or "/_profiler/" markers

## Notes
- Passive only: does not send any HTTP requests
- Publishes "symfony" and "php" to the tech registry`

	ModuleConfirmation = "Confirmed when a Symfony header, cookie, or profiler marker is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"symfony", "php", "fingerprint", "light"}
)
