package subresource_integrity_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subresource-integrity-detect"
	ModuleName  = "Subresource Integrity Detect"
	ModuleShort = "Observes truly cross-origin scripts and stylesheets without valid SRI"
)

var (
	ModuleDesc = `**What it means:** A truly cross-origin script or stylesheet lacks a valid Subresource Integrity digest. This is a supply-chain hardening observation, not evidence that the provider is compromised; mutable resources may intentionally omit SRI.

**How it's exploited:** If the third-party asset or delivery path is compromised, malicious code can execute in the page's origin without an integrity check.

**Fix:** Pin immutable external assets with SHA-256/384/512 integrity and crossorigin attributes, or self-host them.`

	ModuleConfirmation = "Observed when a truly cross-origin executable script or stylesheet lacks a valid sha256/sha384/sha512 integrity digest"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "javascript", "light"}
)
