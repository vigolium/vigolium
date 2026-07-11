package env_secret_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "env-secret-exposure"
	ModuleName  = "Environment Secret Exposure"
	ModuleShort = "Detects credential-shaped values in public environment variables and served dotenv files"
)

var (
	ModuleDesc = `**What it means:** A successful response contains a credential-shaped value in a browser-visible framework variable or directly served dotenv file. Publishable identifiers, placeholders, weak examples, and documentation are filtered; the remainder is still a candidate until validated.

**How it's exploited:** An attacker extracts an exposed live credential and uses its provider permissions. Public framework variables are not secret merely because their names look sensitive.

**Fix:** Validate and rotate live credentials, keep secrets server-side, and block dotenv files.`

	ModuleConfirmation = "Candidate when a successful response exposes a non-placeholder, credential-shaped value in a public framework variable or directly served dotenv file; live-secret validation is required"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
