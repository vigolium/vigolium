// Package catalog defines the on-disk schema for the native secret-detection
// rule catalog. It is a dependency-free leaf package shared by the code
// generator (pkg/secretscan/secretgen) and the runtime detector (pkg/secretscan)
// so that neither pulls the regex engine or the embedded data through the other.
//
// The catalog is generated from one upstream rule set:
//   - kingfisher (Apache-2.0, MongoDB) — Rust-regex rules normalized to RE2
//
// (The gitleaks/betterleaks family was removed as a noisy, redundant duplicate
// of kingfisher's better-anchored provider rules.)
//
// Secret VERIFICATION is intentionally out of scope: kingfisher `validation:`
// blocks are dropped at generation time and no live credential checks are made.
package catalog

// Rule is a single normalized secret-detection rule.
//
// The Regex is RE2-compatible (verbose mode stripped, PCRE inline
// comments removed, named groups rewritten to (?P<...>), repeat counts clamped
// to RE2's 1000 ceiling). Entropy and the Min* character requirements mirror
// kingfisher semantics and are applied to the selected secret capture
// (see SecretGroup) or, for multi-group/named-group rules, the full match —
// matching kingfisher's check_pattern_requirements behavior.
type Rule struct {
	ID   string   `json:"id"`           // stable, source-namespaced (kingfisher.*)
	Name string   `json:"name"`         // human-readable rule name / description
	Src  string   `json:"src"`          // rule source; always "kingfisher"
	Re   string   `json:"re"`           // normalized RE2 pattern
	Kw   []string `json:"kw,omitempty"` // lowercased literal keywords for the prefilter; empty = always-run

	Entropy    float64 `json:"entropy,omitempty"`     // min Shannon entropy (bits/byte); match requires strictly greater
	MinDigits  int     `json:"min_digits,omitempty"`  // required digit count in the validated span
	MinLower   int     `json:"min_lower,omitempty"`   // required lowercase count
	MinUpper   int     `json:"min_upper,omitempty"`   // required uppercase count
	MinSpecial int     `json:"min_special,omitempty"` // required special-char count

	Confidence  string `json:"confidence,omitempty"`   // "high" | "medium" | "low"
	SecretGroup int    `json:"secret_group,omitempty"` // explicit positional capture override; 0 = auto-select
	Visible     bool   `json:"visible"`                // false = noisy/experimental, excluded from the default set
}

// Catalog is the full generated rule set plus provenance.
type Catalog struct {
	KingfisherVersion string `json:"kingfisher_version"`
	Generated         string `json:"generated"` // human note; not a timestamp (kept deterministic)
	Rules             []Rule `json:"rules"`
}
