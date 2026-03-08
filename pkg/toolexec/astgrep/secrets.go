package astgrep

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
)

// SecretFinding represents a hardcoded secret extracted from an ast-grep match,
// optionally confirmed against the known-secrets wordlist.
type SecretFinding struct {
	Match       Match  `json:"match"`
	SecretValue string `json:"secret_value"`
	RuleID      string `json:"rule_id"`
	Framework   string `json:"framework"`
	KnownWeak   bool   `json:"known_weak"`
}

// SecretScanResult contains the output of a secret-focused scan.
type SecretScanResult struct {
	// KnownDefaults are secrets found in the wordlist — actively exploitable.
	KnownDefaults []SecretFinding `json:"known_defaults,omitempty"`
	// HardcodedValues are hardcoded secrets NOT in the wordlist.
	HardcodedValues []SecretFinding `json:"hardcoded_values,omitempty"`
	// ScanDuration is how long the scan took.
	ScanDuration time.Duration `json:"scan_duration"`
}

// knownSecrets holds the lazily-loaded wordlist set.
var (
	knownSecretsOnce sync.Once
	knownSecrets     map[string]struct{}
	knownSecretsErr  error
)

// loadKnownSecrets loads the JWT secrets wordlist into a set for O(1) lookup.
func loadKnownSecrets() (map[string]struct{}, error) {
	knownSecretsOnce.Do(func() {
		data, err := wordlists.WordlistsFS.ReadFile("jwt.secrets.list")
		if err != nil {
			knownSecretsErr = err
			return
		}
		knownSecrets = make(map[string]struct{}, 110_000)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				knownSecrets[line] = struct{}{}
			}
		}
		knownSecretsErr = scanner.Err()
	})
	return knownSecrets, knownSecretsErr
}

// isKnownSecret returns true if the value appears in the wordlist.
func isKnownSecret(value string) bool {
	secrets, err := loadKnownSecrets()
	if err != nil || secrets == nil {
		return false
	}
	_, ok := secrets[value]
	return ok
}

// CheckSecrets processes ast-grep matches from security-secrets rules,
// extracts the $SECRET metavariable, and checks against the known-secrets wordlist.
// Matches are split into two buckets: known defaults (in wordlist) and hardcoded (not in wordlist).
func CheckSecrets(matches []Match) (known, hardcoded []SecretFinding) {
	for _, m := range matches {
		if !strings.HasPrefix(m.ID, "security-secrets-") {
			continue
		}

		secretMV, ok := m.MetaVariables["SECRET"]
		if !ok {
			continue
		}

		value := stripQuotes(secretMV.Text)
		if value == "" {
			continue
		}

		// Skip template interpolation — not a pure literal
		if strings.Contains(value, "${") || strings.Contains(value, "#{") {
			continue
		}

		finding := SecretFinding{
			Match:       m,
			SecretValue: value,
			RuleID:      m.ID,
			Framework:   extractFramework(m.ID),
		}

		if isKnownSecret(value) {
			finding.KnownWeak = true
			known = append(known, finding)
		} else {
			hardcoded = append(hardcoded, finding)
		}
	}
	return
}

// ScanDirForSecrets runs all security-secrets ast-grep rules against targetDir,
// then cross-references extracted secret values against the known-secrets wordlist.
func (s *Scanner) ScanDirForSecrets(ctx context.Context, targetDir string) (*SecretScanResult, error) {
	startTime := time.Now()

	result, err := s.ScanDirWithRules(ctx, targetDir, "security-secrets")
	if err != nil {
		return nil, err
	}

	known, hardcoded := CheckSecrets(result.Matches)
	return &SecretScanResult{
		KnownDefaults:   known,
		HardcodedValues: hardcoded,
		ScanDuration:    time.Since(startTime),
	}, nil
}

// stripQuotes removes surrounding single, double, or backtick quotes.
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' || first == '\'' || first == '`') && first == last {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// extractFramework pulls the framework name from a rule ID.
// e.g. "security-secrets-express-jwt-js" → "express"
func extractFramework(ruleID string) string {
	rest := strings.TrimPrefix(ruleID, "security-secrets-")
	if idx := strings.Index(rest, "-"); idx > 0 {
		return rest[:idx]
	}
	return rest
}
