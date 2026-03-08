// Package diffscan provides differential analysis tools for detecting
// injection vulnerabilities through response comparison.
package diffscan

import "github.com/vigolium/vigolium/pkg/anomaly"

// diffScanFingerprintTypes defines the full attribute set used for response comparison.
var diffScanFingerprintTypes = anomaly.AllFingerprintAttributes

// canaryKeys contains keywords used for response fingerprinting.
// Matches Java's Attack.java keys array (minus the dynamic canary).
var canaryKeys = []string{"\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div", "illegal", "fail", "access", "directory", "file", "not found", "unknown", "uid=", "c:\\", "varchar", "ODBC", "SQL", "quotation mark", "syntax"}

// GetCanaryKeys returns canary keys with optional custom canary prepended.
// Matches Java's behavior where globalSettings.getString("canary") is first.
func GetCanaryKeys(customCanary string) []string {
	if customCanary == "" {
		return canaryKeys
	}
	keys := make([]string, 0, len(canaryKeys)+1)
	keys = append(keys, customCanary)
	keys = append(keys, canaryKeys...)
	return keys
}
