// Package diffscan provides differential analysis tools for detecting
// injection vulnerabilities through response comparison.
package diffscan

import (
	"slices"

	"github.com/vigolium/vigolium/pkg/anomaly"
)

// reflectionProneAttributes are response-fingerprint attributes that primarily
// echo the request URL back to the client. On redirecting or URL-normalizing
// endpoints they reproduce the injected payload verbatim, so a payload that is
// merely *reflected* (not *evaluated*) makes break and escape responses differ
// purely because the literal payload bytes differ. That is a reflection
// artifact, not an evaluation signal, and counting it produced diff-based false
// positives (e.g. SSTI flagged on a 301 whose only difference was the echoed
// Location header). They are excluded from the comparison set for every
// diffscan-based module (ssti_detection, smart_behavior_detection,
// nginx_path_escape). A genuine routing change still surfaces via STATUS_CODE
// and the body-content attributes.
var reflectionProneAttributes = []anomaly.Type{
	anomaly.LOCATION,
	anomaly.CONTENT_LOCATION,
	anomaly.CANONICAL_LINK,
}

// volatileAttributes are response-fingerprint attributes that change from one
// request to the next independently of the injected payload — session/CSRF
// cookies, load-balancer affinity tokens, A/B-test buckets, anti-CSRF rotation.
// A break-vs-escape difference in these is per-request jitter, never evidence
// that the payload was evaluated, so they are excluded from the comparison set
// for every diffscan-based module.
//
// SET_COOKIE_NAMES was the source of a reported diff-based SSTI false positive:
// a 404 with a 0-length body that issued a freshly-named Set-Cookie on every
// request, so break and escape "differed" only in the cookie name set even
// though nothing was rendered. Cookie names are never a template-evaluation
// signal, so dropping them removes that whole class of noise.
var volatileAttributes = []anomaly.Type{
	anomaly.SET_COOKIE_NAMES,
}

// diffScanFingerprintTypes defines the attribute set used for response
// comparison: the full attribute set minus the reflection-prone header
// attributes (see reflectionProneAttributes) and the per-request volatile
// attributes (see volatileAttributes).
var diffScanFingerprintTypes = excludeAttributes(
	anomaly.AllFingerprintAttributes,
	slices.Concat(reflectionProneAttributes, volatileAttributes)...,
)

// excludeAttributes returns all attributes in order with the excluded ones
// removed.
func excludeAttributes(all []anomaly.Type, exclude ...anomaly.Type) []anomaly.Type {
	skip := make(map[anomaly.Type]struct{}, len(exclude))
	for _, t := range exclude {
		skip[t] = struct{}{}
	}
	out := make([]anomaly.Type, 0, len(all))
	for _, t := range all {
		if _, drop := skip[t]; drop {
			continue
		}
		out = append(out, t)
	}
	return out
}

// canaryKeys contains keywords used for response fingerprinting.
var canaryKeys = []string{"\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div", "illegal", "fail", "access", "directory", "file", "not found", "unknown", "uid=", "c:\\", "varchar", "ODBC", "SQL", "quotation mark", "syntax"}

// GetCanaryKeys returns canary keys with optional custom canary prepended.
func GetCanaryKeys(customCanary string) []string {
	if customCanary == "" {
		return canaryKeys
	}
	keys := make([]string, 0, len(canaryKeys)+1)
	keys = append(keys, customCanary)
	keys = append(keys, canaryKeys...)
	return keys
}
