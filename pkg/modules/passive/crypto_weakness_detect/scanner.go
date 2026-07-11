package crypto_weakness_detect

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the Cryptographic Weakness Detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Cryptographic Weakness Detection module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeBoth,
		),
		rhm: dedup.LazyDefaultRHM("passive_crypto_weakness_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request/response for cryptographic weaknesses.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	var findings []finding

	// Check response body for magic hashes. Skip static assets / binary payloads:
	// minified JS bundles, sourcemaps and asset manifests are full of MD5/SHA1
	// fingerprints and "0e..."-shaped strings that are not live crypto weaknesses.
	// URL-extension gating misses extensionless JS, so gate on Content-Type too.
	body := ctx.Response().BodyToString()
	if body != "" && !modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
		findings = append(findings, checkMagicHash(body)...)
		findings = append(findings, checkWeakHashes(body)...)
		findings = append(findings, checkPaddingOracle(body, scanCtx, urlx.Host)...)
	}

	// Check cookies for encrypted values without MAC
	findings = append(findings, checkEncryptedCookies(ctx, scanCtx, urlx.Host)...)

	if len(findings) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, f := range findings {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: []string{f.detail},
			RecordKind:       f.kind,
			EvidenceGrade:    f.grade,
			Info: output.Info{
				Name:        f.name,
				Description: f.description,
				Severity:    f.severity,
				Confidence:  f.confidence,
			},
		})
	}

	return results, nil
}

type finding struct {
	name        string
	detail      string
	description string
	severity    severity.Severity
	confidence  severity.Confidence
	kind        output.RecordKind
	grade       output.EvidenceGrade
}

// checkMagicHash retains only structured key/value occurrences. A random 0e...
// token in prose, telemetry, or a build artifact says nothing about PHP loose
// comparison. Even a named value is an observation until server comparison
// behavior is tested actively.
func checkMagicHash(body string) []finding {
	matches := magicHashFieldPattern.FindAllStringSubmatch(body, 5)
	if len(matches) == 0 {
		return nil
	}

	var findings []finding
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 3 || seen[match[2]] {
			continue
		}
		seen[match[2]] = true
		findings = append(findings, finding{
			name:        "PHP Magic-Hash Value Observation",
			detail:      fmt.Sprintf("Structured field %q contains magic-hash-shaped value %s", match[1], match[2]),
			description: "A named response field contains a 0e-prefixed numeric hash value. This is not a type-juggling vulnerability by itself; confirmation requires proving that the server compares attacker-controlled values with PHP loose equality.",
			severity:    severity.Info,
			confidence:  severity.Tentative,
			kind:        output.RecordKindObservation,
			grade:       output.EvidenceGradeObservation,
		})
	}
	return findings
}

// checkWeakHashes requires a structured password/credential digest field. Mere
// proximity to words such as token, checksum, auth, or hash is too generic and
// routinely matches content hashes and identifiers.
func checkWeakHashes(body string) []finding {
	var findings []finding
	for _, match := range weakHashFieldPattern.FindAllStringSubmatch(body, 20) {
		if len(match) < 3 || isLikelyFalsePositiveHash(match[2]) {
			continue
		}
		algorithm := "MD5"
		if len(match[2]) == 40 {
			algorithm = "SHA-1"
		}
		findings = append(findings, finding{
			name:        "Weak Credential Digest Observation (" + algorithm + ")",
			detail:      fmt.Sprintf("Field %q contains a %s-shaped digest: %s", match[1], algorithm, truncate(match[2], 48)),
			description: "A structured credential/password digest field exposes a legacy hash-shaped value. Passive output cannot prove how it is generated or used; verify the storage/verification algorithm before treating this as a cryptographic vulnerability.",
			severity:    severity.Info,
			confidence:  severity.Tentative,
			kind:        output.RecordKindObservation,
			grade:       output.EvidenceGradeObservation,
		})
	}

	return findings
}

// checkPaddingOracle detects padding oracle error messages. A match publishes the
// "crypto-cbc" tech tag for host so the active padding-oracle confirmer (which is
// hard-gated on it) is unlocked for this host.
func checkPaddingOracle(body string, scanCtx *modkit.ScanContext, host string) []finding {
	var findings []finding

	for _, pattern := range paddingOraclePatterns {
		if match := pattern.FindString(body); match != "" {
			// Publish the CBC/crypto tech tag: a disclosed padding/decryption error
			// is exactly the surface the active padding-oracle module needs.
			if scanCtx != nil {
				scanCtx.MarkTech(host, cbcTechTag)
			}
			findings = append(findings, finding{
				name:        "Padding Error Disclosure Candidate",
				detail:      fmt.Sprintf("Padding error message: %s", truncate(match, 80)),
				description: "The response discloses a padding/decryption error. A padding oracle requires a repeatable ciphertext mutation differential; this single passive response is only a candidate.",
				severity:    severity.Low,
				confidence:  severity.Tentative,
				kind:        output.RecordKindCandidate,
				grade:       output.EvidenceGradeCandidate,
			})
			return findings // One finding is enough
		}
	}

	return findings
}

// checkEncryptedCookies identifies opaque, block-aligned session cookies as an
// observation only. Ciphertext length and a missing companion cookie cannot
// reveal whether integrity is embedded via AEAD or an appended tag.
func checkEncryptedCookies(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext, host string) []finding {
	if ctx.Response() == nil {
		return nil
	}

	type cookieEntry struct{ name, value string }
	var entries []cookieEntry
	cookieNames := make(map[string]bool)

	// Iterate all headers to find Set-Cookie entries
	for _, hdr := range ctx.Response().Headers() {
		if !strings.EqualFold(hdr.Name, "Set-Cookie") {
			continue
		}
		name, value := parseCookieNameValue(hdr.Value)
		if name == "" || value == "" {
			continue
		}
		entries = append(entries, cookieEntry{name: name, value: value})
		cookieNames[strings.ToLower(name)] = true
	}

	var findings []finding
	for _, entry := range entries {
		name, value := entry.name, entry.value
		if !infra.IsSessionCookieName(name) {
			continue
		}

		// Skip JWTs (contain dots)
		if strings.Count(value, ".") >= 2 {
			continue
		}

		// Try base64 decode
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(value)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(value)
				if err != nil {
					continue
				}
			}
		}

		// Check if it looks like a block cipher output:
		// length is multiple of 16 (AES block size) and >= 32 bytes
		if len(decoded) < 32 || len(decoded)%16 != 0 || byteEntropy(decoded) < 4.0 {
			continue
		}

		// Check if there's a companion MAC/signature cookie
		nameLower := strings.ToLower(name)
		hasMac := cookieNames[nameLower+"_mac"] ||
			cookieNames[nameLower+"_sig"] ||
			cookieNames[nameLower+"_hmac"] ||
			cookieNames[nameLower+"-mac"] ||
			cookieNames[nameLower+"-sig"]

		if !hasMac {
			// A block-aligned, high-entropy, opaque session cookie with no companion
			// MAC is a CBC-shaped ciphertext. Publish the tech tag so the active
			// padding-oracle confirmer (hard-gated on it) is unlocked for this host.
			if scanCtx != nil {
				scanCtx.MarkTech(host, cbcTechTag)
			}
			findings = append(findings, finding{
				name:        "Opaque Block-Aligned Session Cookie Observation",
				detail:      fmt.Sprintf("Cookie %q decodes to %d high-entropy, block-aligned bytes", name, len(decoded)),
				description: "The session cookie looks like opaque ciphertext, but its wire shape cannot distinguish unauthenticated CBC from AEAD or an embedded authentication tag. Active mutation or implementation evidence is required.",
				severity:    severity.Info,
				confidence:  severity.Tentative,
				kind:        output.RecordKindObservation,
				grade:       output.EvidenceGradeObservation,
			})
		}
	}

	return findings
}

func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// parseCookieNameValue extracts the name and value from a Set-Cookie header.
func parseCookieNameValue(header string) (string, string) {
	// Set-Cookie: name=value; path=/; ...
	parts := strings.SplitN(header, ";", 2)
	if len(parts) == 0 {
		return "", ""
	}
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameValue) != 2 {
		return "", ""
	}
	return strings.TrimSpace(nameValue[0]), strings.TrimSpace(nameValue[1])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
