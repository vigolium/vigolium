package crypto_weakness_detect

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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

	// Check response body for magic hashes
	body := ctx.Response().BodyToString()
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if body != "" && !isBinaryContentType(ct) {
		findings = append(findings, checkMagicHash(body)...)
		findings = append(findings, checkWeakHashes(body)...)
		findings = append(findings, checkPaddingOracle(body)...)
	}

	// Check cookies for encrypted values without MAC
	findings = append(findings, checkEncryptedCookies(ctx)...)

	if len(findings) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, f := range findings {
		results = append(results, &output.ResultEvent{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: []string{f.detail},
			Info: output.Info{
				Name:        f.name,
				Description: f.description,
				Severity:    f.severity,
				Confidence:  severity.Tentative,
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
}

// checkMagicHash detects PHP magic hash values (0eXXXXX...) in response body.
func checkMagicHash(body string) []finding {
	matches := magicHashPattern.FindAllString(body, 5)
	if len(matches) == 0 {
		return nil
	}

	var findings []finding
	seen := make(map[string]bool)
	for _, match := range matches {
		if seen[match] {
			continue
		}
		seen[match] = true
		findings = append(findings, finding{
			name:        "PHP Magic Hash",
			detail:      fmt.Sprintf("Magic hash value: %s", match),
			description: "Response contains a PHP magic hash (0eXXX...) that evaluates to 0 in loose comparison, enabling type juggling attacks",
			severity:    severity.Medium,
		})
	}
	return findings
}

// checkWeakHashes detects MD5/SHA1 hashes near sensitive keywords.
func checkWeakHashes(body string) []finding {
	bodyLower := strings.ToLower(body)
	var findings []finding

	// Check for MD5 hashes near sensitive keywords
	md5Matches := weakHashPatterns.md5.FindAllStringIndex(body, 20)
	for _, loc := range md5Matches {
		hashValue := body[loc[0]:loc[1]]
		if isLikelyFalsePositiveHash(hashValue) {
			continue
		}
		// Check if any sensitive keyword is within 100 chars
		start := loc[0] - 100
		if start < 0 {
			start = 0
		}
		end := loc[1] + 100
		if end > len(bodyLower) {
			end = len(bodyLower)
		}
		context := bodyLower[start:end]
		for _, keyword := range sensitiveHashKeywords {
			if strings.Contains(context, keyword) {
				findings = append(findings, finding{
					name:        "Weak Hash Algorithm (MD5)",
					detail:      fmt.Sprintf("MD5 hash near '%s': %s", keyword, truncate(hashValue, 40)),
					description: "MD5 hash detected near security-sensitive context. MD5 is cryptographically broken and should not be used for password hashing or integrity checks",
					severity:    severity.Low,
				})
				break
			}
		}
	}

	// Check for SHA1 hashes near sensitive keywords
	sha1Matches := weakHashPatterns.sha1.FindAllStringIndex(body, 20)
	for _, loc := range sha1Matches {
		hashValue := body[loc[0]:loc[1]]
		if isLikelyFalsePositiveHash(hashValue) {
			continue
		}
		start := loc[0] - 100
		if start < 0 {
			start = 0
		}
		end := loc[1] + 100
		if end > len(bodyLower) {
			end = len(bodyLower)
		}
		context := bodyLower[start:end]
		for _, keyword := range sensitiveHashKeywords {
			if strings.Contains(context, keyword) {
				findings = append(findings, finding{
					name:        "Weak Hash Algorithm (SHA1)",
					detail:      fmt.Sprintf("SHA1 hash near '%s': %s", keyword, truncate(hashValue, 48)),
					description: "SHA1 hash detected near security-sensitive context. SHA1 is considered weak and should be replaced with SHA-256 or better",
					severity:    severity.Low,
				})
				break
			}
		}
	}

	return findings
}

// checkPaddingOracle detects padding oracle error messages.
func checkPaddingOracle(body string) []finding {
	var findings []finding

	for _, pattern := range paddingOraclePatterns {
		if match := pattern.FindString(body); match != "" {
			findings = append(findings, finding{
				name:        "Padding Oracle Indicator",
				detail:      fmt.Sprintf("Padding error message: %s", truncate(match, 80)),
				description: "Response contains a padding-related error message that may indicate a padding oracle vulnerability, allowing decryption of encrypted data",
				severity:    severity.Medium,
			})
			return findings // One finding is enough
		}
	}

	return findings
}

// checkEncryptedCookies detects encrypted cookie values that lack MAC protection.
func checkEncryptedCookies(ctx *httpmsg.HttpRequestResponse) []finding {
	if ctx.Response() == nil {
		return nil
	}

	var findings []finding
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
		cookieNames[strings.ToLower(name)] = true

		// Skip JWTs (contain dots)
		if strings.Count(value, ".") >= 2 {
			continue
		}

		// Try base64 decode
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(value)
			if err != nil {
				continue
			}
		}

		// Check if it looks like a block cipher output:
		// length is multiple of 16 (AES block size) and >= 32 bytes
		if len(decoded) < 32 || len(decoded)%16 != 0 {
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
			findings = append(findings, finding{
				name:        "Encrypted Cookie Without MAC",
				detail:      fmt.Sprintf("Cookie '%s' appears encrypted (base64, %d bytes, block-aligned) without MAC", name, len(decoded)),
				description: "Cookie value appears to be encrypted without integrity protection (HMAC). This may allow bit-flipping attacks to manipulate encrypted cookie data",
				severity:    severity.Low,
			})
		}
	}

	return findings
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

func isBinaryContentType(ct string) bool {
	return strings.Contains(ct, "image/") ||
		strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") ||
		strings.Contains(ct, "octet-stream")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
