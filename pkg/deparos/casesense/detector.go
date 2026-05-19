package casesense

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"go.uber.org/zap"
)

var logger = zap.L().Named("casesense")

// DetectionType distinguishes file vs directory detection.
type DetectionType int

const (
	DetectionFile DetectionType = iota
	DetectionDir
)

// String returns string representation.
func (t DetectionType) String() string {
	switch t {
	case DetectionFile:
		return "file"
	case DetectionDir:
		return "directory"
	default:
		return "unknown"
	}
}

// Detector performs lazy case sensitivity detection.
// Called when first valid FILE/DIR is discovered.
type Detector struct {
	learner *fingerprint.Learner
}

// NewDetector creates a new case sensitivity detector.
func NewDetector(learner *fingerprint.Learner) *Detector {
	return &Detector{
		learner: learner,
	}
}

// DetectFromValid checks case sensitivity using a known-valid resource.
// discoveredURL: URL that returned valid response (e.g., /Admin/ → 200)
// originalSample: fingerprint sample from original response
// resourceType: DetectionFile or DetectionDir
//
// Algorithm:
// 1. Flip case of path (/Admin/ → /ADMIN/)
// 2. Learn fingerprint for variant (3 requests same path)
// 3. Compare with original sample
// 4. Match → case-insensitive, Different → case-sensitive
func (d *Detector) DetectFromValid(
	ctx context.Context,
	discoveredURL *url.URL,
	originalSample *fingerprint.Sample,
	resourceType DetectionType,
) (config.CaseSensitivityMode, error) {
	if discoveredURL == nil {
		return config.CaseInsensitive, fmt.Errorf("discovered URL is nil")
	}
	if originalSample == nil {
		return config.CaseInsensitive, fmt.Errorf("original sample is nil")
	}

	// 1. Flip case of path
	variantPath := flipCase(discoveredURL.Path)
	if variantPath == discoveredURL.Path {
		// Path has no alpha chars or couldn't flip
		logger.Debug("Cannot flip case for path, defaulting to insensitive",
			zap.String("path", discoveredURL.Path),
			zap.String("type", resourceType.String()))
		return config.CaseInsensitive, nil
	}

	logger.Debug("Detecting case sensitivity",
		zap.String("original", discoveredURL.Path),
		zap.String("variant", variantPath),
		zap.String("type", resourceType.String()))

	// 2. Learn fingerprint for variant (3 requests same path)
	variantSig, err := d.learnVariantFingerprint(ctx, discoveredURL, variantPath)
	if err != nil {
		logger.Debug("Failed to learn variant fingerprint, defaulting to insensitive",
			zap.Error(err),
			zap.String("type", resourceType.String()))
		return config.CaseInsensitive, err
	}

	// 3. Compare with original sample
	// If variant matches original → server treats them the same → case-insensitive
	if variantSig.Matches(originalSample) {
		logger.Info("Case sensitivity detected",
			zap.String("type", resourceType.String()),
			zap.String("mode", "insensitive"),
			zap.String("reason", "variant matches original"))
		return config.CaseInsensitive, nil
	}

	// Different response → case-sensitive
	logger.Info("Case sensitivity detected",
		zap.String("type", resourceType.String()),
		zap.String("mode", "sensitive"),
		zap.String("reason", "variant differs from original"))
	return config.CaseSensitive, nil
}

// learnVariantFingerprint learns fingerprint by requesting the variant path 3 times.
func (d *Detector) learnVariantFingerprint(ctx context.Context, baseURL *url.URL, variantPath string) (*fingerprint.Signature, error) {
	// Build variant URL
	variantURL := *baseURL
	variantURL.Path = variantPath

	// Request same path 3 times to extract stable attributes
	// (no query string needed - server response stability is what matters)
	paths := []string{variantPath, variantPath, variantPath}

	return d.learner.LearnFromPaths(ctx, &variantURL, paths)
}

// flipCase flips the case of all alphabetic characters in the path.
// Example: /Admin/Config/ → /aDMIN/cONFIG/
// Returns original path if no alpha chars found.
func flipCase(path string) string {
	hasAlpha := false
	result := make([]rune, 0, len(path))

	for _, r := range path {
		if unicode.IsLetter(r) {
			hasAlpha = true
			if unicode.IsUpper(r) {
				result = append(result, unicode.ToLower(r))
			} else {
				result = append(result, unicode.ToUpper(r))
			}
		} else {
			result = append(result, r)
		}
	}

	if !hasAlpha {
		return path
	}

	return string(result)
}

// HasAlphaChars checks if path contains any alphabetic characters.
func HasAlphaChars(path string) bool {
	for _, r := range path {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// ExtractTestableSegment extracts the last path segment that has alpha chars.
// Example: /api/v1/Users/ → "Users"
// Returns empty string if no suitable segment found.
func ExtractTestableSegment(path string) string {
	// Remove trailing slash for processing
	path = strings.TrimSuffix(path, "/")

	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if seg != "" && HasAlphaChars(seg) {
			return seg
		}
	}
	return ""
}
