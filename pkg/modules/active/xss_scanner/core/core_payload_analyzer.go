package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type PayloadReflectionLocator struct {
	scanTargetBytes []byte
	sourceBodyOffset int
	payloadPatternMatcher ByteSequenceMatcher
	scanRangeStartIndex int
	scanRangeEndIndex int
	reflectionLocation ReflectionLocation
	randomProvider *utils.RandomGenerator
}

// NewPayloadReflectionLocator creates a new PayloadReflectionLocator.
func NewPayloadReflectionLocator(
	scanTargetBytes []byte,
	sourceBodyOffset int,
	originalPayloadBytes []byte, // This is the key addition
	scanRangeStartIndex int,
	scanRangeEndIndex int,
	reflectionLocation ReflectionLocation,
	randomProvider *utils.RandomGenerator,
) *PayloadReflectionLocator {
	zap.L().Debug("[DEBUG NewPayloadReflectionLocator] Called",
		zap.Int("sourceBodyOffset", sourceBodyOffset),
		zap.String("originalPayload", string(originalPayloadBytes)),
		zap.Int("scanRangeStartIndex", scanRangeStartIndex),
		zap.Int("scanRangeEndIndex", scanRangeEndIndex),
		zap.Int("reflectionLocation", int(reflectionLocation)))
	payloadMatcher := NewSimpleBytePatternMatcher(
		originalPayloadBytes,
	)
	return NewPayloadReflectionLocatorWithMatcher(
		scanTargetBytes,
		sourceBodyOffset,
		payloadMatcher,
		scanRangeStartIndex,
		scanRangeEndIndex,
		reflectionLocation,
		randomProvider,
	)
}

// NewPayloadReflectionLocatorWithMatcher creates a locator with a pre-built matcher.
func NewPayloadReflectionLocatorWithMatcher(
	scanTargetBytes []byte,
	sourceBodyOffset int,
	payloadMatcher ByteSequenceMatcher,
	scanRangeStartIndex int,
	scanRangeEndIndex int,
	reflectionLocation ReflectionLocation,
	randomProvider *utils.RandomGenerator,
) *PayloadReflectionLocator {

	return &PayloadReflectionLocator{
		scanTargetBytes:       scanTargetBytes,
		sourceBodyOffset:      sourceBodyOffset,
		payloadPatternMatcher: payloadMatcher,
		scanRangeStartIndex:   scanRangeStartIndex,
		scanRangeEndIndex:     scanRangeEndIndex,
		reflectionLocation:    reflectionLocation,
		randomProvider:        randomProvider,
	}
}

func (locator *PayloadReflectionLocator) LocateReflections(detector *HTTPReflectionPointDetector) {

	currentScanIndex := locator.scanRangeStartIndex

	for {
		payloadMatch := locator.payloadPatternMatcher.FindMatch(
			locator.scanTargetBytes,
			currentScanIndex,
			locator.scanRangeEndIndex,
		)
		if payloadMatch == nil {
			break
		}

		// In Go, slicing creates a view. If a true copy is needed like Arrays.copyOfRange:
		matchedPayloadSegment := make(
			[]byte,
			payloadMatch.MatchEndIndex-payloadMatch.MatchStartIndex,
		)
		copy(
			matchedPayloadSegment,
			locator.scanTargetBytes[payloadMatch.MatchStartIndex:payloadMatch.MatchEndIndex],
		)
		zap.L().Debug("[DEBUG LocateReflections] matchedPayloadSegment",
			zap.String("segment", string(matchedPayloadSegment)))

		currentScanIndex = payloadMatch.MatchStartIndex
		zap.L().Debug("[DEBUG LocateReflections] Calling NewReflectionContextualAnalyzer",
			zap.Int("currentScanIndex", currentScanIndex),
			zap.String("matchedPayloadSegment", string(matchedPayloadSegment)))
		contextAnalyzer := NewReflectionContextualAnalyzer(
			detector,
			currentScanIndex,
			locator.sourceBodyOffset,
			locator.reflectionLocation,
			locator.randomProvider,
			matchedPayloadSegment,
		)
		detectedReflection := contextAnalyzer.AnalyzedReflection()
		zap.L().Debug("[DEBUG LocateReflections] Got DetectedReflection",
			zap.Any("reflection", detectedReflection))

		zap.L().Debug("[DEBUG LocateReflections] Calling detector.AddReflection",
			zap.Int("reflectionLocation", int(locator.reflectionLocation)))
		detector.AddReflection(detectedReflection, locator.reflectionLocation)

		currentScanIndex = payloadMatch.MatchEndIndex
		zap.L().Debug("[DEBUG LocateReflections] Updated currentScanIndex",
			zap.Int("newIndex", currentScanIndex))

	}
}
