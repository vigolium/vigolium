package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// PayloadReflectionLocator is the Go equivalent of the Java class hqr.
type PayloadReflectionLocator struct {
	// private final byte[] b;
	scanTargetBytes []byte
	// private final int g;
	sourceBodyOffset int
	// private final db9 f;
	payloadPatternMatcher ByteSequenceMatcher
	// private final int e;
	scanRangeStartIndex int
	// private final int c;
	scanRangeEndIndex int
	// private final byte a;
	reflectionLocation ReflectionLocation
	// private final ou d;
	randomProvider *utils.RandomGenerator
}

// NewPayloadReflectionLocator is the public constructor for Hqr.
// Corresponds to Java: public hqr(byte[] var1, int var2, byte[] var3, int var4, int var5, byte var6, ou var7)
// var3 (in Java) is the original full payload/canary used for deeper dc3 analysis.
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
	// this(var1, var2, e8u.a(var3), var4, var5, var6, var7);
	// In the Java erw.a, var3 to hqr constructor is the *original payload* (erw.c).
	// The db9 pattern is created from this original payload using e8u.a(original_payload).
	// So, payloadMatcher should be created from var3OriginalPayload.
	payloadMatcher := NewSimpleBytePatternMatcher(
		originalPayloadBytes,
	) // e8u.a(var3OriginalPayload)
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

// NewPayloadReflectionLocatorWithMatcher is the unexported constructor.
// Corresponds to Java: hqr(byte[] var1, int var2, db9 var3, int var4, int var5, byte var6, ou var7)
// Added originalPayload for dc3 canary consistency.
func NewPayloadReflectionLocatorWithMatcher(
	scanTargetBytes []byte, // b
	sourceBodyOffset int, // g
	payloadMatcher ByteSequenceMatcher, // f (created from original payload)
	scanRangeStartIndex int, // e
	scanRangeEndIndex int, // c
	reflectionLocation ReflectionLocation, // a
	randomProvider *utils.RandomGenerator, // d
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

// LocateReflections is the Go equivalent of the public Java method a(crp var1).
func (locator *PayloadReflectionLocator) LocateReflections(detector *HTTPReflectionPointDetector) {
	// int var2 = hpo.);

	// int var3 = this.e;
	currentScanIndex := locator.scanRangeStartIndex

	// cc4 var4;
	// var  var4Cc4*MatchSpan // Declare var4Cc4 as a pointer to Cc4, can be nil

	// while (null != (var4 = this.f.a(this.b, var3, this.c))) {
	// this.f (valFDb9 Db9) calls method A(data []byte, val2 int, val3 int) *Cc4
	// this.b (valBBytes []byte)
	// var3 (var3CurrentIndex)
	// this.c (valCInt int)
	for {
		payloadMatch := locator.payloadPatternMatcher.FindMatch(
			locator.scanTargetBytes,
			currentScanIndex,
			locator.scanRangeEndIndex,
		)
		if payloadMatch == nil {
			break
		}

		// byte[] var5 = Arrays.copyOfRange(this.b, var4.b, var4.a);
		// In Go, slicing creates a view. If a true copy is needed like Arrays.copyOfRange:
		matchedPayloadSegment := make(
			[]byte,
			payloadMatch.MatchEndIndex-payloadMatch.MatchStartIndex,
		) // var4.a is 'A', var4.b is 'B' in Cc4 struct
		copy(
			matchedPayloadSegment,
			locator.scanTargetBytes[payloadMatch.MatchStartIndex:payloadMatch.MatchEndIndex],
		)
		zap.L().Debug("[DEBUG LocateReflections] matchedPayloadSegment",
			zap.String("segment", string(matchedPayloadSegment)))

		// var3 = var4.b;
		currentScanIndex = payloadMatch.MatchStartIndex
		// eqx var6 = this.a(var1, var3, var5).b();
		// this.a calls the internal newDc3FromHqr
		zap.L().Debug("[DEBUG LocateReflections] Calling NewReflectionContextualAnalyzer",
			zap.Int("currentScanIndex", currentScanIndex),
			zap.String("matchedPayloadSegment", string(matchedPayloadSegment)))
		// contextAnalyzer := receiver.newDc3FromHqr(b5k, var3CurrentIndex, var5Bytes)
		contextAnalyzer := NewReflectionContextualAnalyzer(
			detector,                   // var1
			currentScanIndex,           // var2 (start of matched db9 pattern in targetBytes)
			locator.sourceBodyOffset,   // this.g (overallBodyOffsetInFullResponse)
			locator.reflectionLocation, // this.a (contextIndicatorForEqx)
			locator.randomProvider,     // this.d (RandomGenerator instance)
			matchedPayloadSegment,
		)
		detectedReflection := contextAnalyzer.AnalyzedReflection() // AnalyzedReflection() is the method on Dc3 that returns Eqx (from dc3.go)
		zap.L().Debug("[DEBUG LocateReflections] Got DetectedReflection",
			zap.Any("reflection", detectedReflection))

		// var1.a(var6, this.a);
		// crpVal (Crp interface) calls AEqxByte(Eqx, byte)
		zap.L().Debug("[DEBUG LocateReflections] Calling detector.AddReflection",
			zap.Int("reflectionLocation", int(locator.reflectionLocation)))
		detector.AddReflection(detectedReflection, locator.reflectionLocation)

		// var3 = var4.a;
		currentScanIndex = payloadMatch.MatchEndIndex
		zap.L().Debug("[DEBUG LocateReflections] Updated currentScanIndex",
			zap.Int("newIndex", currentScanIndex))

	}
}
