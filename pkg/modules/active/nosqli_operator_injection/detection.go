package nosqli_operator_injection

import (
	"math"
	"regexp"
	"strings"
	"time"
)

// nosqlErrorPatterns are used to skip findings when the response contains NoSQL error messages
// (those are handled by nosqli_error_based module instead).
var nosqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)MongoError|BSON|mongod|MongoClient|TopologyDescription`),
	regexp.MustCompile(`(?i)E11000 duplicate key|cannot index parallel arrays|\$where requires`),
	regexp.MustCompile(`(?i)couchdb|org\.apache\.couchdb`),
	regexp.MustCompile(`(?i)com\.datastax\.driver|InvalidRequestException|SyntaxException.*CQL`),
}

const (
	timeDelayThresholdMs = 80   // milliseconds over baseline to consider time-based injection
	sizeIncreasePercent  = 50   // percent body size increase to consider data exfiltration
	sizeIncreaseMinBytes = 200  // minimum absolute increase in bytes
)

// containsNoSQLError checks if the response body contains NoSQL error patterns.
func containsNoSQLError(body string) bool {
	for _, pattern := range nosqlErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// analyzeAuthBypass checks if status changed from 401/403 to 200-range.
func analyzeAuthBypass(baselineStatus, probeStatus int) bool {
	if baselineStatus == 401 || baselineStatus == 403 {
		return probeStatus >= 200 && probeStatus < 300
	}
	return false
}

// analyzeSizeIncrease checks if body grew significantly compared to baseline.
func analyzeSizeIncrease(baselineLen, probeLen int) bool {
	if baselineLen == 0 {
		return probeLen >= sizeIncreaseMinBytes
	}
	increase := probeLen - baselineLen
	if increase < sizeIncreaseMinBytes {
		return false
	}
	percentIncrease := (float64(increase) / float64(baselineLen)) * 100
	return percentIncrease >= sizeIncreasePercent
}

// analyzeTimeDelay checks if response time is significantly slower than baseline.
func analyzeTimeDelay(baselineDuration, probeDuration time.Duration) bool {
	delta := probeDuration - baselineDuration
	return delta.Milliseconds() >= timeDelayThresholdMs
}

// analyzeBooleanDiff checks if two response bodies differ significantly.
func analyzeBooleanDiff(trueBody, falseBody string) bool {
	if trueBody == falseBody {
		return false
	}
	// Simple length-based comparison — if bodies differ by more than 10%, consider it a boolean diff
	lenDiff := math.Abs(float64(len(trueBody)) - float64(len(falseBody)))
	maxLen := math.Max(float64(len(trueBody)), float64(len(falseBody)))
	if maxLen == 0 {
		return false
	}
	// Also check that the bodies actually differ in content
	return lenDiff/maxLen > 0.1 || !strings.Contains(trueBody, falseBody[:min(len(falseBody), 100)])
}

