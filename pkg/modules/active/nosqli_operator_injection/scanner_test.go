package nosqli_operator_injection

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestContainsNoSQLError(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"mongodb error", "MongoError: bad query", true},
		{"couchdb error", `{"error":"bad_request","reason":"invalid_json"}`, false},
		{"couchdb org", "org.apache.couchdb.error", true},
		{"no error", "normal response body", false},
		{"empty", "", false},
		{"duplicate key", "E11000 duplicate key error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNoSQLError(tt.body)
			if got != tt.expected {
				t.Errorf("containsNoSQLError(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeAuthBypass(t *testing.T) {
	tests := []struct {
		name           string
		baselineStatus int
		probeStatus    int
		expected       bool
	}{
		{"401 to 200", 401, 200, true},
		{"403 to 200", 403, 200, true},
		{"401 to 302", 401, 302, false},
		{"200 to 200", 200, 200, false},
		{"403 to 403", 403, 403, false},
		{"401 to 201", 401, 201, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeAuthBypass(tt.baselineStatus, tt.probeStatus)
			if got != tt.expected {
				t.Errorf("analyzeAuthBypass(%d, %d) = %v, want %v", tt.baselineStatus, tt.probeStatus, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeSizeIncrease(t *testing.T) {
	tests := []struct {
		name        string
		baselineLen int
		probeLen    int
		expected    bool
	}{
		{"significant increase", 100, 500, true},
		{"small increase", 100, 120, false},
		{"no increase", 100, 100, false},
		{"decrease", 100, 50, false},
		{"zero baseline large probe", 0, 300, true},
		{"zero baseline small probe", 0, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeSizeIncrease(tt.baselineLen, tt.probeLen)
			if got != tt.expected {
				t.Errorf("analyzeSizeIncrease(%d, %d) = %v, want %v", tt.baselineLen, tt.probeLen, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeTimeDelay(t *testing.T) {
	tests := []struct {
		name             string
		baselineDuration time.Duration
		probeDuration    time.Duration
		expected         bool
	}{
		{"significant delay", 10 * time.Millisecond, 100 * time.Millisecond, true},
		{"small delay", 10 * time.Millisecond, 50 * time.Millisecond, false},
		{"no delay", 10 * time.Millisecond, 10 * time.Millisecond, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeTimeDelay(tt.baselineDuration, tt.probeDuration)
			if got != tt.expected {
				t.Errorf("analyzeTimeDelay() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAnalyzeBooleanDiff(t *testing.T) {
	tests := []struct {
		name      string
		trueBody  string
		falseBody string
		expected  bool
	}{
		{"same body", "same content", "same content", false},
		{"different bodies", "this is a much longer response with data", "short", true},
		{"empty both", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeBooleanDiff(tt.trueBody, tt.falseBody)
			if got != tt.expected {
				t.Errorf("analyzeBooleanDiff() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetPayloadsForType(t *testing.T) {
	jsonPayloads := getPayloadsForType(httpmsg.INS_PARAM_JSON)
	if len(jsonPayloads) == 0 {
		t.Error("expected JSON payloads, got none")
	}

	urlPayloads := getPayloadsForType(httpmsg.INS_PARAM_URL)
	if len(urlPayloads) == 0 {
		t.Error("expected URL payloads, got none")
	}

	bodyPayloads := getPayloadsForType(httpmsg.INS_PARAM_BODY)
	if len(bodyPayloads) == 0 {
		t.Error("expected body payloads, got none")
	}

	// JSON payloads should include JSON operators
	hasJSON := false
	for _, p := range jsonPayloads {
		if p.value == `{"$ne":""}` {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		t.Error("JSON payloads should include $ne operator")
	}

	// URL payloads should include array syntax
	hasArray := false
	for _, p := range urlPayloads {
		if p.value == "[$ne]=" {
			hasArray = true
			break
		}
	}
	if !hasArray {
		t.Error("URL payloads should include array syntax")
	}
}
