package kingfisher

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		scanner, err := NewScanner(nil)
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &Config{
			CacheDir: t.TempDir(),
		}
		scanner, err := NewScanner(config)
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
	})
}

func TestScanner_ScanEmptyBody(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result, err := scanner.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan empty: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.BytesScanned != 0 {
		t.Errorf("expected 0 bytes scanned, got %d", result.BytesScanned)
	}
}

func TestScanner_ScanEmptySlice(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result, err := scanner.Scan(context.Background(), []byte{})
	if err != nil {
		t.Fatalf("Scan empty slice: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestScanner_Version(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	// Before any scan, version should be empty
	if v := scanner.Version(); v != "" {
		t.Errorf("expected empty version before scan, got %q", v)
	}
}

func TestScanner_BinaryPath(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	// Before any scan, binary path should be empty
	if p := scanner.BinaryPath(); p != "" {
		t.Errorf("expected empty binary path before scan, got %q", p)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if !config.AutoUpdate {
		t.Error("expected AutoUpdate to be true")
	}
	if config.HTTPTimeout != 60*time.Second {
		t.Errorf("expected 60s HTTP timeout, got %v", config.HTTPTimeout)
	}
	if config.CacheDir != "" {
		t.Errorf("expected empty CacheDir (default), got %q", config.CacheDir)
	}
	if config.Version != "" {
		t.Errorf("expected empty Version (latest), got %q", config.Version)
	}
}

func TestScanResult_HasFindings(t *testing.T) {
	t.Run("empty findings", func(t *testing.T) {
		result := &ScanResult{Findings: []Finding{}}
		if result.HasFindings() {
			t.Error("expected HasFindings to return false for empty findings")
		}
	})

	t.Run("with findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{{Rule: RuleInfo{Name: "test", ID: "test.1"}}},
		}
		if !result.HasFindings() {
			t.Error("expected HasFindings to return true")
		}
	})
}

func TestScanResult_VerifiedFindings(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{Rule: RuleInfo{ID: "rule1"}, Finding: FindingInfo{Validation: ValidationInfo{Status: "Verified"}}},
			{Rule: RuleInfo{ID: "rule2"}, Finding: FindingInfo{Validation: ValidationInfo{Status: "Not Attempted"}}},
			{Rule: RuleInfo{ID: "rule3"}, Finding: FindingInfo{Validation: ValidationInfo{Status: "Verified"}}},
		},
	}

	verified := result.VerifiedFindings()
	if len(verified) != 2 {
		t.Errorf("expected 2 verified findings, got %d", len(verified))
	}

	for _, f := range verified {
		if !f.IsValidated() {
			t.Errorf("finding %s should be verified", f.Rule.ID)
		}
	}
}

func TestFinding_Methods(t *testing.T) {
	f := Finding{
		Rule:    RuleInfo{Name: "MongoDB URI", ID: "kingfisher.mongodb.3"},
		Finding: FindingInfo{Snippet: "mongodb://...", Validation: ValidationInfo{Status: "Verified"}},
	}

	if f.RuleName() != "MongoDB URI" {
		t.Errorf("expected RuleName 'MongoDB URI', got %q", f.RuleName())
	}
	if f.RuleID() != "kingfisher.mongodb.3" {
		t.Errorf("expected RuleID 'kingfisher.mongodb.3', got %q", f.RuleID())
	}
	if f.Snippet() != "mongodb://..." {
		t.Errorf("expected Snippet 'mongodb://...', got %q", f.Snippet())
	}
	if !f.IsValidated() {
		t.Error("expected IsValidated to be true")
	}
}

func TestParseKingfisherOutput(t *testing.T) {
	t.Run("empty output", func(t *testing.T) {
		findings, err := parseKingfisherOutput([]byte{})
		if err != nil {
			t.Fatalf("parseKingfisherOutput: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("json array", func(t *testing.T) {
		output := `[{"rule":{"name":"test1","id":"t.1"},"finding":{"snippet":"s1"}},{"rule":{"name":"test2","id":"t.2"},"finding":{"snippet":"s2"}}]`
		findings, err := parseKingfisherOutput([]byte(output))
		if err != nil {
			t.Fatalf("parseKingfisherOutput: %v", err)
		}
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("jsonl format", func(t *testing.T) {
		output := `{"rule":{"name":"MongoDB URI","id":"kingfisher.mongodb.3"},"finding":{"snippet":"mongodb://admin:pass@localhost:27017","confidence":"medium"}}
{"rule":{"name":"AWS Access Key","id":"kingfisher.aws.1"},"finding":{"snippet":"AKIAIOSFODNN7EXAMPLE","confidence":"high"}}`
		findings, err := parseKingfisherOutput([]byte(output))
		if err != nil {
			t.Fatalf("parseKingfisherOutput: %v", err)
		}
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
		if findings[0].Rule.Name != "MongoDB URI" {
			t.Errorf("expected rule name 'MongoDB URI', got %q", findings[0].Rule.Name)
		}
	})

	t.Run("jsonl with empty lines", func(t *testing.T) {
		output := `{"rule":{"name":"test1","id":"t.1"},"finding":{"snippet":"s1"}}

{"rule":{"name":"test2","id":"t.2"},"finding":{"snippet":"s2"}}
`
		findings, err := parseKingfisherOutput([]byte(output))
		if err != nil {
			t.Fatalf("parseKingfisherOutput: %v", err)
		}
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})
}

// Integration test - requires network access and downloads binary
func TestScanner_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := &Config{
		CacheDir:    t.TempDir(),
		HTTPTimeout: 120 * time.Second,
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	// Pre-download binary
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := scanner.EnsureBinary(ctx); err != nil {
		// Skip on network or GitHub API errors — this test requires internet access.
		errMsg := err.Error()
		if strings.Contains(errMsg, "403") ||
			strings.Contains(errMsg, "rate") ||
			strings.Contains(errMsg, "connection reset") ||
			strings.Contains(errMsg, "timeout") ||
			strings.Contains(errMsg, "no such host") ||
			strings.Contains(errMsg, "context deadline") ||
			strings.Contains(errMsg, "connection refused") {
			t.Skipf("Skipping integration test: network/API error: %v", err)
		}
		t.Fatalf("EnsureBinary: %v", err)
	}

	// Verify version is populated
	if v := scanner.Version(); v == "" {
		t.Error("expected non-empty version after EnsureBinary")
	}

	// Test with sample content containing a potential secret
	body := []byte(`
		{
			"config": {
				"mongodb": "mongodb://admin:password123@localhost:27017/mydb",
				"aws_access_key": "AKIAIOSFODNN7EXAMPLE"
			}
		}
	`)

	result, err := scanner.Scan(ctx, body)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	t.Logf("Scan completed in %v, found %d findings", result.ScanDuration, len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  - %s: %s (validated: %v)", f.RuleID(), f.RuleName(), f.IsValidated())
	}
}
