package claudestream

import (
	"strings"
	"testing"
	"time"
)

func TestDetectQuotaReset(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	now := time.Date(2026, 4, 21, 2, 18, 58, 0, loc)
	stream := strings.NewReader(strings.Join([]string{
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"You've hit your limit · resets 3am (Asia/Singapore)"}]}}`,
		`{"type":"result","subtype":"error","is_error":true,"duration_ms":1000,"num_turns":1,"result":"quota"}`,
	}, "\n"))

	info, err := DetectQuotaReset(stream, now)
	if err != nil {
		t.Fatalf("DetectQuotaReset: %v", err)
	}
	if info == nil {
		t.Fatal("DetectQuotaReset returned nil, want quota reset info")
	}

	want := time.Date(2026, 4, 21, 3, 0, 0, 0, loc)
	if !info.ResetAt.Equal(want) {
		t.Fatalf("ResetAt = %s, want %s", info.ResetAt.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if !strings.Contains(info.Message, "You've hit your limit") {
		t.Fatalf("Message = %q, want quota text", info.Message)
	}
}

func TestDetectQuotaResetRollsToNextDay(t *testing.T) {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	now := time.Date(2026, 4, 21, 4, 0, 0, 0, loc)
	stream := strings.NewReader(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"You've hit your limit · resets 03:00:01 (UTC)"}]}}`)

	info, err := DetectQuotaReset(stream, now)
	if err != nil {
		t.Fatalf("DetectQuotaReset: %v", err)
	}
	if info == nil {
		t.Fatal("DetectQuotaReset returned nil, want quota reset info")
	}

	want := time.Date(2026, 4, 22, 3, 0, 1, 0, loc)
	if !info.ResetAt.Equal(want) {
		t.Fatalf("ResetAt = %s, want %s", info.ResetAt.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}
