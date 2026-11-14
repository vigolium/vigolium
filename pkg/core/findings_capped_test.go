package core

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func cappedEvent(param, desc, url string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:           "sqli-error",
		Info:               output.Info{Name: "SQL Injection", Description: desc, Severity: severity.High},
		URL:                url,
		Matched:            url,
		BaseURL:            "https://app.test/item",
		Request:            "GET /item HTTP/1.1\r\n\r\n",
		InsertionPointType: "URL_PARAM",
		FuzzingParameter:   param,
	}
}

// TestFindingsCapped_CountsDistinctIdentities is RES-1: the cap counts
// distinct findings (identity keys), the drop count names each dropped finding
// once, and payload/prose variants of one finding consume nothing.
func TestFindingsCapped_CountsDistinctIdentities(t *testing.T) {
	e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 2}}
	for i := 0; i < 5; i++ {
		ev := cappedEvent(fmt.Sprintf("p%d", i), "error", "https://app.test/item")
		e.admitFinding(ev.ID(), ev.ModuleID)
	}
	// A repeat of a dropped finding is not a second drop.
	again := cappedEvent("p4", "error", "https://app.test/item")
	e.admitFinding(again.ID(), again.ModuleID)
	if got := e.Report().FindingsCapped["sqli-error"]; got != 3 {
		t.Fatalf("capped = %d, want 3 (5 params, cap 2)", got)
	}

	v := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 2}}
	for i := 0; i < 5; i++ {
		ev := cappedEvent("id", fmt.Sprintf("error after %dms", i), fmt.Sprintf("https://app.test/item?id=%d'", i))
		if _, allowed := v.admitFinding(ev.ID(), ev.ModuleID); !allowed {
			t.Fatalf("variant %d of one finding was capped", i)
		}
	}
	if got := v.Report().FindingsCapped; len(got) != 0 {
		t.Fatalf("capped = %v, want none for value variants of one finding", got)
	}
}
