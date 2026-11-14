package runner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// tierProbe is a per-request active module that counts the records it ran on
// and optionally sleeps per call.
type tierProbe struct {
	modkit.BaseActiveModule
	class int
	delay time.Duration
	mu    sync.Mutex
	seen  map[string]int
	calls atomic.Int64
}

func newTierProbe(id string, class int, delay time.Duration) *tierProbe {
	return &tierProbe{
		BaseActiveModule: modkit.NewBaseActiveModule(id, id, "d", "s", "c", 0, 0,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes),
		class: class, delay: delay, seen: map[string]int{},
	}
}

func (m *tierProbe) ClassPriority() int                           { return m.class }
func (m *tierProbe) CanProcess(*httpmsg.HttpRequestResponse) bool { return true }
func (m *tierProbe) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *protohttp.Requester, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	m.seen[item.Request().Path()]++
	m.mu.Unlock()
	return nil, nil
}

func seedTierRecords(t *testing.T, repo *database.Repository, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		raw := fmt.Sprintf("GET /page-%c HTTP/1.1\r\nHost: tier.test\r\n\r\n", rune('a'+i))
		req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("tier.test", 443, true), []byte(raw))
		rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>")))
		if _, err := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID); err != nil {
			t.Fatal(err)
		}
	}
}

func tierRunner(t *testing.T, repo *database.Repository, scanUUID string) (*Runner, *phaseInfra, core.ExecutorConfig) {
	t.Helper()
	if err := repo.CreateScan(context.Background(), &database.Scan{UUID: scanUUID, ProjectUUID: database.DefaultProjectUUID, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	r := &Runner{repository: repo, options: &types.Options{Silent: true}}
	infra := &phaseInfra{scanUUID: scanUUID}
	cfg := core.ExecutorConfig{
		Workers: 4, SkipBaseline: true, Repository: repo, ScanUUID: scanUUID,
		ProjectUUID: database.DefaultProjectUUID,
	}
	return r, infra, cfg
}

// Tiered passes: under a deadline the slow tier cannot meet, the
// cheap tier still covers every record, because it runs across all records
// first instead of record-major alongside the slow module.
func TestTieredRoundCoversCheapTierFirst(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	seedTierRecords(t, repo, 20)
	r, infra, cfg := tierRunner(t, repo, "scan-tier")

	cheap := newTierProbe("cheap-inband", modkit.ClassCostInBand, 0)
	slow := newTierProbe("slow-timing", modkit.ClassCostTiming, 400*time.Millisecond)
	active := []modules.ActiveModule{slow, cheap} // slow first: record-major order would favour it

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l := r.prepareDALedger(ctx, infra.scanUUID, active, nil)
	if l == nil || len(l.pass0) != 1 || len(l.pass1) != 1 {
		t.Fatalf("tier split: %+v", l)
	}
	_, _ = r.runDynamicAssessmentRound(ctx, infra, 0, nil, active, nil, cfg, nil, l)
	l.close()

	cheap.mu.Lock()
	covered := len(cheap.seen)
	cheap.mu.Unlock()
	if covered != 20 {
		t.Fatalf("cheap tier covered %d/20 records under the deadline", covered)
	}
}

// Resume: a second run of the same scan skips every record whose
// tier-0 work the ledger records as done — the cheap module runs 0 times.
func TestTieredRoundResumeSkipsDoneWork(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	seedTierRecords(t, repo, 6)
	r, infra, cfg := tierRunner(t, repo, "scan-resume")

	cheap := newTierProbe("cheap-inband", modkit.ClassCostInBand, 0)
	slow := newTierProbe("slow-timing", modkit.ClassCostTiming, 0)
	active := []modules.ActiveModule{cheap, slow}
	ctx := context.Background()

	l := r.prepareDALedger(ctx, infra.scanUUID, active, nil)
	if _, err := r.runDynamicAssessmentRound(ctx, infra, 0, nil, active, nil, cfg, nil, l); err != nil {
		t.Fatal(err)
	}
	l.close()
	if cheap.calls.Load() != 6 || slow.calls.Load() != 6 {
		t.Fatalf("first run: cheap=%d slow=%d, want 6/6", cheap.calls.Load(), slow.calls.Load())
	}
	var rows []database.ScanRecordProgress
	if err := repo.DB().NewSelect().Model(&rows).Where("scan_uuid = ?", infra.scanUUID).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		t.Fatalf("ledger rows = %d, want 6", len(rows))
	}
	for _, row := range rows {
		if row.TierDone != 1 {
			t.Fatalf("record %s tier_done = %d, want 1 (bits %x)", row.RecordUUID, row.TierDone, row.DoneBits)
		}
	}

	// Run 2 of the same scan, cursor reset as a fresh phase would.
	if err := repo.ResetScanCursor(ctx, infra.scanUUID); err != nil {
		t.Fatal(err)
	}
	cheap2 := newTierProbe("cheap-inband", modkit.ClassCostInBand, 0)
	slow2 := newTierProbe("slow-timing", modkit.ClassCostTiming, 0)
	active2 := []modules.ActiveModule{cheap2, slow2}
	l2 := r.prepareDALedger(ctx, infra.scanUUID, active2, nil)
	if _, err := r.runDynamicAssessmentRound(ctx, infra, 0, nil, active2, nil, cfg, nil, l2); err != nil {
		t.Fatal(err)
	}
	l2.close()
	if n := cheap2.calls.Load() + slow2.calls.Load(); n != 0 {
		t.Fatalf("resumed run re-ran %d module calls on finished records", n)
	}
}
