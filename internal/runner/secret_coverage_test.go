package runner

import (
	"context"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// testStripeKey is assembled so the literal never appears in source.
var testStripeKey = "sk_live_f0" + "1c79xuuug7" + "yodgzj5ws0" + "h1x2kyvho3"

type fixedResolver map[string]string

func (f fixedResolver) ResolveRequestUUID(h string) string { return f[h] }

// TestSecretCoverage_DAKeepsSecretDetectAndKISSkipsCovered: with the
// known-issue scan enabled, secret_detect stays in dynamic assessment; the
// records it analysed are recorded, and the known-issue secret batch scans only
// the records assessment did not reach. Identity collapses any overlap: the
// passive and batch findings for one secret on one URL hash the same.
func TestSecretCoverage_DAKeepsSecretDetectAndKISSkipsCovered(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	ctx := context.Background()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.ProjectUUID = database.DefaultProjectUUID

	body := `<script>var cfg={key:"` + testStripeKey + `"};</script>`
	save := func(path string) (string, *httpmsg.HttpRequestResponse) {
		rr, err := httpmsg.GetRawRequestFromURL("http://app.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		resp := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Content-Type": "text/html"}, body))
		rr = rr.WithResponse(resp)
		uuid, err := repo.SaveRecord(ctx, rr, "discovery", opts.ProjectUUID)
		if err != nil {
			t.Fatal(err)
		}
		return uuid, rr
	}
	coveredUUID, coveredRR := save("/covered")
	_, _ = save("/uncovered")

	// Dynamic assessment: secret_detect is wrapped, not removed.
	cov := newSecretCoverage()
	wrapped := wrapSecretCoverage([]modules.PassiveModule{secret_detect.New()}, cov)
	if len(wrapped) != 1 || wrapped[0].ID() != secret_detect.ModuleID {
		t.Fatal("secret_detect must stay in the assessment module list")
	}
	scanCtx := &modules.ScanContext{RequestUUIDResolver: fixedResolver{coveredRR.Request().ID(): coveredUUID}}
	passive, err := wrapped[0].ScanPerRequest(coveredRR, scanCtx)
	if err != nil || len(passive) == 0 {
		t.Fatalf("passive secret_detect found nothing: %v", err)
	}
	if !cov.has(coveredUUID) || cov.len() != 1 {
		t.Fatalf("coverage = %d, want the covered record only", cov.len())
	}

	// Known-issue secret batch: only /uncovered is scanned.
	r := &Runner{options: opts, repository: repo, settings: config.DefaultSettings(), secretCoverage: cov}
	var mu sync.Mutex
	var urls []string
	var batch []*output.ResultEvent
	if err := r.runSecretScanBatch(ctx, &phaseInfra{scanUUID: "s1"}, func(ev *output.ResultEvent) {
		mu.Lock()
		urls = append(urls, ev.URL)
		batch = append(batch, ev)
		mu.Unlock()
	}, nil); err != nil {
		t.Fatal(err)
	}
	for _, u := range urls {
		if u == "http://app.test/covered" {
			t.Fatalf("batch rescanned a record assessment covered: %v", urls)
		}
	}
	if len(urls) == 0 {
		t.Fatal("batch must still scan the record assessment did not reach")
	}

	// Without coverage the batch scans both, and the covered record's batch
	// finding has the same identity as the passive one.
	r.secretCoverage = nil
	batch = nil
	if err := r.runSecretScanBatch(ctx, &phaseInfra{scanUUID: "s2"}, func(ev *output.ResultEvent) {
		mu.Lock()
		batch = append(batch, ev)
		mu.Unlock()
	}, nil); err != nil {
		t.Fatal(err)
	}
	var matched bool
	for _, ev := range batch {
		if ev.URL == passive[0].URL && ev.ID() == passive[0].ID() {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("passive and batch findings for one secret on one URL must share identity (passive %s %s)", passive[0].URL, passive[0].ID())
	}
}
