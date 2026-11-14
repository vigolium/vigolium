package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestSecretBatch_MemoAndOrderedEmit: a body stored under several URLs is
// detected once (memo by decoded-body hash) yet graded per URL, and findings
// are emitted in record order from the worker pool.
func TestSecretBatch_MemoAndOrderedEmit(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	ctx := context.Background()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.ProjectUUID = database.DefaultProjectUUID

	shared := `<script>var k="` + testStripeKey + `";</script>`
	other := `<p>nothing to see</p>`
	var records []*database.HTTPRecord
	for _, tc := range []struct{ path, body string }{
		{"/a", shared}, {"/b", other}, {"/c", shared}, {"/d", shared},
	} {
		rr, err := httpmsg.GetRawRequestFromURL("http://app.test" + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Content-Type": "text/html"}, tc.body))
		if _, err := repo.SaveRecord(ctx, rr.WithResponse(resp), "discovery", opts.ProjectUUID); err != nil {
			t.Fatal(err)
		}
	}
	records, err := repo.GetRecordsWithResponseBody(ctx, opts.ProjectUUID, "", 100)
	if err != nil || len(records) != 4 {
		t.Fatalf("records: %v %d", err, len(records))
	}

	det, err := secretscan.Default()
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{options: opts, repository: repo, settings: config.DefaultSettings()}
	memo := newSecretMatchMemo()
	var got []string
	if _, err := r.scanSecretRecordBatch(ctx, &phaseInfra{scanUUID: "s"}, det, memo, records,
		map[string]struct{}{}, func(ev *output.ResultEvent) { got = append(got, ev.URL) }); err != nil {
		t.Fatal(err)
	}
	if len(memo.m) != 2 {
		t.Fatalf("memo entries = %d, want 2 distinct bodies", len(memo.m))
	}
	// Every URL carrying the secret is reported, in record (uuid) order.
	var want []string
	for _, rec := range records {
		if rec.URL != "http://app.test/b" {
			want = append(want, rec.URL)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("emitted %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("emit order %v, want record order %v", got, want)
		}
	}
}

// blockingSource is a harvester source that holds until released, counting
// whether it was started.
type blockingSource struct {
	started atomic.Bool
	release chan struct{}
}

func (b *blockingSource) Name() string   { return "fake" }
func (b *blockingSource) NeedsKey() bool { return false }
func (b *blockingSource) Run(ctx context.Context, domain string) <-chan harvester.Result {
	out := make(chan harvester.Result, 2)
	go func() {
		defer close(out)
		b.started.Store(true)
		select {
		case <-b.release:
		case <-ctx.Done():
			return
		}
		out <- harvester.Result{Source: "fake", URL: "https://" + domain + "/archived/one"}
		out <- harvester.Result{Source: "fake", URL: "https://" + domain + "/archived/two"}
	}()
	return out
}

// TestHarvestPrefetch_RunsInBackground: the archive queries start before the
// harvest phase and the phase only joins them.
func TestHarvestPrefetch_RunsInBackground(t *testing.T) {
	fake := &blockingSource{release: make(chan struct{})}
	build := func() *source.ExternalHarvesterInputSource {
		h := harvester.New([]harvester.Source{fake}, 10*time.Second)
		return source.NewExternalHarvesterInputSource(h, []string{"app.test"}, nil)
	}
	p := startHarvestPrefetch(context.Background(), build)
	deadline := time.Now().Add(5 * time.Second)
	for !fake.started.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !fake.started.Load() {
		t.Fatal("prefetch did not start the archive source in the background")
	}
	select {
	case <-p.done:
		t.Fatal("prefetch finished before the source released")
	default:
	}
	close(fake.release)
	if err := p.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := p.replay()
	n := 0
	for {
		item, err := src.Next(context.Background())
		if err != nil {
			break
		}
		if item != nil {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("replayed %d items, want 2", n)
	}
	p.stop()

	// An unconsumed prefetch is cancelled cleanly.
	stuck := &blockingSource{release: make(chan struct{})}
	p2 := startHarvestPrefetch(context.Background(), func() *source.ExternalHarvesterInputSource {
		return source.NewExternalHarvesterInputSource(harvester.New([]harvester.Source{stuck}, time.Minute), []string{"app.test"}, nil)
	})
	done := make(chan struct{})
	go func() { p2.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel the background harvest")
	}
	var nilP *harvestPrefetch
	nilP.stop()
}
