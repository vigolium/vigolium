package core

import (
	"context"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// repoRiskScoreUpdater adapts *database.Repository to modkit.RiskScoreUpdater.
type repoRiskScoreUpdater struct {
	repo *database.Repository
}

func (u *repoRiskScoreUpdater) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	return u.repo.UpdateRiskScores(ctx, scores)
}

// executorFeeder implements modkit.RequestFeeder via a non-blocking channel send.
type executorFeeder struct {
	ch       chan *work.WorkItem
	dropped  atomic.Int64
	lastWarn atomic.Int64
}

func (f *executorFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	item := work.NewWithModules(rr, nil)
	select {
	case f.ch <- item:
		return true
	default:
		f.dropped.Add(1)
		// Rate-limited warning: log at most once every 5 seconds
		now := time.Now().Unix()
		if last := f.lastWarn.Load(); now-last >= 5 {
			if f.lastWarn.CompareAndSwap(last, now) {
				zap.L().Warn("Feedback channel full, discovered URLs dropped",
					zap.Int64("total_dropped", f.dropped.Load()))
			}
		}
		return false
	}
}

// Dropped returns the total number of feedback items dropped due to channel capacity.
func (f *executorFeeder) Dropped() int64 {
	return f.dropped.Load()
}

// nopFeeder is the RequestFeeder used when ExecutorConfig.DisableFeedback is
// set: every Feed call returns false without doing any work. Lets modules
// that unconditionally call feeder.Feed(rr) keep working without forcing
// every caller to nil-check.
type nopFeeder struct{}

func (nopFeeder) Feed(*httpmsg.HttpRequestResponse) bool { return false }

var nopFeederInstance = nopFeeder{}

// executorIPProvider wraps the executor's LRU insertion point cache
// as a modkit.InsertionPointProvider so modules can reuse cached IPs.
type executorIPProvider struct {
	cache *lru.Cache[string, []httpmsg.InsertionPoint]
}

func (p *executorIPProvider) GetInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	if p.cache == nil {
		return httpmsg.CreateAllInsertionPoints(raw, includeNested)
	}

	// Cache key includes includeNested flag to separate variants
	key := requestID
	if !includeNested {
		key = requestID + ":shallow"
	}

	if points, ok := p.cache.Get(key); ok {
		return points, nil
	}

	points, err := httpmsg.CreateAllInsertionPoints(raw, includeNested)
	if err != nil {
		return nil, err
	}
	p.cache.Add(key, points)
	return points, nil
}

// repoRemarksAnnotator adapts *database.Repository to modkit.RemarksAnnotator.
type repoRemarksAnnotator struct {
	repo *database.Repository
}

func (u *repoRemarksAnnotator) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	return u.repo.AppendRemarks(ctx, annotations)
}
