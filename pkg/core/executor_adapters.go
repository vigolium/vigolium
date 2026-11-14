package core

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
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

// repoSurfaceScoreUpdater adapts *database.Repository to modkit.SurfaceScoreUpdater.
type repoSurfaceScoreUpdater struct {
	repo *database.Repository
}

func (u *repoSurfaceScoreUpdater) UpdateSurfaceScores(ctx context.Context, scores map[string]int) error {
	return u.repo.UpdateSurfaceScores(ctx, scores)
}

// defaultFeedbackOverflowCap bounds the feeder's overflow list. Discovered
// requests past the channel wait there instead of being dropped; only past this
// many are they dropped (and the phase is marked partial: feedback_dropped).
const defaultFeedbackOverflowCap = 50000

// executorFeeder implements modkit.RequestFeeder. Discovered work goes to the
// feedback channel when there is room, otherwise to a bounded overflow list
// (deduplicated by request id) that the executor drains after the channel. A
// producer never waits: the old 100ms bounded-blocking send dropped discovered
// URLs whenever a burst outlasted it, and nothing reported the loss (MISS-32).
type executorFeeder struct {
	ch chan *work.WorkItem
	// overflowCap overrides defaultFeedbackOverflowCap (tests).
	overflowCap int

	mu       sync.Mutex
	overflow []*work.WorkItem
	ids      map[string]struct{}

	dropped  atomic.Int64
	lastWarn atomic.Int64
}

func (f *executorFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	item := work.NewWithModules(rr, nil)
	// Fast path: enqueue immediately when there's room.
	select {
	case f.ch <- item:
		return true
	default:
	}

	id := ""
	if rr != nil && rr.Request() != nil {
		id = rr.Request().ID()
	}
	limit := f.overflowCap
	if limit <= 0 {
		limit = defaultFeedbackOverflowCap
	}
	f.mu.Lock()
	if id != "" {
		if _, dup := f.ids[id]; dup {
			f.mu.Unlock()
			return true // already waiting in the overflow list
		}
	}
	if len(f.overflow) < limit {
		f.overflow = append(f.overflow, item)
		if id != "" {
			if f.ids == nil {
				f.ids = make(map[string]struct{})
			}
			f.ids[id] = struct{}{}
		}
		f.mu.Unlock()
		return true
	}
	f.mu.Unlock()

	f.dropped.Add(1)
	// Rate-limited warning: log at most once every 5 seconds.
	now := time.Now().Unix()
	if last := f.lastWarn.Load(); now-last >= 5 {
		if f.lastWarn.CompareAndSwap(last, now) {
			zap.L().Warn("Feedback overflow full, discovered URLs dropped",
				zap.Int64("total_dropped", f.dropped.Load()))
		}
	}
	return false
}

// takeOverflow removes and returns up to n overflow items (all when n <= 0).
func (f *executorFeeder) takeOverflow(n int) []*work.WorkItem {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.overflow) == 0 {
		return nil
	}
	if n <= 0 || n > len(f.overflow) {
		n = len(f.overflow)
	}
	out := make([]*work.WorkItem, n)
	copy(out, f.overflow[:n])
	rest := copy(f.overflow, f.overflow[n:])
	clear(f.overflow[rest:])
	f.overflow = f.overflow[:rest]
	for _, it := range out {
		if it.Request != nil && it.Request.Request() != nil {
			delete(f.ids, it.Request.Request().ID())
		}
	}
	return out
}

// overflowLen reports how many items wait in the overflow list.
func (f *executorFeeder) overflowLen() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.overflow)
}

// Dropped returns the total number of feedback items dropped past the overflow cap.
func (f *executorFeeder) Dropped() int64 {
	return f.dropped.Load()
}

// executorScopeExpander adapts *config.ScopeMatcher to modkit.ScopeExpander so
// modules (subdomain_harvest under --follow-subdomains) can add an exact
// discovered host to the scan's runtime scope allow-set.
type executorScopeExpander struct {
	matcher *config.ScopeMatcher
}

func (s *executorScopeExpander) AllowHost(host string) {
	if s.matcher != nil {
		s.matcher.AllowHost(host)
	}
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
	cache *InsertionPointCache
}

// GetAllInsertionPoints implements modkit.AllInsertionPointProvider.
func (p *executorIPProvider) GetAllInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	return p.cache.GetOrComputeAll(raw, requestID, includeNested)
}

func (p *executorIPProvider) GetInsertionPoints(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	// A nil cache is handled by GetOrCompute's nil receiver.
	return p.cache.GetOrCompute(raw, requestID, includeNested)
}

// repoRemarksAnnotator adapts *database.Repository to modkit.RemarksAnnotator.
type repoRemarksAnnotator struct {
	repo *database.Repository
}

func (u *repoRemarksAnnotator) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	return u.repo.AppendRemarks(ctx, annotations)
}

// repoTechnologyAnnotator adapts *database.Repository to
// modkit.TechnologyAnnotator.
type repoTechnologyAnnotator struct {
	repo *database.Repository
}

func (u *repoTechnologyAnnotator) SetRecordTechnology(ctx context.Context, technology map[string][]string) error {
	return u.repo.SetRecordTechnology(ctx, technology)
}

// repoRecordResponseRewriter adapts *database.Repository to
// modkit.RecordResponseRewriter (used by the passive js-beautify module to
// overwrite a record's minified JS body with its beautified form).
type repoRecordResponseRewriter struct {
	repo *database.Repository
}

// repoDerivedArtifactWriter stores immutable analysis companions without
// modifying the raw HTTP record.
type repoDerivedArtifactWriter struct {
	repo *database.Repository
}

func (w *repoDerivedArtifactWriter) StoreDerivedArtifact(ctx context.Context, artifact *modkit.DerivedArtifact) error {
	if artifact == nil {
		return nil
	}
	metadata, err := json.Marshal(artifact.Metadata)
	if err != nil {
		return err
	}
	return w.repo.SaveAnalysisArtifactForRecord(ctx, &database.AnalysisArtifact{
		HTTPRecordUUID: artifact.RecordUUID,
		Kind:           artifact.Kind,
		Filename:       artifact.Filename,
		MediaType:      artifact.MediaType,
		SHA256:         artifact.SHA256,
		Content:        append([]byte(nil), artifact.Content...),
		Metadata:       string(metadata),
	})
}

func (u *repoRecordResponseRewriter) RewriteRecordResponse(ctx context.Context, uuid string, rawResponse []byte) error {
	return u.repo.OverwriteRecordResponseBody(ctx, uuid, rawResponse)
}

// executorScopeChecker adapts *config.ScopeMatcher to modkit.ScopeChecker so
// modules can ask whether a host is within the scan's scope (i.e. the target).
type executorScopeChecker struct {
	matcher *config.ScopeMatcher
}

func (s *executorScopeChecker) IsHostInScope(host string) bool {
	return s.matcher.HostInScope(host)
}
