package oast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// Persisted out-of-band correlation.
//
// A blind payload's callback can arrive long after the scan that planted it:
// an admin renders a stored blind XSS next week, a queued job fetches a URL
// tonight. An in-memory tracker and a session deregistered at scan end would
// lose every such late callback.
//
// So every minted payload context is written to oast_payloads, a callback
// whose nonce is no longer in the tracker is looked up there, and — unless
// the scan is stateless or oast.keep_session is off — the interactsh
// registration is kept open at the end of the scan and stored in
// oast_sessions. `vigolium oast poll` and the
// server's periodic poller resume it (interactsh SessionInfo), collect what
// arrived, and file findings through the same classifier.

// lookupStoredPayload restores the payload context of a nonce the in-memory
// tracker no longer holds (evicted, or planted by an earlier process).
func (s *Service) lookupStoredPayload(nonce, callback string) (PayloadContext, bool) {
	if s.repo == nil || nonce == "" {
		return PayloadContext{}, false
	}
	// A payload still queued in this process is not in the store yet.
	s.flushPayloads()
	row, err := s.repo.GetOASTPayload(context.Background(), s.projectUUID, nonce)
	if err != nil || row == nil {
		if err != nil {
			zap.L().Debug("OAST: stored payload lookup failed", zap.Error(err))
		}
		return PayloadContext{}, false
	}
	return payloadContextFromRow(row, callback), true
}

// recordStoredPayload attaches the planted value to a persisted payload row:
// on the queued row, or — for a row already written — with the next buffer
// write (a stored-payload lookup flushes first, so it always sees the value).
func (s *Service) recordStoredPayload(nonce, payload string) {
	if s.repo == nil || nonce == "" {
		return
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	if p, ok := s.pendingPayloads[nonce]; ok {
		p.Payload = payload
		return
	}
	if s.pendingValues == nil {
		s.pendingValues = make(map[string]string)
	}
	s.pendingValues[nonce] = payload
	s.maybeWritePendingLocked()
}

// sessionInfoOf exports a registered client's session. interactsh only writes
// it to a file, so it goes through a private temp file removed at once.
func sessionInfoOf(c *interactshclient.Client) (*options.SessionInfo, error) {
	f, err := os.CreateTemp("", "vigolium-oast-session-*.yaml")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(path) }()
	if err := c.SaveSessionTo(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info options.SessionInfo
	if err := yaml.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// keepSession stops polling and stores the session instead of deregistering,
// so a later poll resumes it. Falls back to deregistering when the session
// cannot be stored: an orphaned registration nobody can poll helps no one.
func (s *Service) keepSessionOpen(c *interactshclient.Client) {
	if c.State.Load() == interactshclient.Polling {
		if err := c.StopPolling(); err != nil {
			zap.L().Debug("OAST: error stopping polling", zap.Error(err))
		}
	}
	info, err := sessionInfoOf(c)
	if err == nil {
		err = s.repo.SaveOASTSession(context.Background(), &database.OASTSession{
			ProjectUUID:   s.projectUUID,
			ScanUUID:      s.scanUUID,
			ServerURL:     info.ServerURL,
			CorrelationID: info.CorrelationID,
			SecretKey:     info.SecretKey,
			PrivateKey:    info.PrivateKey,
			PublicKey:     info.PublicKey,
			Token:         info.Token,
		})
	}
	if err != nil {
		zap.L().Warn("OAST: could not keep the session open; deregistering", zap.Error(err))
		closeClient(c)
		return
	}
	zap.L().Info("OAST: session kept open for late callbacks; collect them with `vigolium oast poll`",
		zap.String("scan_uuid", s.scanUUID))
}

// resumeClient is the session-resume seam; tests replace it.
var resumeClient = func(info *options.SessionInfo) (*interactshclient.Client, error) {
	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = pollTimeout
	httpOpts.RetryMax = 0
	httpOpts.KillIdleConn = true
	return interactshclient.New(&interactshclient.Options{
		ServerURL:           info.ServerURL,
		SessionInfo:         info,
		HTTPClient:          retryablehttp.NewClient(httpOpts),
		DisableHTTPFallback: !explicitCleartextServer(info.ServerURL),
	})
}

// PollResult is what one poll of a kept session collected.
type PollResult struct {
	SessionID    int64  `json:"session_id"`
	ScanUUID     string `json:"scan_uuid,omitempty"`
	Interactions int    `json:"interactions"`
	Correlated   int    `json:"correlated"`
	Closed       bool   `json:"closed,omitempty"`
	Error        string `json:"error,omitempty"`
}

// PollOptions tunes PollSessions.
type PollOptions struct {
	// Wait is how long each session is polled (interactsh polls on a ticker;
	// two ticks fit). Default 2s.
	Wait time.Duration
	// Close deregisters each session after polling and marks it closed.
	Close bool
	// Emit receives each correlated finding (also saved to the store).
	Emit func(*output.ResultEvent)
}

// pollParallelism bounds how many kept sessions PollSessions polls at once:
// each poll mostly waits out opts.Wait, so polling them one after another
// would take sessions × Wait.
const pollParallelism = 8

// PollSessions resumes each kept session, collects the callbacks that arrived
// since it was last polled, correlates them through oast_payloads and files
// findings, then leaves the session open (or closes it with opts.Close). A
// session the server no longer knows (evicted) is closed. Sessions are polled
// up to pollParallelism at a time; opts.Emit is never called concurrently.
// Results are in session order; a session not reached before ctx ended is
// left out.
func PollSessions(ctx context.Context, repo *database.Repository, sessions []*database.OASTSession, opts PollOptions) []PollResult {
	if opts.Wait <= 0 {
		opts.Wait = 2 * time.Second
	}
	if emit := opts.Emit; emit != nil {
		var mu sync.Mutex
		opts.Emit = func(ev *output.ResultEvent) {
			mu.Lock()
			defer mu.Unlock()
			emit(ev)
		}
	}
	results := make([]*PollResult, len(sessions))
	var g errgroup.Group
	g.SetLimit(pollParallelism)
	for i, row := range sessions {
		if ctx.Err() != nil {
			break
		}
		g.Go(func() error {
			if ctx.Err() == nil {
				res := pollSession(ctx, repo, row, opts)
				results[i] = &res
			}
			return nil
		})
	}
	_ = g.Wait()
	out := make([]PollResult, 0, len(sessions))
	for _, res := range results {
		if res != nil {
			out = append(out, *res)
		}
	}
	return out
}

func pollSession(ctx context.Context, repo *database.Repository, row *database.OASTSession, opts PollOptions) PollResult {
	res := PollResult{SessionID: row.ID, ScanUUID: row.ScanUUID}
	if row.SecretKey == "" || row.PrivateKey == "" {
		res.Error = "session has no key material"
		return res
	}
	client, err := resumeClient(&options.SessionInfo{
		ServerURL:     row.ServerURL,
		Token:         row.Token,
		PrivateKey:    row.PrivateKey,
		CorrelationID: row.CorrelationID,
		SecretKey:     row.SecretKey,
		PublicKey:     row.PublicKey,
	})
	if err != nil {
		res.Error = "resume: " + err.Error()
		return res
	}
	svc := &Service{repo: repo, scanUUID: row.ScanUUID, projectUUID: row.ProjectUUID, emitResult: opts.Emit}
	counted := &countingHandler{svc: svc}
	if err := client.StartPolling(opts.Wait/2+time.Millisecond, counted.handle); err != nil {
		res.Error = "poll: " + err.Error()
		return res
	}
	timer := time.NewTimer(opts.Wait)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
	}
	if err := client.StopPolling(); err != nil {
		zap.L().Debug("OAST: error stopping polling", zap.Error(err))
	}
	res.Interactions, res.Correlated = counted.counts()
	now := time.Now().UTC()
	_ = repo.MarkOASTSessionPolled(context.Background(), row.ID, now)
	if opts.Close {
		if err := client.Close(); err != nil && !errors.Is(err, context.Canceled) {
			zap.L().Debug("OAST: error closing resumed client", zap.Error(err))
		}
		if err := repo.CloseOASTSession(context.Background(), row.ID, now); err == nil {
			res.Closed = true
		}
	}
	return res
}

// countingHandler wraps handleInteraction with counts for the poll result.
// Atomic: the polling goroutine may still be finishing a batch when the
// counts are read.
type countingHandler struct {
	svc        *Service
	n, matched atomic.Int64
}

func (h *countingHandler) handle(i *server.Interaction) {
	if i == nil {
		return
	}
	h.n.Add(1)
	if h.svc.handleInteractionCorrelated(i) {
		h.matched.Add(1)
	}
}

func (h *countingHandler) counts() (int, int) { return int(h.n.Load()), int(h.matched.Load()) }

// String renders a poll result as one line.
func (r PollResult) String() string {
	s := fmt.Sprintf("session %d (scan %s): %d callback(s), %d correlated", r.SessionID, r.ScanUUID, r.Interactions, r.Correlated)
	if r.Closed {
		s += ", closed"
	}
	if r.Error != "" {
		s += ", error: " + r.Error
	}
	return s
}
