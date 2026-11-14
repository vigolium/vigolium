package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// SessionStatusFilename is the per-scan liveness file the heartbeat keeps in
// {sessions_dir}/{scan_uuid}/, next to runtime.log.
const SessionStatusFilename = "status.json"

// HeartbeatInterval is how often a running scan refreshes its liveness record
// (status.json and the scan row's heartbeat columns). Phase transitions write
// immediately on top of it.
//
// Ten seconds keeps the write cost negligible (one tiny file rename and one
// single-row UPDATE) while sitting far inside the two-minute staleness window
// readers apply, so a live scan can miss several beats under DB contention
// before anyone calls it abandoned.
const HeartbeatInterval = 10 * time.Second

// heartbeatWriteBudget bounds each heartbeat's database write. A beat that
// cannot land in this long is skipped, not queued: the next one carries newer
// numbers anyway.
const heartbeatWriteBudget = 5 * time.Second

// Session status values written to status.json. "running" while the heartbeat
// is live; one of the terminal values once the scan has finalized.
const (
	SessionRunning   = "running"
	SessionCompleted = "completed"
	SessionFailed    = "failed"
	SessionCancelled = "cancelled"
)

// SessionProgress is the running phase's work-item progress, the same figures
// phase.progress carries: Total is a non-decreasing upper bound and is nil
// until one is known.
type SessionProgress struct {
	Done  int64  `json:"done"`
	Total *int64 `json:"total,omitempty"`
	Unit  string `json:"unit,omitempty"`
}

// SessionStatus is the document a running scan keeps in status.json.
//
// It exists because the scan row cannot always answer "is this scan alive, and
// how far along is it": under -S and --db-isolate the row lives in a scratch
// database nobody else can see until the run ends, and the row has no place for
// work-item progress at all. The file is on the local filesystem of the host
// that runs the scan, written atomically (a reader sees the previous complete
// document or the next one, never a torn write), and small enough to rewrite
// every beat.
type SessionStatus struct {
	ScanUUID    string `json:"scan_uuid"`
	PID         int    `json:"pid"`
	Host        string `json:"host"`
	DBPath      string `json:"db_path,omitempty"`
	ProjectUUID string `json:"project_uuid,omitempty"`
	// Status is "running" while the heartbeat runs, then the terminal status.
	Status string `json:"status"`

	Phase          string     `json:"phase,omitempty"`
	PhaseStartedAt *time.Time `json:"phase_started_at,omitempty"`
	PhasesPlanned  []string   `json:"phases_planned,omitempty"`
	PhasesDone     []string   `json:"phases_done"`

	RequestsSent       int64            `json:"requests_sent"`
	Findings           int64            `json:"findings"`
	FindingsBySeverity map[string]int64 `json:"findings_by_severity,omitempty"`
	Progress           *SessionProgress `json:"progress,omitempty"`

	StartedAt   time.Time `json:"started_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	// ScanMaxDurationMS is the --scanning-max-duration budget, 0 when unset —
	// the one bound a reader can turn into an honest ETA ceiling.
	ScanMaxDurationMS int64 `json:"scan_max_duration_ms,omitempty"`
}

// SessionStatusPath is where the heartbeat writes scanUUID's status.json.
func SessionStatusPath(sessionsDir, scanUUID string) string {
	return filepath.Join(sessionsDir, scanUUID, SessionStatusFilename)
}

// ReadSessionStatus parses a status.json. A missing file is (nil, nil): most
// readers treat "no heartbeat file" as one absent signal among several.
func ReadSessionStatus(path string) (*SessionStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st SessionStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &st, nil
}

// HeartbeatConfig wires a Heartbeat to the scan it reports on.
type HeartbeatConfig struct {
	// Repo receives the scans-row heartbeat; nil writes the file only.
	Repo     *database.Repository
	ScanUUID string
	// SessionsDir is the native sessions root; "" writes the row only.
	SessionsDir string
	ProjectUUID string
	DBPath      string
	// Phase is the initial phase, for a caller with a single fixed phase.
	Phase           string
	PhasesPlanned   []string
	ScanMaxDuration time.Duration

	// Requests reports requests sent so far by sources the heartbeat does not
	// track itself; nil reports none (and leaves total_requests unwritten).
	Requests func() int64
	// Progress reports the running phase's work-item progress; nil for none.
	Progress func() *SessionProgress
	// StopWhenRowDone ends the heartbeat by itself once its scan row is no
	// longer running (someone else finalized it), recording the row's
	// terminal status in status.json. For callers that finalize the row
	// without a handle on the heartbeat (the direct scan-url path).
	StopWhenRowDone bool

	// Interval and Now are for tests; zero values mean HeartbeatInterval and
	// time.Now.
	Interval time.Duration
	Now      func() time.Time
}

// Heartbeat keeps one scan's liveness record fresh: status.json every interval
// and on every phase transition, and the scans row's heartbeat columns
// alongside it. Always on — it is not tied to --events or persist_logs — so
// `scan status`, `scan wait` and `log ls` can tell a live scan from one whose
// process died, which a status column alone never could.
//
// Every method is nil-safe, so callers need no guard when a scan runs without
// one.
type Heartbeat struct {
	cfg      HeartbeatConfig
	path     string
	interval time.Duration
	now      func() time.Time

	// writeMu serializes beats, so the file and row are only ever written by
	// one goroutine at a time and in order.
	writeMu sync.Mutex

	mu sync.Mutex
	st SessionStatus
	// extraSent is what finished phases contributed through counters the
	// Requests func stops seeing once their phase ends.
	extraSent int64

	kick     chan struct{}
	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// StartHeartbeat writes the first beat synchronously, so a reader that looks
// the moment the scan starts already finds it, then keeps beating until Stop
// or Finish.
func StartHeartbeat(cfg HeartbeatConfig) *Heartbeat {
	h := &Heartbeat{
		cfg:      cfg,
		interval: cfg.Interval,
		now:      cfg.Now,
		kick:     make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	if h.interval <= 0 {
		h.interval = HeartbeatInterval
	}
	if h.now == nil {
		h.now = time.Now
	}
	if cfg.SessionsDir != "" && cfg.ScanUUID != "" {
		h.path = SessionStatusPath(cfg.SessionsDir, cfg.ScanUUID)
	}
	host, _ := os.Hostname()
	now := h.now()
	h.st = SessionStatus{
		ScanUUID:          cfg.ScanUUID,
		PID:               os.Getpid(),
		Host:              host,
		DBPath:            cfg.DBPath,
		ProjectUUID:       cfg.ProjectUUID,
		Status:            SessionRunning,
		PhasesPlanned:     cfg.PhasesPlanned,
		PhasesDone:        []string{},
		StartedAt:         now,
		ScanMaxDurationMS: cfg.ScanMaxDuration.Milliseconds(),
	}
	if cfg.Phase != "" {
		h.st.Phase = cfg.Phase
		h.st.PhaseStartedAt = &now
	}
	if h.path != "" {
		if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
			zap.L().Debug("heartbeat: cannot create session directory; status.json disabled", zap.String("path", h.path), zap.Error(err))
			h.path = ""
		}
	}
	h.beat(context.Background(), false)
	go h.loop()
	return h
}

func (h *Heartbeat) loop() {
	defer close(h.done)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-h.kick:
		case <-h.stopCh:
			return
		}
		if rowDone := h.beat(context.Background(), false); rowDone && h.cfg.StopWhenRowDone {
			h.adoptRowStatus()
			return
		}
	}
}

// poke asks the loop for an immediate beat without blocking the caller (a
// phase transition); a beat already pending covers it.
func (h *Heartbeat) poke() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// PhaseStarted records the phase now running and beats.
func (h *Heartbeat) PhaseStarted(phase string) {
	if h == nil {
		return
	}
	now := h.now()
	h.mu.Lock()
	h.st.Phase = phase
	h.st.PhaseStartedAt = &now
	h.st.Progress = nil
	h.mu.Unlock()
	h.poke()
}

// PhaseEnded records phase as done. extraSent is what the phase sent through
// counters the Requests func reads only while the phase is current, folded in
// here so the scan-wide figure does not drop when the phase ends.
func (h *Heartbeat) PhaseEnded(phase string, extraSent int64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.extraSent += extraSent
	h.st.PhasesDone = append(h.st.PhasesDone, phase)
	if h.st.Phase == phase {
		h.st.Phase = ""
		h.st.PhaseStartedAt = nil
		h.st.Progress = nil
	}
	h.mu.Unlock()
	h.poke()
}

// RecordFinding counts one finding at severity (lowercase name).
func (h *Heartbeat) RecordFinding(severity string) {
	if h == nil {
		return
	}
	severity = strings.ToLower(strings.TrimSpace(severity))
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Findings++
	if severity == "" {
		return
	}
	if h.st.FindingsBySeverity == nil {
		h.st.FindingsBySeverity = make(map[string]int64)
	}
	h.st.FindingsBySeverity[severity]++
}

// snapshot refreshes the live counters and returns a copy of the document.
func (h *Heartbeat) snapshot() SessionStatus {
	var sent int64
	if h.cfg.Requests != nil {
		sent = h.cfg.Requests()
	}
	var progress *SessionProgress
	if h.cfg.Progress != nil {
		progress = h.cfg.Progress()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.RequestsSent = sent + h.extraSent
	if h.st.Phase != "" && progress != nil {
		h.st.Progress = progress
	}
	h.st.HeartbeatAt = h.now()
	st := h.st
	st.PhasesDone = append([]string{}, h.st.PhasesDone...)
	if h.st.FindingsBySeverity != nil {
		st.FindingsBySeverity = make(map[string]int64, len(h.st.FindingsBySeverity))
		for k, v := range h.st.FindingsBySeverity {
			st.FindingsBySeverity[k] = v
		}
	}
	return st
}

// beat writes one liveness record: the file always, the row unless fileOnly.
// rowDone reports that the row is no longer running, so the beat touched
// nothing (see UpdateScanHeartbeat).
func (h *Heartbeat) beat(ctx context.Context, fileOnly bool) (rowDone bool) {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	st := h.snapshot()
	h.writeFile(st)
	if fileOnly || h.cfg.Repo == nil || h.cfg.ScanUUID == "" {
		return false
	}
	hb := database.ScanHeartbeat{
		At:    st.HeartbeatAt,
		Phase: st.Phase,
		PID:   st.PID,
		Host:  st.Host,
	}
	if h.cfg.Requests != nil {
		n := st.RequestsSent
		hb.RequestsSent = &n
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), heartbeatWriteBudget)
	defer cancel()
	updated, err := h.cfg.Repo.UpdateScanHeartbeat(writeCtx, h.cfg.ScanUUID, hb)
	if err != nil {
		zap.L().Debug("heartbeat: scan row update failed", zap.String("scan_uuid", h.cfg.ScanUUID), zap.Error(err))
		return false
	}
	return !updated
}

// adoptRowStatus records the finalized row's status in status.json, for a
// heartbeat that stopped because someone else finalized its row.
func (h *Heartbeat) adoptRowStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatWriteBudget)
	defer cancel()
	row, err := h.cfg.Repo.GetScanByUUID(ctx, h.cfg.ScanUUID)
	if err != nil || row == nil {
		return
	}
	status := row.Status
	if status == SessionFailed && row.ErrorMessage == "cancelled" {
		status = SessionCancelled
	}
	h.mu.Lock()
	h.st.Status = status
	h.st.Phase, h.st.PhaseStartedAt, h.st.Progress = "", nil, nil
	h.mu.Unlock()
	h.beat(ctx, true)
}

func (h *Heartbeat) writeFile(st SessionStatus) {
	if h.path == "" {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := atomicfile.WriteBytes(h.path, data); err != nil {
		zap.L().Debug("heartbeat: status.json write failed", zap.String("path", h.path), zap.Error(err))
	}
}

// Stop ends the periodic beats and writes the final row heartbeat, which
// carries the scan's final total_requests. Call it before the scan row is
// finalized. Idempotent.
func (h *Heartbeat) Stop(ctx context.Context) {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() {
		close(h.stopCh)
		<-h.done
		h.mu.Lock()
		h.st.Phase = ""
		h.st.PhaseStartedAt = nil
		h.st.Progress = nil
		h.mu.Unlock()
		if rowDone := h.beat(ctx, false); rowDone && h.cfg.StopWhenRowDone {
			h.adoptRowStatus()
		}
	})
}

// Finish stops the heartbeat (if Stop has not) and records the terminal status
// in status.json. Call it after the scan row is finalized, so the file never
// claims an end the row does not yet show.
func (h *Heartbeat) Finish(status string) {
	if h == nil {
		return
	}
	h.Stop(context.Background())
	h.mu.Lock()
	h.st.Status = status
	h.mu.Unlock()
	h.beat(context.Background(), true)
}

// sessionsDirFor is the native sessions root from settings, "" without them.
func sessionsDirFor(settings *config.Settings) string {
	if settings == nil {
		return ""
	}
	return paths.StateDir("native-sessions", settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir())
}

// sqliteDBPathFor names the database file a scan writes, "" for a non-SQLite
// store (the path is a reader's hint, not an identity).
func sqliteDBPathFor(settings *config.Settings) string {
	if settings == nil || settings.Database.Driver != "sqlite" {
		return ""
	}
	return config.ExpandPath(settings.Database.SQLite.Path)
}

// startLiveness starts the scan's heartbeat for the plan the run will execute.
// Requests is the shared requester's count plus the running phase's extra
// counters (deparos, a phase-local requester, the browser's own traffic);
// finished phases' extras are folded in by PhaseEnded.
func (r *Runner) startLiveness(infra *phaseInfra, plan NativeScanPlan) *Heartbeat {
	planned := []string{}
	for _, step := range plan.Steps {
		if step.Enabled {
			planned = append(planned, string(step.Phase))
		}
	}
	requester := infra.httpRequester
	h := StartHeartbeat(HeartbeatConfig{
		Repo:            r.repository,
		ScanUUID:        infra.scanUUID,
		SessionsDir:     sessionsDirFor(r.settings),
		ProjectUUID:     r.options.ProjectUUID,
		DBPath:          sqliteDBPathFor(r.settings),
		PhasesPlanned:   planned,
		ScanMaxDuration: r.options.ScanMaxDuration,
		Requests: func() int64 {
			var n int64
			if requester != nil {
				n = requester.RequestsSent()
			}
			return n + r.currentPhase.Load().extraSentSoFar()
		},
		Progress: func() *SessionProgress {
			return r.currentPhase.Load().progressSnapshot()
		},
	})
	r.liveness.Store(h)
	return h
}

// terminalSessionStatus is the status.json terminal value for a run that
// returned err, by the same precedence the scan-row finalizer uses.
func (r *Runner) terminalSessionStatus(err error) string {
	switch {
	case err != nil:
		return SessionFailed
	case r.ctx != nil && r.ctx.Err() != nil:
		return SessionCancelled
	default:
		return SessionCompleted
	}
}
