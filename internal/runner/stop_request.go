package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/database"
)

// SessionStopFilename is the stop sentinel a `scan stop` drops into
// {sessions_dir}/{scan_uuid}/ next to status.json. It is how a scan whose row
// lives in a scratch database (-S, --db-isolate) — where no other process can
// see or write the row — still learns it was asked to stop.
const SessionStopFilename = "stop"

// StopRequest is the content of a stop sentinel.
type StopRequest struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// SessionStopPath is where the stop sentinel for scanUUID lives.
func SessionStopPath(sessionsDir, scanUUID string) string {
	return filepath.Join(sessionsDir, scanUUID, SessionStopFilename)
}

// WriteStopSentinel drops the stop sentinel for scanUUID. The session
// directory must already exist (the heartbeat created it): a sentinel for a
// scan that never ran on this host would stop nothing.
func WriteStopSentinel(sessionsDir, scanUUID, by string) (string, error) {
	return WriteSentinel(filepath.Join(sessionsDir, scanUUID), SessionStopFilename, by)
}

// WriteSentinel writes a StopRequest from by as filename inside the existing
// directory dir (a scan's or agent run's session directory) and returns its
// path.
func WriteSentinel(dir, filename, by string) (string, error) {
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}
	data, err := json.Marshal(StopRequest{By: by, At: time.Now().UTC()})
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, filename)
	return path, atomicfile.WriteBytes(path, data)
}

// readStopSentinel returns the sentinel's request, nil when there is none. An
// unreadable or empty file still counts as a request: its presence is the
// signal, the content only names the asker.
func readStopSentinel(path string) *StopRequest {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return &StopRequest{By: "sentinel"}
		}
		return nil
	}
	var req StopRequest
	if json.Unmarshal(data, &req) != nil || strings.TrimSpace(req.By) == "" {
		req.By = "sentinel"
	}
	return &req
}

// pollStopRequest checks the two places a stop request can arrive — the scan
// row's stop_requested_at, which the beat's UPDATE returned as dbReq, and the
// session's stop sentinel — and hands the first one found to OnStopRequest,
// once.
func (h *Heartbeat) pollStopRequest(dbReq *StopRequest) {
	if h.cfg.OnStopRequest == nil || h.stopDelivered.Load() {
		return
	}
	req := dbReq
	if req == nil && h.cfg.SessionsDir != "" && h.cfg.ScanUUID != "" {
		req = readStopSentinel(SessionStopPath(h.cfg.SessionsDir, h.cfg.ScanUUID))
	}
	if req == nil || !h.stopDelivered.CompareAndSwap(false, true) {
		return
	}
	h.cfg.OnStopRequest(*req)
}

// removeStopSentinel deletes the sentinel once the scan has finished, so a
// later run that reuses the uuid (a resumed scan) does not stop at once.
func (h *Heartbeat) removeStopSentinel() {
	if h.cfg.SessionsDir == "" || h.cfg.ScanUUID == "" {
		return
	}
	_ = os.Remove(SessionStopPath(h.cfg.SessionsDir, h.cfg.ScanUUID))
}

// StopRequestedBy names who asked this run to stop ("" when nobody did).
func (r *Runner) StopRequestedBy() string {
	if v, ok := r.stopRequestedBy.Load().(string); ok {
		return v
	}
	return ""
}

// handleStopRequest ends the run on a stop request: the scan's stop reason
// becomes user_stopped (first reason wins, so this must precede the cancel
// the phases then report), and the run's context is cancelled exactly as a
// Ctrl-C would, so the finalizer stores whatever ran.
func (r *Runner) handleStopRequest(req StopRequest) {
	by := strings.TrimSpace(req.By)
	if by == "" {
		by = "unknown"
	}
	r.stopRequestedBy.Store(by)
	r.scanOutcome.setStopReason(database.ReasonUserStopped)
	if r.scanLogger != nil {
		r.scanLogger.Warn("", "stop requested by "+by+"; stopping the scan")
	}
	zap.L().Warn("Stop requested; stopping the scan", zap.String("by", by))
	if r.cancel != nil {
		r.cancel()
	}
}
