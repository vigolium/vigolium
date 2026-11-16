package cli

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// --resume-scan refuses a scan whose process is still writing it
// (scan_running), and resumes one whose process is gone or that finished.
func TestRefuseResumeOfLiveScan(t *testing.T) {
	repo := newC2bTestRepo(t)
	ctx := context.Background()
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
	const host = "runner-host"
	seed := func(uuid, status string, pid int) {
		require.NoError(t, repo.CreateScan(ctx, &database.Scan{
			UUID: uuid, ProjectUUID: database.DefaultProjectUUID, Status: status,
			PID: pid, RunnerHost: host, StartedAt: time.Now(),
		}))
	}
	seed("live-scan", "running", 4242)
	seed("dead-scan", "running", 4343)
	seed("done-scan", "completed", 0)
	stubLiveness(t, time.Now(), host, func(pid int) bool { return pid == 4242 })

	err := refuseResumeOfLiveScan(ctx, repo, settings, "live-scan")
	var coded codedError
	require.True(t, errors.As(err, &coded), "a live scan must be refused, got %v", err)
	require.Equal(t, apicontract.CodeScanRunning, coded.Code())
	require.Equal(t, apicontract.CodeScanRunning, classifyErrorCode(err, classifyExitCode(err)))

	require.NoError(t, refuseResumeOfLiveScan(ctx, repo, settings, "dead-scan"), "a running row whose process is gone is resumable")
	require.NoError(t, refuseResumeOfLiveScan(ctx, repo, settings, "done-scan"))
	require.NoError(t, refuseResumeOfLiveScan(ctx, repo, settings, "no-such-scan"), "the runner owns scan_not_found")
	require.NoError(t, refuseResumeOfLiveScan(ctx, repo, settings, ""))
}

// The runner's resume refusals reach error.code as themselves, at exit 1.
func TestResumeErrorCodes(t *testing.T) {
	for _, code := range []apicontract.ErrorCode{apicontract.CodeScanNotFound, apicontract.CodeResumeMismatch} {
		err := fmt.Errorf("scan: %w", &runner.ResumeError{Kind: code, Message: "refused"})
		exit := classifyExitCode(err)
		require.Equal(t, ExitError, exit)
		require.Equal(t, code, classifyErrorCode(err, exit))
	}
}
