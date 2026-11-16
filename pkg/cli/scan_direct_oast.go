package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Out-of-band (OAST) checks on the scan-url / scan-request direct path.
//
// The Runner path builds its OAST service in buildInfrastructure; the direct
// path used to build none, so every blind check (SSRF, XXE, command injection,
// log4shell, ...) silently planted nothing. Now:
//
//   - --offline (or settings key offline): no OAST at all.
//   - --oast-url: fixed-URL mode, ready at once (no registration).
//   - otherwise, oast.enabled (default true): interactsh registration starts
//     before the request goes out and gets the Runner's bounded wait
//     (directOASTWait) right before the executor runs. A registration that
//     fails or is still pending is reported once on stderr and the row is
//     partial with oast_unavailable, as on the Runner path.
//
// The config is read through the same settings layers and the same
// runner.ApplyScanSettingOverrides as `vigolium scan` (directSettings), so
// --oast-url and oast.enabled mean the same thing on every path.

// directOASTWait bounds the wait for interactsh registration before the
// executor runs: the Runner's dynamic-assessment wait.
const directOASTWait = 3 * time.Second

// oastConfig returns the OAST config the direct path runs with, or nil when
// OAST is off: oast.enabled false, or --offline (flag or settings key
// offline), which keeps the run off every non-target network path — no
// interactsh registration and no fixed --oast-url payloads either, as on the
// Runner path (Runner.applyOffline). A settings load failure is returned: it
// means an explicit --config could not be read, which every other path treats
// as fatal too.
func (s *directScanSession) oastConfig() (*config.OASTConfig, error) {
	settings, err := s.loadSettings()
	if err != nil {
		return nil, err
	}
	if !settings.OAST.Enabled || runner.Offline(globalOffline, settings) {
		return nil, nil
	}
	cfg := settings.OAST
	return &cfg, nil
}

// startDirectOAST builds one input's OAST service (registration, if any,
// proceeds in the background). emit receives correlated callback findings; the
// service persists them to repo itself. nil when OAST is off.
func startDirectOAST(cfg *config.OASTConfig, emit func(*output.ResultEvent), repo *database.Repository, scanUUID, projectUUID string) *oast.Service {
	if cfg == nil {
		return nil
	}
	svc, err := oast.New(cfg, emit, repo, scanUUID, projectUUID, nil)
	if err != nil || svc == nil {
		return nil
	}
	return svc
}

// awaitDirectOAST waits (bounded) for svc to be able to mint callback URLs and
// wires it into the executor config. When it cannot, the service is closed,
// the gap is reported once on stderr, and the row is marked oast_unavailable;
// the scan runs without out-of-band checks. It returns the service to close
// after the run (nil when none was wired).
func awaitDirectOAST(ctx context.Context, sess *directScanSession, scanUUID string, svc *oast.Service, cfg *core.ExecutorConfig) *oast.Service {
	if svc == nil {
		return nil
	}
	err := svc.WaitReady(ctx, directOASTWait)
	if err == nil {
		cfg.OASTProvider = svc
		cfg.OASTService = svc
		return svc
	}
	// The public default server being unreachable is a caveat of this
	// machine's network, not lost coverage; a configured server that is down
	// is (see Runner.reportOASTUnavailable).
	caveatOnly := svc.UsesDefaultServer()
	svc.Close()
	if ctx.Err() != nil {
		return nil
	}
	if caveatOnly {
		sess.notePhaseCaveat(scanUUID, database.ReasonOASTUnavailable)
	} else {
		sess.notePhaseReason(scanUUID, database.ReasonOASTUnavailable)
	}
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "%s OAST unavailable (%s) — blind/out-of-band checks skipped\n",
			terminal.WarnPrefix(), oastUnavailableDetail(err))
	}
	return nil
}

// oastUnavailableDetail is the "<server>: <reason>" part of the notice.
func oastUnavailableDetail(err error) string {
	var uerr *oast.UnavailableError
	if errors.As(err, &uerr) {
		return uerr.Error()
	}
	return err.Error()
}

// withScanMaxDuration bounds the direct path's executor run by
// --scanning-max-duration (0: unbounded).
func withScanMaxDuration(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// noteDirectScanBudget marks the row partial with scan_budget when
// --scanning-max-duration ended the run (the executor returns no error for a
// deadline), and says so once on stderr.
func noteDirectScanBudget(sess *directScanSession, scanUUID string, maxDuration time.Duration) {
	sess.notePhaseReason(scanUUID, database.ReasonScanBudget)
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "%s --scanning-max-duration %s reached — the scan stopped early\n",
			terminal.WarnPrefix(), maxDuration)
	}
}
