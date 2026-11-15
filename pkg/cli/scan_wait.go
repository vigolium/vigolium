package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	scanWaitTimeout       time.Duration
	scanWaitPoll          time.Duration
	scanWaitFailOnPartial bool
	scanWaitEvents        string
)

// scanWaitNotFoundGrace is how long `scan wait` tolerates a UUID that is not
// (yet) known. A driver that launches a scan in the background and waits on its
// --scan-uuid straight away can get here before the runner has written its row
// or first heartbeat; a typo'd UUID still fails within seconds rather than
// sitting out the whole --timeout.
const scanWaitNotFoundGrace = 30 * time.Second

// scanWaitQuietReprint is how often an unchanged progress line is repeated on
// stderr, so a long quiet phase still shows the wait is alive.
const scanWaitQuietReprint = 30 * time.Second

var scanWaitCmd = &cobra.Command{
	Use:   "wait <scan-uuid>",
	Short: "Block until a scan finishes, then print its summary and exit with its outcome",
	Long: `Poll a scan's status (the same view as 'vigolium scan status') until it
reaches a terminal state, printing progress to stderr, then print the finished
scan on stdout and exit with the scan's outcome. Under -j that is the scan
document — the same envelope 'vigolium scan -j' prints (kind "scan", findings
as items, status, completeness, phase_outcomes, the stored plan), rebuilt from
the scan's row — so a driver that waited parses what one that ran the scan
would; -n/--limit, --fields and --compact shape it the same way.

  0  completed
  1  failed or cancelled (error.code failed); the scan's process died while the
     row still said running (error.code scan_abandoned); --timeout elapsed
     first (error.code wait_timeout)
  4  --fail-on <severity> matched a finding of the finished scan
  5  --fail-on-partial and the scan completed with partial coverage
     (error.code partial)

Reads through the read-only database pool, so polling never contends for the
write lock the running scan needs. --events ndjson streams the progress as
phase.progress lines on stdout instead, ending with scan.finished (or an error
line carrying error_kind wait_timeout / scan_abandoned).`,
	Example: FormatExamples(
		"# Start a scan in the background, then block on it (agent pattern)",
		"vigolium scan -t https://app.example --scan-uuid $ID >/dev/null 2>&1 &",
		"vigolium scan wait $ID --timeout 45m -j",
		"# Gate CI on the finished scan",
		"vigolium scan wait $ID --fail-on high --fail-on-partial",
		"# Progress as NDJSON for a driver",
		"vigolium scan wait $ID --events ndjson",
	),
	Args: cobra.ExactArgs(1),
	RunE: runScanWait,
}

func init() {
	scanCmd.AddCommand(scanWaitCmd)
	f := scanWaitCmd.Flags()
	f.DurationVar(&scanWaitTimeout, "timeout", 30*time.Minute, "Give up after this long (exit 1, error.code wait_timeout); 0 waits indefinitely")
	f.DurationVar(&scanWaitPoll, "poll", 2*time.Second, "How often to re-read the scan's status")
	f.StringVar(&scanFailOn, "fail-on", "", failOnUsage("evaluated on the finished scan (exit 4); --soft-fail overrides."))
	f.BoolVar(&scanWaitFailOnPartial, "fail-on-partial", false, "Exit 5 (error.code partial) when the scan completed with partial coverage")
	f.StringVar(&scanWaitEvents, "events", "", "Stream progress as NDJSON on stdout (value: ndjson): phase.progress lines, then scan.finished")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a standalone .sqlite) with project scoping off")
	registerScanDocumentFlags(f)
}

// waitClock is the time source of the wait loop; tests substitute a fake.
type waitClock interface {
	Now() time.Time
	// Sleep waits d or until ctx ends, returning ctx's error in that case.
	Sleep(ctx context.Context, d time.Duration) error
}

type realWaitClock struct{}

func (realWaitClock) Now() time.Time { return time.Now() }

func (realWaitClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scanWaiter is the polling loop, separated from the command so it can run on
// a fake clock against a scripted probe.
type scanWaiter struct {
	uuid    string
	probe   func(ctx context.Context) (*scanStatusView, error)
	clock   waitClock
	timeout time.Duration
	poll    time.Duration
	// notFoundGrace bounds how long an unknown UUID is tolerated.
	notFoundGrace time.Duration
	// onProgress is called with every non-terminal view.
	onProgress func(*scanStatusView)
}

// wait polls until the scan is terminal (the view, nil), abandoned
// (scan_abandoned), the timeout elapses (wait_timeout), or ctx ends.
func (w *scanWaiter) wait(ctx context.Context) (*scanStatusView, error) {
	start := w.clock.Now()
	var last *scanStatusView
	done, err := pollUntil(ctx, w.clock, w.timeout, w.poll, func(ctx context.Context) (bool, error) {
		v, err := w.probe(ctx)
		switch {
		case err == nil:
			last = v
			if isTerminalEffectiveStatus(v.EffectiveStatus) {
				return true, nil
			}
			if v.EffectiveStatus == effStatusAbandoned {
				return false, codedErrorf(apicontract.CodeScanAbandoned,
					"scan %s is abandoned: its row says running but nothing has written since %s%s",
					w.uuid, lastWriteLabel(v), processGoneSuffix(v))
			}
			if w.onProgress != nil {
				w.onProgress(v)
			}
		case database.IsBusy(err):
			// The scan is holding the lock; try again next poll.
		case isNotFoundError(err) && w.clock.Now().Sub(start) < w.notFoundGrace:
			// Not written yet; see scanWaitNotFoundGrace.
		default:
			last = nil
			return false, err
		}
		return false, nil
	})
	switch {
	case err != nil:
		return last, err
	case !done:
		return last, codedErrorf(apicontract.CodeWaitTimeout,
			"scan %s did not finish within --timeout %s%s", w.uuid, w.timeout, lastStateSuffix(last))
	}
	return last, nil
}

// pollUntil calls probe every `every` until it reports done (true, nil),
// returns an error, timeout elapses (false, nil; 0 waits indefinitely), or
// ctx ends (false, ctx's error). The last sleep is cut short to end at the
// timeout.
func pollUntil(ctx context.Context, clock waitClock, timeout, every time.Duration, probe func(context.Context) (bool, error)) (bool, error) {
	start := clock.Now()
	for {
		if done, err := probe(ctx); done || err != nil {
			return done, err
		}
		elapsed := clock.Now().Sub(start)
		if timeout > 0 && elapsed >= timeout {
			return false, nil
		}
		sleep := every
		if timeout > 0 && timeout-elapsed < sleep {
			sleep = timeout - elapsed
		}
		if err := clock.Sleep(ctx, sleep); err != nil {
			return false, err
		}
	}
}

func isNotFoundError(err error) bool {
	var coded codedError
	return errors.As(err, &coded) && coded.Code() == apicontract.CodeNotFound
}

func lastWriteLabel(v *scanStatusView) string {
	if v == nil || v.Liveness.LastWriteAt == nil {
		return "it started (no liveness signal at all)"
	}
	return *v.Liveness.LastWriteAt
}

func processGoneSuffix(v *scanStatusView) string {
	if v != nil && v.Liveness.ProcessGone != nil && *v.Liveness.ProcessGone {
		return fmt.Sprintf(", and its process (pid %d on this host) has exited", v.PID)
	}
	return ""
}

func lastStateSuffix(v *scanStatusView) string {
	if v == nil {
		return " (the scan was never found)"
	}
	s := " (last seen " + v.EffectiveStatus
	if v.Phase != "" {
		s += " in " + v.Phase
	}
	return s + ")"
}

// scanWaitExit maps a finished scan to the command's result: nil (exit 0), a
// coded failure (exit 1), the --fail-on gate (exit 4) or, behind
// --fail-on-partial, the incomplete result (exit 5). gate evaluates --fail-on
// and returns its error, nil when it did not trip.
func scanWaitExit(v *scanStatusView, gate func() error, failOnPartial bool) error {
	switch v.EffectiveStatus {
	case effStatusFailed:
		msg := v.ErrorMessage
		if msg == "" {
			msg = "no error message recorded"
		}
		return codedErrorf(apicontract.CodeFailed, "scan %s failed: %s", v.ScanUUID, msg)
	case effStatusCancelled:
		return codedErrorf(apicontract.CodeFailed, "scan %s was cancelled", v.ScanUUID)
	}
	if gate != nil {
		if err := gate(); err != nil {
			return err
		}
	}
	if failOnPartial && v.Completeness == database.CompletenessPartial {
		reason := v.StopReason
		if reason == "" {
			reason = "partial coverage"
		}
		return incompleteErrorf(apicontract.CodePartial, "scan %s completed with partial coverage (%s)", v.ScanUUID, reason)
	}
	return nil
}

func runScanWait(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	uuid := strings.TrimSpace(args[0])
	if uuid == "" {
		return usageErrorf("scan wait needs a scan UUID")
	}
	if scanWaitPoll <= 0 {
		return usageErrorf("--poll must be positive (got %s)", scanWaitPoll)
	}
	if scanWaitTimeout < 0 {
		return usageErrorf("--timeout must not be negative (got %s)", scanWaitTimeout)
	}
	if err := resetFailOnGate(); err != nil {
		return err
	}
	if err := validateScanDocumentFlags(); err != nil {
		return err
	}
	format, err := scanevents.ParseFormat(scanWaitEvents)
	if err != nil {
		return asUsageError(err)
	}
	streaming := format != ""
	if streaming && globalJSON {
		return usageErrorf("--events and -j both write stdout; pick one")
	}

	reader, err := newScanStatusReader()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var progress func(*scanStatusView)
	if streaming {
		scanevents.Install(scanevents.NewStdout(uuid))
		progress = newWaitEventProgress()
	} else if !globalSilent {
		progress = newWaitStderrProgress(os.Stderr, realWaitClock{})
	}

	w := &scanWaiter{
		uuid:          uuid,
		probe:         func(ctx context.Context) (*scanStatusView, error) { return reader.read(ctx, uuid) },
		clock:         realWaitClock{},
		timeout:       scanWaitTimeout,
		poll:          scanWaitPoll,
		notFoundGrace: scanWaitNotFoundGrace,
		onProgress:    progress,
	}
	view, waitErr := w.wait(ctx)
	if waitErr != nil {
		if streaming {
			emitWaitStreamError(waitErr)
		}
		if ctx.Err() != nil {
			// Interrupted by the operator: the scan itself is untouched.
			return fmt.Errorf("scan wait interrupted%s", lastStateSuffix(view))
		}
		return waitErr
	}

	switch {
	case streaming:
		emitWaitStreamFinished(view)
	case globalJSON:
		if err := scanWaitDocument(reader, view).Emit(); err != nil {
			return err
		}
	default:
		printScanStatusHuman(os.Stdout, view)
	}

	gate := func() error {
		if scanFailOn == "" {
			return nil
		}
		if reader.repo != nil && slices.Contains(view.Source, "db") {
			evaluateFailOnGate(reader.repo, view.ProjectUUID, uuid, globalSilent || streaming)
		} else {
			failOnGateFromCounts(view.FindingsBySeverity, globalSilent || streaming)
		}
		return failOnGateError()
	}
	return scanWaitExit(view, gate, scanWaitFailOnPartial)
}

// scanWaitDocument builds the scan document for the finished scan v: from its
// row when the store being read has it (AddStored, the same reads `scan -j`
// makes), else from the status.json facts alone (AddStatusOnly: a -S or
// --db-isolate scan whose row went with its scratch store).
func scanWaitDocument(reader *scanStatusReader, v *scanStatusView) *scanDocBuilder {
	b := newScanDocBuilder("scan wait")
	if reader != nil && reader.repo != nil && slices.Contains(v.Source, "db") {
		ctx, cancel := docReadContext()
		defer cancel()
		if row, err := reader.repo.GetScanByUUID(ctx, v.ScanUUID); err == nil && row != nil {
			b.AddStored(ctx, reader.repo, row, v.EffectiveStatus, reader.dbPath)
			return b
		}
	}
	b.AddStatusOnly(v)
	return b
}

// failOnGateFromCounts trips --fail-on from a severity tally, for a scan whose
// findings are not in the store being read (status.json only).
func failOnGateFromCounts(bySev map[string]int, silent bool) {
	threshold := severityRank(scanFailOn)
	if threshold == 0 {
		return
	}
	n := 0
	for sev, count := range bySev {
		if severityRank(sev) >= threshold {
			n += count
		}
	}
	if n > 0 {
		markFailOnTriggered(n, silent)
	}
}

// waitProgressLine renders one stderr progress line for a running scan.
func waitProgressLine(v *scanStatusView) string {
	line := waitProgressKey(v)
	if eta := formatETA(v.ETA); eta != "unknown" {
		line += " · eta " + eta
	}
	return line
}

// waitProgressKey is the progress line without the ETA, which moves on every
// poll: what decides whether anything worth repeating changed.
func waitProgressKey(v *scanStatusView) string {
	short := v.ScanUUID
	if len(short) > 8 {
		short = short[:8]
	}
	parts := []string{"scan " + short, v.EffectiveStatus}
	if v.Phase != "" {
		parts = append(parts, v.Phase)
	}
	if p := v.Progress; p != nil {
		total := "?"
		if p.Total != nil {
			total = fmt.Sprintf("%d", *p.Total)
		}
		parts = append(parts, fmt.Sprintf("%d/%s %s", p.Done, total, p.Unit))
	}
	parts = append(parts, fmt.Sprintf("%d req", v.RequestsSent), fmt.Sprintf("%d findings", v.Findings))
	return strings.Join(parts, " · ")
}

// newWaitStderrProgress prints a progress line when it changes, and repeats an
// unchanged one every scanWaitQuietReprint so a quiet phase still shows life.
func newWaitStderrProgress(out io.Writer, clock waitClock) func(*scanStatusView) {
	var lastKey string
	var lastAt time.Time
	return func(v *scanStatusView) {
		key := waitProgressKey(v)
		now := clock.Now()
		if key == lastKey && now.Sub(lastAt) < scanWaitQuietReprint {
			return
		}
		lastKey, lastAt = key, now
		_, _ = fmt.Fprintf(out, "%s %s\n", terminal.InfoSymbol(), terminal.Gray(waitProgressLine(v)))
	}
}

// newWaitEventProgress re-emits progress as phase.progress lines, one per poll
// that changed something a driver would chart.
func newWaitEventProgress() func(*scanStatusView) {
	var last string
	return func(v *scanStatusView) {
		ev := scanevents.Event{
			Type:         scanevents.TypePhaseProgress,
			Phase:        v.Phase,
			RequestsSent: scanevents.Int64(v.RequestsSent),
			Findings:     scanevents.Int64(int64(v.Findings)),
		}
		if p := v.Progress; p != nil {
			ev.Done = scanevents.Int64(p.Done)
			ev.Total = p.Total
			ev.Unit = p.Unit
		}
		key := waitProgressKey(v)
		if key == last {
			return
		}
		last = key
		scanevents.Emit(ev)
	}
}

// emitWaitStreamFinished closes the --events stream with the scan's terminal
// line, in the vocabulary `scan --events` uses.
func emitWaitStreamFinished(v *scanStatusView) {
	status := scanevents.StatusCompleted
	switch v.EffectiveStatus {
	case effStatusFailed:
		status = scanevents.StatusFailed
	case effStatusCancelled:
		status = scanevents.StatusInterrupted
	default:
		if v.Completeness == database.CompletenessPartial {
			status = scanevents.StatusCurtailed
		}
	}
	ev := scanevents.Event{
		Type:         scanevents.TypeScanFinished,
		Status:       status,
		DurationMS:   v.DurationMS,
		RequestsSent: scanevents.Int64(v.RequestsSent),
		StopReason:   v.StopReason,
	}
	if len(v.FindingsBySeverity) > 0 {
		ev.FindingsBySeverity = v.FindingsBySeverity
	}
	if v.EffectiveStatus == effStatusFailed && v.ErrorMessage != "" {
		ev.Message = v.ErrorMessage
	}
	scanevents.Finish(ev)
}

// emitWaitStreamError ends a --events stream whose wait did not see the scan
// finish: an error line naming why (error_kind is the error.code), not a
// scan.finished, which would claim an end nobody observed.
func emitWaitStreamError(err error) {
	ev := scanevents.Event{Type: scanevents.TypeError, Message: err.Error()}
	var coded codedError
	if errors.As(err, &coded) {
		ev.ErrorKind = string(coded.Code())
	}
	scanevents.Emit(ev)
	scanevents.Default().Close()
}
