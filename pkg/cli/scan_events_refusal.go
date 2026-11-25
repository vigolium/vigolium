package cli

import (
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/scanevents"
)

// scanEventsAnnotation marks the --events flag of the scan commands (registerEventsFlag),
// as opposed to the same-named flag of `scan wait` and `server`, which stream
// other things.
const scanEventsAnnotation = "vigolium/scan-events"

// processStart is when this process began, for the duration of a refusal.
var processStart = time.Now()

// emitRefusalTerminalEvent writes the one scan.finished an invocation owes its
// --events stream when it ended before the stream began: a usage error, an
// unknown flag, a config refusal, a preflight failure. beginScanEventStream
// installs the emitter only once the scan uuid and the database exist, so
// every exit before that point otherwise left stdout empty and the cause on
// stderr alone, which a consumer cannot tell from a SIGKILL.
//
// The line carries status failed, the exit code the process ends with (before
// --soft-fail, as on every other terminal event), the stable error code and
// the totals known at that point: zero records written. It is written only
// when no terminal event has been written already, and never under -j, whose
// error envelope owns stdout (the two together are refused as a usage error).
//
// code is Execute's classified exit code, which folds in the
// required-flag case classifyExitCode does not see.
func emitRefusalTerminalEvent(cmd *cobra.Command, err error, code int, args []string) {
	if err == nil || globalJSON || !isScanEventsCommand(cmd) {
		return
	}
	if scanevents.Default().Terminated() {
		return
	}
	recoveredEvents, recoveredUUID := recoverScanStreamFlags(args)
	format, perr := scanevents.ParseFormat(strings.TrimSpace(firstNonEmptyString(scanOpts.Events, recoveredEvents)))
	if perr != nil || format == "" {
		// No stream was asked for, or the value is what was refused: there is
		// no stream to write to.
		return
	}
	emitter := scanevents.Default()
	if !emitter.Enabled() {
		emitter = scanevents.NewStdout(strings.TrimSpace(firstNonEmptyString(scanOpts.ScanUUID, globalScanUUID, recoveredUUID)))
	}
	emitter.Finish(refusalTerminalEvent(err, code, time.Since(processStart)))
}

// refusalTerminalEvent is the scan.finished of an invocation that never
// started its scan.
func refusalTerminalEvent(err error, code int, elapsed time.Duration) scanevents.Event {
	return scanevents.Event{
		Status:         scanevents.StatusFailed,
		Message:        err.Error(),
		DurationMS:     elapsed.Milliseconds(),
		RecordsWritten: scanevents.Int64(0),
		ExitCode:       scanevents.Int(code),
		ErrorCode:      string(classifyErrorCode(err, code)),
	}
}

// isScanEventsCommand reports whether cmd carries the scan --events flag.
func isScanEventsCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	f := cmd.Flags().Lookup("events")
	if f == nil {
		return false
	}
	_, ok := f.Annotations[scanEventsAnnotation]
	return ok
}

// recoverScanStreamFlags reads --events and --scan-uuid back out of argv after
// a failed parse, when cobra never bound them, the same way
// resolvePresentationMode recovers the presentation flags: a real pflag
// flagset that knows only these two flags, with unknown flags allowed.
func recoverScanStreamFlags(args []string) (events, scanUUID string) {
	fs := pflag.NewFlagSet("scan-stream", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	ev := fs.String("events", "", "")
	id := fs.String("scan-uuid", "", "")
	_ = fs.Parse(args)
	return *ev, *id
}
