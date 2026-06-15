package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// This file holds the piolium (Pi-native) audit-driver helpers shared with the
// unified `vigolium agent audit` dispatcher (pkg/cli/agent_audit.go). The
// standalone `vigolium agent piolium` subcommand was removed — piolium now runs
// only through `vigolium agent audit` (`--driver=piolium` for piolium alone).

// setupAuditStreamWriter combines stdout (when --no-stream is off) with
// a tee to {session}/runtime.log so `vigolium log <uuid>` can replay
// the run regardless of whether anyone was watching live.
func setupAuditStreamWriter(streamToConsole bool, sessionDir string) (io.Writer, func()) {
	var w io.Writer
	if streamToConsole {
		// Under --json, stdout is reserved for the final JSON summary; send the
		// agent stream to stderr so machine-readable output stays clean.
		if globalJSON {
			w = os.Stderr
		} else {
			w = os.Stdout
		}
	}
	if tee, closer := teeToRuntimeLog(w, sessionDir); closer != nil {
		return tee, func() { _ = closer.Close() }
	}
	return w, nil
}

// pioliumCfgInput collects everything buildPioliumAuditCfg needs.
// Consumed by the `agent audit` driver dispatcher.
type pioliumCfgInput struct {
	Mode            string
	Modes           []string
	SourcePath      string
	SessionDir      string
	ProjectUUID     string
	StreamToConsole bool
	StreamWriter    io.Writer
	PiProvider      string
	PiModel         string
	AdditionalArgs  []string
	ScanLimit       int
	ScanSince       string

	// AuthOverride is the per-run BYOK bundle (api-key / oauth-token /
	// oauth-cred-file) that should be injected as env vars on the pi
	// subprocess (or, for codex cred files, staged at <pi-agent-dir>/auth.json).
	// Empty = inherit ambient pi auth from ~/.pi/agent/settings.json.
	AuthOverride agent.AuthOverride
}

func buildPioliumAuditCfg(in pioliumCfgInput) agent.AuditAgentConfig {
	return agent.AuditAgentConfig{
		Harness:        piolium.DefaultHarness(),
		Mode:           in.Mode,
		Modes:          in.Modes,
		Platform:       agent.PlatformPi,
		SourcePath:     in.SourcePath,
		SessionDir:     in.SessionDir,
		ProjectUUID:    in.ProjectUUID,
		ScanUUID:       globalScanUUID,
		SyncInterval:   agent.DefaultAuditSyncInterval,
		Stream:         in.StreamToConsole,
		AdditionalArgs: in.AdditionalArgs,
		PiProvider:     in.PiProvider,
		PiModel:        in.PiModel,
		StreamDecoder: func(r io.Reader, render io.Writer, raw io.Writer) error {
			return pistream.Stream(r, render, pistream.Options{RawLog: raw})
		},
		CommitScanLimit: in.ScanLimit,
		CommitScanSince: in.ScanSince,
		StreamWriter:    in.StreamWriter,
		AuthOverride:    in.AuthOverride,
	}
}

// runPiPreflight surfaces auth and model-availability failures before
// the audit subprocess launches.
func runPiPreflight(provider, model string, timeout time.Duration) error {
	fmt.Fprintf(os.Stderr, "%s Pi preflight check...", terminal.Purple(terminal.SymbolDot))
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	res, err := piolium.Preflight(ctx, piolium.PreflightOptions{
		Provider: provider,
		Model:    model,
		Timeout:  timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, " %s\n", terminal.Red("FAILED"))
		return fmt.Errorf("pi preflight failed: %w (rerun with --no-preflight to bypass)", err)
	}
	fmt.Fprintf(os.Stderr, " %s %s\n", terminal.Green("ok"), terminal.Gray(res.String()))
	fmt.Fprintln(os.Stderr)
	return nil
}
