package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// RunAuditDriverInteractive launches the embedded vigolium-audit binary in interactive
// mode (`-i`) attached to the caller's terminal, then blocks until it exits.
//
// This is the "drop into the coding agent" path: audit's `-i` installs its
// harness (agent defs + slash commands) into the coding agent and hands the
// terminal to the user, who drives the audit themselves inside Claude/Codex.
// Because the operator owns the session, vigolium does NOT decode an NDJSON
// stream, create an AgenticScan row, or auto-import findings here — audit
// writes its results to <source>/audit/ and the operator imports them
// afterward (`vigolium import <source>/audit`).
//
// The command is built through the same buildAuditAgentCommand path as a
// headless run so --target / --mode|--modes / --agent / auth flags stay
// identical; the only differences are stream=false (no --json — interactive
// replaces the machine log) and the appended -i.
func RunAuditDriverInteractive(ctx context.Context, cfg AuditAgentConfig) error {
	if cfg.SourcePath == "" {
		return fmt.Errorf("audit source path is empty")
	}
	if info, err := os.Stat(cfg.SourcePath); err != nil {
		return fmt.Errorf("audit source path %q is not accessible: %w", cfg.SourcePath, err)
	} else if !info.IsDir() {
		return fmt.Errorf("audit source path %q is not a directory", cfg.SourcePath)
	}

	cfg.Platform = PlatformAuditBin
	// stream=false → buildAuditAgentCommand omits --json; audit's
	// interactive Ink TUI owns stdout instead of the NDJSON event surface.
	binary, args, _, err := buildAuditAgentCommand(PlatformAuditBin, cfg, false)
	if err != nil {
		return err
	}
	args = append(args, "-i")

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cfg.SourcePath
	// Mirror the headless launcher's ARCHON_* env injection so an
	// interactive run sees the same repository/git/info signals. No
	// Setpgid: the child shares vigolium's controlling terminal so the
	// audit TUI gets a real TTY and Ctrl+C reaches it directly.
	cmd.Env = append(os.Environ(),
		auditEnvFor(DefaultAuditHarness().EnvPrefix, cfg.SourcePath, cfg.ScanUUID, cfg.CommitScanLimit, cfg.CommitScanSince)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
