package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	sessionTUI   bool
	sessionNoTUI bool
)

// pickAgentSessionTUI shows an interactive picker and, on selection, calls
// showAgentSessionDetail for the chosen session. Returns nil if the user
// quits without selecting.
func pickAgentSessionTUI(ctx context.Context, repo *database.Repository, runs []*database.AgenticScan) error {
	items := make([]tui.Item, 0, len(runs))
	for _, r := range runs {
		items = append(items, agentSessionItem(r))
	}

	res, err := tui.RunList(tui.ListConfig{
		Title: fmt.Sprintf("vigolium agent sessions (%d)", len(runs)),
		Items: items,
	})
	if err != nil {
		return err
	}
	if res.SelectedID == "" {
		return nil
	}
	return showAgentSessionDetail(ctx, repo, res.SelectedID)
}

func agentSessionItem(r *database.AgenticScan) tui.Item {
	target := r.TargetURL
	if target == "" && r.SourcePath != "" {
		target = terminal.ShortenHome(r.SourcePath)
	}
	if target == "" {
		target = "(no target)"
	}

	title := fmt.Sprintf("[%s] %s — %s", r.Mode, r.Status, target)

	duration := ""
	if r.DurationMs > 0 {
		duration = (time.Duration(r.DurationMs) * time.Millisecond).Round(time.Second).String()
	}

	phase := r.CurrentPhase
	if phase == "" && len(r.PhasesRun) > 0 {
		phase = strings.Join(r.PhasesRun, "→")
	}

	parts := []string{
		fmt.Sprintf("findings=%d", r.FindingCount),
		fmt.Sprintf("records=%d", r.RecordCount),
	}
	if phase != "" {
		parts = append(parts, "phase="+phase)
	}
	if duration != "" {
		parts = append(parts, "dur="+duration)
	}
	parts = append(parts, r.CreatedAt.Format("2006-01-02 15:04"))
	parts = append(parts, "uuid="+shortUUID(r.UUID))

	return tui.Item{
		ID:         r.UUID,
		TitleText:  title,
		DescText:   strings.Join(parts, "  "),
		FilterText: r.UUID + " " + r.Mode + " " + r.Status + " " + target + " " + r.AgentName + " " + r.TemplateID,
	}
}

// shortUUID returns an abbreviated UUID for display in dense rows.
func shortUUID(u string) string {
	if len(u) <= 10 {
		return u
	}
	return u[:8] + ".."
}
