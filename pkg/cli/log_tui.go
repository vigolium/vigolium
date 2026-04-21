package cli

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/tui"
)

var (
	logLsTUI   bool
	logLsNoTUI bool
)

// pickLogLsTUI shows an interactive picker and, on selection, streams the
// chosen session's log (same as `vigolium log <uuid>`). Returns nil if the
// user quits without selecting.
func pickLogLsTUI(rows []sessionRow) error {
	items := make([]tui.Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, logRowItem(r))
	}

	res, err := tui.RunList(tui.ListConfig{
		Title: fmt.Sprintf("vigolium log sessions (%d)", len(rows)),
		Items: items,
	})
	if err != nil {
		return err
	}
	if res.SelectedID == "" {
		return nil
	}
	// False: user did not explicitly set --follow; auto-follow when running.
	return showLogForUUID(res.SelectedID, false)
}

func logRowItem(r sessionRow) tui.Item {
	target := r.target
	if target == "" {
		target = "(no target)"
	}
	title := fmt.Sprintf("[%s] %s — %s", r.kind, r.status, target)

	logCol := "db-only"
	sizeCol := ""
	if r.hasLog {
		logCol = "file"
		sizeCol = formatFileSize(r.logSize)
	} else if r.kind == "agentic" {
		logCol = "missing"
	}

	parts := []string{
		"log=" + logCol,
	}
	if sizeCol != "" {
		parts = append(parts, "size="+sizeCol)
	}
	parts = append(parts, r.createdAt.Format("2006-01-02 15:04"))
	parts = append(parts, "uuid="+shortUUID(r.uuid))

	return tui.Item{
		ID:         r.uuid,
		TitleText:  title,
		DescText:   strings.Join(parts, "  "),
		FilterText: r.uuid + " " + r.kind + " " + r.status + " " + r.target,
	}
}
