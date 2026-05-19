package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	projectLsTUI   bool
	projectLsNoTUI bool
)

// pickProjectLsTUI shows an interactive picker and, on selection, prints
// full project details. Returns nil if the user quits without selecting.
func pickProjectLsTUI(projects []*database.Project, activeUUID string) error {
	byUUID := make(map[string]*database.Project, len(projects))
	items := make([]tui.Item, 0, len(projects))
	for _, p := range projects {
		byUUID[p.UUID] = p
		items = append(items, projectItem(p, activeUUID))
	}

	res, err := tui.RunList(tui.ListConfig{
		Title: fmt.Sprintf("vigolium projects (%d)", len(projects)),
		Items: items,
	})
	if err != nil {
		return err
	}
	if res.SelectedID == "" {
		return nil
	}
	p, ok := byUUID[res.SelectedID]
	if !ok {
		return fmt.Errorf("selected project %s not in current result set", res.SelectedID)
	}
	showProjectDetail(p, activeUUID)
	return nil
}

func projectItem(p *database.Project, activeUUID string) tui.Item {
	marker := ""
	if p.UUID == activeUUID {
		marker = "* "
	}
	title := marker + p.Name
	if p.Description != "" {
		title += " — " + p.Description
	}

	parts := []string{}
	if p.DefaultTarget != "" {
		parts = append(parts, "default="+p.DefaultTarget)
	}
	parts = append(parts, "uuid="+p.UUID)

	return tui.Item{
		ID:         p.UUID,
		TitleText:  title,
		DescText:   strings.Join(parts, "  "),
		FilterText: p.UUID + " " + p.Name + " " + p.Description,
	}
}

// showProjectDetail prints full project details to stderr.
func showProjectDetail(p *database.Project, activeUUID string) {
	activeLabel := terminal.Gray("no")
	if p.UUID == activeUUID {
		activeLabel = terminal.BoldGreen("yes (active)")
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Project Detail"))

	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("UUID:"), p.UUID)
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Name:"), terminal.BoldCyan(p.Name))
	if p.Description != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Description:"), p.Description)
	}
	if p.OwnerUUID != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Owner UUID:"), terminal.Gray(p.OwnerUUID))
	}
	if p.DefaultTarget != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Default target:"), terminal.Cyan(p.DefaultTarget))
	}
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Active:"), activeLabel)
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Created:"), terminal.Gray(p.CreatedAt.Format("2006-01-02 15:04:05")))
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Updated:"), terminal.Gray(p.UpdatedAt.Format("2006-01-02 15:04:05")))
	fmt.Fprintln(os.Stderr)
}
