package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	findingTUIFlag   bool
	findingNoTUIFlag bool
)

// selectFindingFromList runs the interactive list picker over findings and
// returns the chosen one. Returns (nil, nil) when the user quits without
// selecting. The Title shown above the picker is caller-supplied so the same
// helper backs both `vigolium finding` browsing and the agent triage picker.
func selectFindingFromList(title string, findings []*database.Finding) (*database.Finding, error) {
	byID := make(map[string]*database.Finding, len(findings))
	items := make([]tui.Item, 0, len(findings))
	for _, f := range findings {
		id := strconv.FormatInt(f.ID, 10)
		byID[id] = f
		items = append(items, findingItem(f))
	}

	res, err := tui.RunList(tui.ListConfig{Title: title, Items: items})
	if err != nil {
		return nil, err
	}
	if res.SelectedID == "" {
		return nil, nil
	}
	f, ok := byID[res.SelectedID]
	if !ok {
		return nil, fmt.Errorf("selected finding %s not in current result set", res.SelectedID)
	}
	return f, nil
}

// pickFindingTUI shows an interactive picker and, on selection, prints the
// chosen finding's raw detail (same format as `--raw`). Returns nil if the
// user quits without selecting.
func pickFindingTUI(ctx context.Context, db *database.DB, findings []*database.Finding, total int64) error {
	f, err := selectFindingFromList(fmt.Sprintf("vigolium findings (%d of %d)", len(findings), total), findings)
	if err != nil || f == nil {
		return err
	}
	return displayFindingsRaw(db, ctx, []*database.Finding{f})
}

func findingItem(f *database.Finding) tui.Item {
	short := f.ModuleShort
	if short == "" {
		short = f.Description
	}
	title := fmt.Sprintf("[%s] %s — %s", f.Severity, f.ModuleName, short)

	loc := f.RepoName
	if loc == "" {
		loc = findingURLValue(f)
	}

	parts := []string{
		"id=" + fmt.Sprintf("%d", f.ID),
		"conf=" + f.Confidence,
	}
	if f.ModuleType != "" {
		parts = append(parts, "type="+f.ModuleType)
	}
	if f.FindingSource != "" {
		parts = append(parts, "src="+f.FindingSource)
	}
	if loc != "" {
		parts = append(parts, loc)
	}
	parts = append(parts, f.FoundAt.Format("2006-01-02 15:04"))

	return tui.Item{
		ID:         fmt.Sprintf("%d", f.ID),
		TitleText:  title,
		DescText:   strings.Join(parts, "  "),
		FilterText: fmt.Sprintf("%d %s %s %s %s %s", f.ID, f.Severity, f.ModuleName, f.ModuleID, loc, strings.Join(f.MatchedAt, " ")),
	}
}
