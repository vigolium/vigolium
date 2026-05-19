package cli

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	trafficTUI   bool
	trafficNoTUI bool
)

// pickTrafficTUI shows an interactive picker and, on selection, prints the
// chosen record's raw HTTP request/response (same format as `--raw`).
// Returns nil if the user quits without selecting.
func pickTrafficTUI(records []*database.HTTPRecord, total int64) error {
	byUUID := make(map[string]*database.HTTPRecord, len(records))
	items := make([]tui.Item, 0, len(records))
	for _, r := range records {
		byUUID[r.UUID] = r
		items = append(items, trafficItem(r))
	}

	res, err := tui.RunList(tui.ListConfig{
		Title: fmt.Sprintf("vigolium traffic (%d of %d)", len(records), total),
		Items: items,
	})
	if err != nil {
		return err
	}
	if res.SelectedID == "" {
		return nil
	}
	rec, ok := byUUID[res.SelectedID]
	if !ok {
		return fmt.Errorf("selected record %s not in current result set", res.SelectedID)
	}
	return displayRaw([]*database.HTTPRecord{rec})
}

func trafficItem(r *database.HTTPRecord) tui.Item {
	title := fmt.Sprintf("%s %s://%s:%d%s",
		r.Method, r.Scheme, r.Hostname, r.Port, r.Path)

	status := "-"
	if r.HasResponse {
		status = fmt.Sprintf("%d", r.StatusCode)
	}
	respTime := "-"
	if r.HasResponse {
		respTime = fmt.Sprintf("%dms", r.ResponseTimeMs)
	}
	size := "-"
	if r.HasResponse {
		size = fmt.Sprintf("%d", r.ResponseContentLength)
	}

	parts := []string{
		"status=" + status,
		"time=" + respTime,
		"size=" + size,
	}
	if r.ResponseContentType != "" {
		parts = append(parts, "type="+r.ResponseContentType)
	}
	if r.Source != "" {
		parts = append(parts, "src="+r.Source)
	}
	parts = append(parts, "uuid="+shortUUID(r.UUID))

	return tui.Item{
		ID:         r.UUID,
		TitleText:  title,
		DescText:   strings.Join(parts, "  "),
		FilterText: r.UUID + " " + r.Method + " " + r.Hostname + " " + r.Path + " " + r.ResponseContentType + " " + r.Source,
	}
}
