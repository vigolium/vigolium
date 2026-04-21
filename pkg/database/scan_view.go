package database

// ScanView is a display-oriented wrapper around Scan used by listing endpoints
// (CLI `db ls --table scans --json` and REST `GET /api/scans`). It overrides the
// `modules` JSON field so a fully-populated module list renders as "all" instead
// of a multi-kilobyte CSV, and surfaces active/passive module counts for quick
// tracking without forcing callers to split the CSV themselves.
type ScanView struct {
	*Scan
	Target              string `json:"target"`
	Modules             string `json:"modules"`
	TotalActiveModules  int    `json:"total_active_modules"`
	TotalPassiveModules int    `json:"total_passive_modules"`
}
