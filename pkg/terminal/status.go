package terminal

import "fmt"

// FormatModuleProgress renders the "<scanned>/<total> (<active> active, <passive>
// passive[, <timedOut> timed out])" module summary used by the scan status lines
// that show the active/passive split (native dynamic-assessment, scan-request).
// The "timed out" segment is appended only when timedOut > 0, so clean scans
// don't carry a "0 timed out" tail. The returned string is uncolored; callers
// wrap it (typically in Yellow).
func FormatModuleProgress(scanned, total, active, passive, timedOut int64) string {
	breakdown := fmt.Sprintf("%d active, %d passive", active, passive)
	if timedOut > 0 {
		breakdown += fmt.Sprintf(", %d timed out", timedOut)
	}
	return fmt.Sprintf("%d/%d (%s)", scanned, total, breakdown)
}

// FormatModuleCount renders the "<scanned> / <total>[ (<timedOut> timed out)]"
// module summary used by the status lines without the active/passive split
// (scan-on-receive, scan-url CLI). The "timed out" segment is appended only when
// timedOut > 0. The returned string is uncolored; callers wrap it.
func FormatModuleCount(scanned, total, timedOut int64) string {
	s := fmt.Sprintf("%d / %d", scanned, total)
	if timedOut > 0 {
		s += fmt.Sprintf(" (%d timed out)", timedOut)
	}
	return s
}
