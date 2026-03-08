package nginx_path_escape

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// Probe severity levels
const (
	SeverityLow    = 3
	SeverityMedium = 4
	SeverityHigh   = 5
)

// ProbeInfo contains metadata about a probe for reporting.
type ProbeInfo struct {
	ID                string
	Name              string
	Description       string
	Probe             *diffscan.Probe
	RedirectMeansSafe bool // true = 3xx redirect from break means server normalized path (not vulnerable)
	IsACLBypass       bool // true = ACL bypass probe (break accesses same resource, not parent)
	TraversalLevels   int  // How many parent levels this probe traverses (0 = no traversal, e.g., ACL bypass)
}
