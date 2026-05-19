package discovery

// WorkItem is a ready-to-execute HTTP request.
// All URL building and dedup checking done BEFORE WorkItem is created.
// Workers pull WorkItems from the work channel and execute them.
type WorkItem struct {
	// URL is the fully constructed URL to request.
	URL string

	// Depth is the discovery depth for recursive task generation.
	Depth uint16

	// Task is the parent task reference (for Description, Priority in results).
	Task Task

	// Callbacks holds the discovery callbacks (shared across all WorkItems from same task).
	Callbacks *Callbacks
}
