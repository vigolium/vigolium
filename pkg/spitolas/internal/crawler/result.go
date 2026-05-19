package crawler

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Result holds the complete crawl result.
type Result struct {
	Config    *config.Config
	Graph     *state.Graph
	Stats     Stats
	Fragments fragment.FragmentStats
	Session   *CrawlSession
}

// Summary returns a text summary of the crawl.
func (r *Result) Summary() string {
	duration := r.Stats.EndTime.Sub(r.Stats.StartTime)

	return fmt.Sprintf(`Crawl Summary
=============
URL: %s
Duration: %s

States:
  - Discovered: %d
  - Duplicate: %d

Actions:
  - Executed: %d
  - Failed: %d
  - Forms Submitted: %d

Fragments:
  - Total: %d
  - Dynamic: %d
  - Static: %d
`,
		r.Config.URL.String(),
		duration.Round(time.Second),
		r.Stats.StatesDiscovered,
		r.Stats.StatesDuplicate,
		r.Stats.ActionsExecuted,
		r.Stats.ActionsFailed,
		r.Stats.FormsSubmitted,
		r.Fragments.TotalFragments,
		r.Fragments.DynamicFragments,
		r.Fragments.StaticFragments,
	)
}

// StateCount returns the number of states.
func (r *Result) StateCount() int {
	return r.Graph.StateCount()
}

// EdgeCount returns the number of edges.
func (r *Result) EdgeCount() int {
	return r.Graph.EdgeCount()
}

// Duration returns the crawl duration.
func (r *Result) Duration() time.Duration {
	return r.Stats.EndTime.Sub(r.Stats.StartTime)
}

// Success returns true if crawl completed successfully.
func (r *Result) Success() bool {
	return r.Stats.StatesDiscovered > 0 && r.Stats.ActionsFailed < r.Stats.ActionsExecuted
}

// GetState returns a state by ID.
func (r *Result) GetState(id string) (*state.State, bool) {
	return r.Graph.GetState(id)
}

// GetIndexState returns the index state.
func (r *Result) GetIndexState() *state.State {
	return r.Graph.GetIndexState()
}

// PathBetween finds the shortest path between two states.
func (r *Result) PathBetween(sourceID, targetID string) []*action.Eventable {
	return r.Graph.ShortestPath(sourceID, targetID)
}
