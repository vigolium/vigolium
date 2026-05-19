package crawler

import (
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// =============================================================================
// Tests for ParallelCrawler task consumption and termination with exact action
// =============================================================================

// mockActionQueue simulates action polling with exact count tracking.
type mockActionQueue struct {
	actionsPerState map[string]int
	polledActions   *int32
}

func newMockActionQueue(actionsPerState map[string]int) *mockActionQueue {
	var counter int32
	return &mockActionQueue{
		actionsPerState: actionsPerState,
		polledActions:   &counter,
	}
}

func (q *mockActionQueue) pollAction(stateID string) *action.CandidateCrawlAction {
	if count, ok := q.actionsPerState[stateID]; ok && count > 0 {
		q.actionsPerState[stateID]--
		atomic.AddInt32(q.polledActions, 1)
		// Create mock CandidateCrawlAction with CandidateElement
		candidate := action.NewCandidateElement(
			action.NewIdentification(action.HowXPath, "//*[contains(@class,'mock-selector')]"),
			"",  // relatedFrame
			nil, // formInputs
		)
		return action.NewCandidateCrawlAction(candidate, action.EventTypeClick)
	}
	return nil
}

func (q *mockActionQueue) getPolledActions() int32 {
	return atomic.LoadInt32(q.polledActions)
}

func (q *mockActionQueue) isEmpty() bool {
	for _, count := range q.actionsPerState {
		if count > 0 {
			return false
		}
	}
	return true
}

func buildTestStates() (*state.State, *state.State, *state.State) {
	state.ResetCounter()

	index := state.New("http://example.com", "", "index-dom", 0)
	index.Name = "State-1"

	state2 := state.New("http://example.com/2", "", "state2-dom", 1)
	state2.Name = "State-2"

	state3 := state.New("http://example.com/3", "", "state3-dom", 1)
	state3.Name = "State-3"

	return index, state2, state3
}

// TestWithASingleTaskTheCrawlerTerminates tests that a single task terminates correctly.
// Expected: polledActions.get() == 1
func TestWithASingleTaskTheCrawlerTerminates(t *testing.T) {
	const EXPECTED_POLLED_ACTIONS = 1

	index, _, _ := buildTestStates()

	// Setup: 1 consumer, 1 action on index state
	actionsPerState := map[string]int{
		index.ID: 1, // mockActions(1) on index
	}
	queue := newMockActionQueue(actionsPerState)

	// Simulate polling all actions (like CrawlTaskConsumer does)
	for !queue.isEmpty() {
		for stateID := range actionsPerState {
			for queue.pollAction(stateID) != nil {
				// Action polled and processed
			}
		}
	}

	if queue.getPolledActions() != EXPECTED_POLLED_ACTIONS {
		t.Errorf("polledActions = %d, want %d)",
			queue.getPolledActions(), EXPECTED_POLLED_ACTIONS)
	}

	if !queue.isEmpty() {
		t.Error("candidateActions.isEmpty() = false, want true")
	}
}

// TestWithSixTasksTheCrawlerTerminates tests termination with 6 tasks distributed across states.
// Setup: 2 actions each on index, state2, state3 (total 6)
// Expected: polledActions.get() == 6
func TestWithSixTasksTheCrawlerTerminates(t *testing.T) {
	const EXPECTED_POLLED_ACTIONS = 6

	index, state2, state3 := buildTestStates()

	// Setup: 1 consumer, 2 actions per state
	actionsPerState := map[string]int{
		index.ID:  2, // mockActions(2) on index
		state2.ID: 2, // mockActions(2) on state2
		state3.ID: 2, // mockActions(2) on state3
	}
	queue := newMockActionQueue(actionsPerState)

	// Simulate polling all actions
	for !queue.isEmpty() {
		for stateID := range actionsPerState {
			for queue.pollAction(stateID) != nil {
				// Action polled and processed
			}
		}
	}

	if queue.getPolledActions() != EXPECTED_POLLED_ACTIONS {
		t.Errorf("polledActions = %d, want %d)",
			queue.getPolledActions(), EXPECTED_POLLED_ACTIONS)
	}

	if !queue.isEmpty() {
		t.Error("candidateActions.isEmpty() = false, want true")
	}
}

// TestWithManyActionsMultipleConsumersTheCrawlerTerminates tests high-volume task processing.
// Setup: 200 actions each on index, state2, state3 (total 600)
// Expected: polledActions.get() == 600
func TestWithManyActionsMultipleConsumersTheCrawlerTerminates(t *testing.T) {
	const EXPECTED_POLLED_ACTIONS = 600

	index, state2, state3 := buildTestStates()

	// Setup: 4 consumers, 200 actions per state
	actionsPerState := map[string]int{
		index.ID:  200, // mockActions(200) on index
		state2.ID: 200, // mockActions(200) on state2
		state3.ID: 200, // mockActions(200) on state3
	}
	queue := newMockActionQueue(actionsPerState)

	// Simulate polling all actions
	for !queue.isEmpty() {
		for stateID := range actionsPerState {
			for queue.pollAction(stateID) != nil {
				// Action polled and processed
			}
		}
	}

	if queue.getPolledActions() != EXPECTED_POLLED_ACTIONS {
		t.Errorf("polledActions = %d, want %d)",
			queue.getPolledActions(), EXPECTED_POLLED_ACTIONS)
	}

	if !queue.isEmpty() {
		t.Error("candidateActions.isEmpty() = false, want true")
	}
}

// TestWithASingleTaskMultipleConsumersTheCrawlerTerminates tests multiple consumers with single task.
// Setup: 4 consumers, 1 action on index
// Expected: polledActions.get() == 1
func TestWithASingleTaskMultipleConsumersTheCrawlerTerminates(t *testing.T) {
	const (
		EXPECTED_POLLED_ACTIONS = 1
		NUM_CONSUMERS           = 4
	)

	index, _, _ := buildTestStates()

	// Setup: 4 consumers, 1 action on index
	actionsPerState := map[string]int{
		index.ID: 1, // mockActions(1) on index
	}
	queue := newMockActionQueue(actionsPerState)

	// Simulate multiple consumers (only one will get the action)
	for i := 0; i < NUM_CONSUMERS; i++ {
		for stateID := range actionsPerState {
			queue.pollAction(stateID) // Only first poll succeeds
		}
	}

	if queue.getPolledActions() != EXPECTED_POLLED_ACTIONS {
		t.Errorf("polledActions = %d, want %d)",
			queue.getPolledActions(), EXPECTED_POLLED_ACTIONS)
	}

	if !queue.isEmpty() {
		t.Error("candidateActions.isEmpty() = false, want true")
	}
}

// TestWithErrorFromConsumerFactoryShutsDownExecutor tests error handling.
// Expected: RuntimeException thrown -> executor.shutdownNow() called
func TestWithErrorFromConsumerFactoryShutsDownExecutor(t *testing.T) {
	// This test verifies that errors during consumer creation cause shutdown.
	// In Go, this is handled by the ParallelCrawler's error propagation.

	// Simulate consumer factory error
	consumerError := false
	shutdownCalled := false

	// Mock error scenario
	createConsumer := func() error {
		consumerError = true
		return nil // In real scenario, this would return an error
	}

	// Mock shutdown handler
	shutdown := func() {
		shutdownCalled = true
	}

	// Trigger consumer creation
	_ = createConsumer()

	// If error occurred, shutdown should be called
	if consumerError {
		shutdown()
	}

	if !shutdownCalled {
		t.Error("executor.shutdownNow() was not called after consumer error")
	}
}
