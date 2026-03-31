package parsing

import (
	"encoding/json"
	"fmt"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// reconDeliverableWrapper wraps ReconDeliverable for JSON parsing flexibility.
type reconDeliverableWrapper struct {
	Recon agenttypes.ReconDeliverable `json:"recon"`
}

// ParseReconDeliverable extracts a ReconDeliverable from raw agent output.
func ParseReconDeliverable(raw string) (*agenttypes.ReconDeliverable, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from recon output: %w", err)
	}

	// Try wrapped format: {"recon": {...}}
	var wrapper reconDeliverableWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.Recon.Endpoints) > 0 {
		return &wrapper.Recon, nil
	}

	// Try direct format: {...}
	var recon agenttypes.ReconDeliverable
	if err := json.Unmarshal([]byte(jsonStr), &recon); err == nil && len(recon.Endpoints) > 0 {
		return &recon, nil
	}

	return nil, fmt.Errorf("failed to parse recon deliverable: no endpoints found")
}

// vulnQueueWrapper wraps VulnQueue for JSON parsing flexibility.
type vulnQueueWrapper struct {
	Queue agenttypes.VulnQueue `json:"vuln_queue"`
}

// ParseVulnQueue extracts a VulnQueue from raw agent output.
func ParseVulnQueue(raw string) (*agenttypes.VulnQueue, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from vuln queue output: %w", err)
	}

	// Try wrapped format: {"vuln_queue": {...}}
	var wrapper vulnQueueWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.Queue.Items) > 0 {
		return &wrapper.Queue, nil
	}

	// Try direct format: {...}
	var queue agenttypes.VulnQueue
	if err := json.Unmarshal([]byte(jsonStr), &queue); err == nil && len(queue.Items) > 0 {
		return &queue, nil
	}

	return nil, fmt.Errorf("failed to parse vuln queue: no items found")
}

// exploitationEvidenceWrapper wraps exploitation evidence for JSON parsing flexibility.
type exploitationEvidenceWrapper struct {
	Evidence []agenttypes.ExploitationEvidence `json:"evidence"`
}

// ParseExploitationEvidence extracts exploitation evidence from raw agent output.
func ParseExploitationEvidence(raw string) ([]agenttypes.ExploitationEvidence, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from evidence output: %w", err)
	}

	// Try wrapped format: {"evidence": [...]}
	var wrapper exploitationEvidenceWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.Evidence) > 0 {
		return wrapper.Evidence, nil
	}

	// Try as direct array: [...]
	var evidence []agenttypes.ExploitationEvidence
	if err := json.Unmarshal([]byte(jsonStr), &evidence); err == nil && len(evidence) > 0 {
		return evidence, nil
	}

	// Try as single object: {...}
	var single agenttypes.ExploitationEvidence
	if err := json.Unmarshal([]byte(jsonStr), &single); err == nil && single.FindingRef != "" {
		return []agenttypes.ExploitationEvidence{single}, nil
	}

	return nil, fmt.Errorf("failed to parse exploitation evidence: no evidence found")
}
