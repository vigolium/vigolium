package queue

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TaskStatus represents the current state of a scan task.
type TaskStatus string

const (
	// TaskStatusPending indicates the task is waiting to be processed.
	TaskStatusPending TaskStatus = "pending"

	// TaskStatusProcessing indicates the task is currently being processed.
	TaskStatusProcessing TaskStatus = "processing"

	// TaskStatusCompleted indicates the task has been completed.
	TaskStatusCompleted TaskStatus = "completed"
)

// ScanTask represents a scan request in the queue.
type ScanTask struct {
	// ID is the unique identifier for this task.
	ID string `json:"id"`

	// URL is the target URL to scan.
	// Required if RawRequest is empty.
	URL string `json:"url,omitempty"`

	// RawRequest is the raw HTTP request string.
	// Optional - if empty, a GET request will be generated from URL.
	RawRequest string `json:"raw_request,omitempty"`

	// EnableModules is the list of module IDs to run.
	// Empty means use all default modules.
	EnableModules []string `json:"enable_modules,omitempty"`

	// WebhookURL is the URL to send results to.
	// Optional - if empty, results go to default output only.
	WebhookURL string `json:"webhook_url,omitempty"`

	// Metadata contains arbitrary key-value pairs for tracking.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Status is the current state of the task.
	Status TaskStatus `json:"status"`

	// CreatedAt is when the task was enqueued.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the task was last updated.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// NewScanTask creates a new ScanTask with a generated UUID and pending status.
func NewScanTask(url, rawRequest string, enableModules []string) *ScanTask {
	now := time.Now()
	return &ScanTask{
		ID:            uuid.New().String(),
		URL:           url,
		RawRequest:    rawRequest,
		EnableModules: enableModules,
		Status:        TaskStatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// NewScanTaskFromRequest creates a ScanTask from an API request.
func NewScanTaskFromRequest(url, rawRequest, webhookURL string, enableModules []string, metadata map[string]string) *ScanTask {
	task := NewScanTask(url, rawRequest, enableModules)
	task.WebhookURL = webhookURL
	task.Metadata = metadata
	return task
}

// Clone creates a deep copy of the task.
func (t *ScanTask) Clone() *ScanTask {
	clone := *t

	if t.EnableModules != nil {
		clone.EnableModules = make([]string, len(t.EnableModules))
		copy(clone.EnableModules, t.EnableModules)
	}

	if t.Metadata != nil {
		clone.Metadata = make(map[string]string, len(t.Metadata))
		for k, v := range t.Metadata {
			clone.Metadata[k] = v
		}
	}

	return &clone
}

// MarshalJSON implements json.Marshaler.
func (t *ScanTask) MarshalJSON() ([]byte, error) {
	type Alias ScanTask
	return json.Marshal((*Alias)(t))
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *ScanTask) UnmarshalJSON(data []byte) error {
	type Alias ScanTask
	return json.Unmarshal(data, (*Alias)(t))
}

// IsValid checks if the task has required fields.
func (t *ScanTask) IsValid() bool {
	return t.ID != "" && (t.URL != "" || t.RawRequest != "")
}

// MarkProcessing updates the task status to processing.
func (t *ScanTask) MarkProcessing() {
	t.Status = TaskStatusProcessing
	t.UpdatedAt = time.Now()
}

// MarkCompleted updates the task status to completed.
func (t *ScanTask) MarkCompleted() {
	t.Status = TaskStatusCompleted
	t.UpdatedAt = time.Now()
}
