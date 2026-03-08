package queue

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewScanTask(t *testing.T) {
	t.Run("creates task with URL", func(t *testing.T) {
		task := NewScanTask("https://example.com", "", nil)

		require.NotEmpty(t, task.ID)
		require.Equal(t, "https://example.com", task.URL)
		require.Empty(t, task.RawRequest)
		require.Nil(t, task.EnableModules)
		require.Equal(t, TaskStatusPending, task.Status)
		require.False(t, task.CreatedAt.IsZero())
		require.False(t, task.UpdatedAt.IsZero())
	})

	t.Run("creates task with raw request", func(t *testing.T) {
		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		task := NewScanTask("", rawReq, nil)

		require.NotEmpty(t, task.ID)
		require.Empty(t, task.URL)
		require.Equal(t, rawReq, task.RawRequest)
	})

	t.Run("creates task with enable modules", func(t *testing.T) {
		modules := []string{"xss", "sqli"}
		task := NewScanTask("https://example.com", "", modules)

		require.Equal(t, modules, task.EnableModules)
		require.Equal(t, 2, len(task.EnableModules))
		require.Equal(t, "xss", task.EnableModules[0])
		require.Equal(t, "sqli", task.EnableModules[1])
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		task1 := NewScanTask("https://example.com", "", nil)
		task2 := NewScanTask("https://example.com", "", nil)

		require.NotEqual(t, task1.ID, task2.ID)
	})
}

func TestNewScanTaskFromRequest(t *testing.T) {
	t.Run("creates task with all fields", func(t *testing.T) {
		url := "https://example.com"
		rawReq := "GET / HTTP/1.1\r\n\r\n"
		webhookURL := "https://webhook.example.com"
		modules := []string{"xss"}
		metadata := map[string]string{"key": "value"}

		task := NewScanTaskFromRequest(url, rawReq, webhookURL, modules, metadata)

		require.Equal(t, url, task.URL)
		require.Equal(t, rawReq, task.RawRequest)
		require.Equal(t, webhookURL, task.WebhookURL)
		require.Equal(t, modules, task.EnableModules)
		require.Equal(t, metadata, task.Metadata)
		require.Equal(t, "value", task.Metadata["key"])
	})
}

func TestScanTask_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		task     *ScanTask
		expected bool
	}{
		{
			name:     "valid with URL",
			task:     &ScanTask{ID: "task-1", URL: "https://example.com"},
			expected: true,
		},
		{
			name:     "valid with RawRequest",
			task:     &ScanTask{ID: "task-2", RawRequest: "GET / HTTP/1.1\r\n\r\n"},
			expected: true,
		},
		{
			name:     "valid with both URL and RawRequest",
			task:     &ScanTask{ID: "task-3", URL: "https://example.com", RawRequest: "GET / HTTP/1.1\r\n\r\n"},
			expected: true,
		},
		{
			name:     "invalid - empty ID",
			task:     &ScanTask{URL: "https://example.com"},
			expected: false,
		},
		{
			name:     "invalid - no URL or RawRequest",
			task:     &ScanTask{ID: "task-4"},
			expected: false,
		},
		{
			name:     "invalid - empty task",
			task:     &ScanTask{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.task.IsValid()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestScanTask_Clone(t *testing.T) {
	t.Run("creates deep copy", func(t *testing.T) {
		original := &ScanTask{
			ID:            "task-1",
			URL:           "https://example.com",
			RawRequest:    "GET / HTTP/1.1\r\n\r\n",
			EnableModules: []string{"xss", "sqli"},
			WebhookURL:    "https://webhook.example.com",
			Metadata:      map[string]string{"key": "value"},
			Status:        TaskStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		clone := original.Clone()

		// Values should be equal
		require.Equal(t, original.ID, clone.ID)
		require.Equal(t, original.URL, clone.URL)
		require.Equal(t, original.RawRequest, clone.RawRequest)
		require.Equal(t, original.EnableModules, clone.EnableModules)
		require.Equal(t, original.WebhookURL, clone.WebhookURL)
		require.Equal(t, original.Metadata, clone.Metadata)
		require.Equal(t, original.Status, clone.Status)

		// Slices should be independent
		clone.EnableModules[0] = "modified"
		require.Equal(t, "xss", original.EnableModules[0])
		require.Equal(t, "modified", clone.EnableModules[0])

		// Maps should be independent
		clone.Metadata["key"] = "modified"
		require.Equal(t, "value", original.Metadata["key"])
		require.Equal(t, "modified", clone.Metadata["key"])
	})

	t.Run("handles nil slices and maps", func(t *testing.T) {
		original := &ScanTask{
			ID:  "task-1",
			URL: "https://example.com",
		}

		clone := original.Clone()

		require.Nil(t, clone.EnableModules)
		require.Nil(t, clone.Metadata)
	})
}

func TestScanTask_MarkProcessing(t *testing.T) {
	task := NewScanTask("https://example.com", "", nil)
	originalUpdatedAt := task.UpdatedAt

	time.Sleep(1 * time.Millisecond) // Ensure time difference
	task.MarkProcessing()

	require.Equal(t, TaskStatusProcessing, task.Status)
	require.True(t, task.UpdatedAt.After(originalUpdatedAt))
}

func TestScanTask_MarkCompleted(t *testing.T) {
	task := NewScanTask("https://example.com", "", nil)
	originalUpdatedAt := task.UpdatedAt

	time.Sleep(1 * time.Millisecond)
	task.MarkCompleted()

	require.Equal(t, TaskStatusCompleted, task.Status)
	require.True(t, task.UpdatedAt.After(originalUpdatedAt))
}

func TestScanTask_JSONSerialization(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		original := &ScanTask{
			ID:            "task-123",
			URL:           "https://example.com/api?id=1",
			RawRequest:    "GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			EnableModules: []string{"xss", "sqli"},
			WebhookURL:    "https://webhook.example.com/callback",
			Metadata:      map[string]string{"source": "api", "priority": "high"},
			Status:        TaskStatusPending,
			CreatedAt:     time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		// Marshal
		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Unmarshal
		var restored ScanTask
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		// Compare
		require.Equal(t, original.ID, restored.ID)
		require.Equal(t, original.URL, restored.URL)
		require.Equal(t, original.RawRequest, restored.RawRequest)
		require.Equal(t, original.EnableModules, restored.EnableModules)
		require.Equal(t, original.WebhookURL, restored.WebhookURL)
		require.Equal(t, original.Metadata, restored.Metadata)
		require.Equal(t, original.Status, restored.Status)
		require.True(t, original.CreatedAt.Equal(restored.CreatedAt))
	})

	t.Run("omits empty fields", func(t *testing.T) {
		task := &ScanTask{
			ID:     "task-1",
			URL:    "https://example.com",
			Status: TaskStatusPending,
		}

		data, err := json.Marshal(task)
		require.NoError(t, err)

		// Check that omitempty works
		var m map[string]any
		err = json.Unmarshal(data, &m)
		require.NoError(t, err)

		require.Equal(t, "task-1", m["id"])
		require.Equal(t, "https://example.com", m["url"])
		require.Equal(t, "pending", m["status"])

		// These should be omitted
		_, hasRawRequest := m["raw_request"]
		_, hasEnableModules := m["enable_modules"]
		_, hasWebhookURL := m["webhook_url"]
		_, hasMetadata := m["metadata"]

		require.False(t, hasRawRequest)
		require.False(t, hasEnableModules)
		require.False(t, hasWebhookURL)
		require.False(t, hasMetadata)
	})
}

func TestTaskStatus(t *testing.T) {
	require.Equal(t, TaskStatus("pending"), TaskStatusPending)
	require.Equal(t, TaskStatus("processing"), TaskStatusProcessing)
	require.Equal(t, TaskStatus("completed"), TaskStatusCompleted)
}
