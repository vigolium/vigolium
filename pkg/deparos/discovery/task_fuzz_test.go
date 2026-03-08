package discovery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

func TestFuzzTask_Expand(t *testing.T) {
	tests := []struct {
		name        string
		urlTemplate string
		payloads    []string
		expected    []string
	}{
		{
			name:        "replaces FUZZ in path",
			urlTemplate: "http://example.com/FUZZ",
			payloads:    []string{"admin", "api", "login"},
			expected: []string{
				"http://example.com/admin",
				"http://example.com/api",
				"http://example.com/login",
			},
		},
		{
			name:        "replaces FUZZ in middle of path",
			urlTemplate: "http://example.com/api/FUZZ/v1",
			payloads:    []string{"users", "items"},
			expected: []string{
				"http://example.com/api/users/v1",
				"http://example.com/api/items/v1",
			},
		},
		{
			name:        "replaces FUZZ in query parameter",
			urlTemplate: "http://example.com/search?q=FUZZ",
			payloads:    []string{"test", "hello"},
			expected: []string{
				"http://example.com/search?q=test",
				"http://example.com/search?q=hello",
			},
		},
		{
			name:        "replaces multiple FUZZ occurrences",
			urlTemplate: "http://example.com/FUZZ?key=FUZZ",
			payloads:    []string{"admin"},
			expected: []string{
				"http://example.com/admin?key=admin",
			},
		},
		{
			name:        "handles empty wordlist",
			urlTemplate: "http://example.com/FUZZ",
			payloads:    []string{},
			expected:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payloads := make([][]byte, len(tc.payloads))
			for i, p := range tc.payloads {
				payloads[i] = []byte(p)
			}
			provider := payload.NewStaticProvider(payloads)

			task := NewFuzzTask(&FuzzTaskConfig{
				URLTemplate: tc.urlTemplate,
				Provider:    provider,
				Depth:       0,
			})

			var results []string
			err := task.Expand(context.Background(), func(url string, depth uint16) {
				results = append(results, url)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, results)
		})
	}
}

func TestFuzzTask_Priority(t *testing.T) {
	provider := payload.NewStaticProvider([][]byte{[]byte("test")})
	task := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider,
	})

	assert.Equal(t, PriorityFuzzer, task.Priority())
	assert.Equal(t, uint8(12), task.Priority())
}

func TestFuzzTask_FoundByName(t *testing.T) {
	provider := payload.NewStaticProvider([][]byte{[]byte("test")})
	task := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider,
	})

	assert.Equal(t, "fuzzer", task.FoundByName())
}

func TestFuzzTask_Hash(t *testing.T) {
	provider1 := payload.NewStaticProvider([][]byte{[]byte("a"), []byte("b")})
	provider2 := payload.NewStaticProvider([][]byte{[]byte("a"), []byte("b")})
	provider3 := payload.NewStaticProvider([][]byte{[]byte("c"), []byte("d")})

	task1 := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider1,
	})
	task2 := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider2,
	})
	task3 := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://other.com/FUZZ",
		Provider:    provider3,
	})

	// Same template + same provider content → same hash
	assert.Equal(t, task1.Hash(), task2.Hash())

	// Different template or provider → different hash
	assert.NotEqual(t, task1.Hash(), task3.Hash())
}

func TestFuzzTask_ExpandContextCancel(t *testing.T) {
	payloads := make([][]byte, 1000)
	for i := range payloads {
		payloads[i] = []byte("word")
	}
	provider := payload.NewStaticProvider(payloads)

	task := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := task.Expand(ctx, func(url string, depth uint16) {})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestFuzzTask_IsFromSpider(t *testing.T) {
	provider := payload.NewStaticProvider([][]byte{[]byte("test")})
	task := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider,
	})

	assert.False(t, task.IsFromSpider())
}

func TestFuzzTask_FullURL(t *testing.T) {
	provider := payload.NewStaticProvider([][]byte{[]byte("test")})
	task := NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.com/FUZZ",
		Provider:    provider,
	})

	assert.Equal(t, []byte("http://example.com/FUZZ"), task.FullURL())
}
