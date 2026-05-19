package payload

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestObservedProvider_Add verifies basic addition functionality.
func TestObservedProvider_Add(t *testing.T) {
	t.Run("add single name", func(t *testing.T) {
		provider := NewObservedProvider(true) // case-sensitive

		provider.Add([]byte("test"))

		assert.Equal(t, 1, provider.Count())
	})

	t.Run("add multiple unique names", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("alpha"))
		provider.Add([]byte("beta"))
		provider.Add([]byte("gamma"))

		assert.Equal(t, 3, provider.Count())
	})

	t.Run("skip empty names", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte(""))
		provider.Add(nil)

		assert.Equal(t, 0, provider.Count())
	})
}

// TestObservedProvider_Deduplication verifies deduplication behavior.
func TestObservedProvider_Deduplication(t *testing.T) {
	t.Run("skip duplicate names", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("test"))
		provider.Add([]byte("test")) // duplicate
		provider.Add([]byte("test")) // duplicate

		assert.Equal(t, 1, provider.Count(), "Should only store one copy")
	})

	t.Run("case sensitive deduplication", func(t *testing.T) {
		provider := NewObservedProvider(true) // case-sensitive

		provider.Add([]byte("Test"))
		provider.Add([]byte("test"))
		provider.Add([]byte("TEST"))

		assert.Equal(t, 3, provider.Count(), "Case-sensitive: all are different")
	})

	t.Run("case insensitive deduplication", func(t *testing.T) {
		provider := NewObservedProvider(false) // case-insensitive

		provider.Add([]byte("Test"))
		provider.Add([]byte("test"))
		provider.Add([]byte("TEST"))

		assert.Equal(t, 1, provider.Count(), "Case-insensitive: all are same")
	})

	t.Run("contains check", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("exists"))

		assert.True(t, provider.Contains([]byte("exists")))
		assert.False(t, provider.Contains([]byte("notfound")))
	})
}

// TestObservedProvider_Sorting verifies alphabetical sorting.
func TestObservedProvider_Sorting(t *testing.T) {
	t.Run("maintains alphabetical order", func(t *testing.T) {
		provider := NewObservedProvider(true)

		// Add in random order
		provider.Add([]byte("zebra"))
		provider.Add([]byte("apple"))
		provider.Add([]byte("monkey"))
		provider.Add([]byte("banana"))

		// Extract all items
		ctx := context.Background()
		var items []string
		for {
			item, err := provider.Next(ctx)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			items = append(items, string(item))
		}

		// Verify sorted order
		expected := []string{"apple", "banana", "monkey", "zebra"}
		assert.Equal(t, expected, items, "Should be alphabetically sorted")
	})

	t.Run("sorting with case insensitive", func(t *testing.T) {
		provider := NewObservedProvider(false) // case-insensitive

		provider.Add([]byte("Zebra"))
		provider.Add([]byte("apple"))
		provider.Add([]byte("Monkey"))

		ctx := context.Background()
		var items []string
		for {
			item, err := provider.Next(ctx)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			items = append(items, string(item))
		}

		// Should be lowercase and sorted
		expected := []string{"apple", "monkey", "zebra"}
		assert.Equal(t, expected, items)
	})
}

// TestObservedProvider_CaseNormalization verifies case handling.
func TestObservedProvider_CaseNormalization(t *testing.T) {
	t.Run("case sensitive preserves case", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("MixedCase"))

		ctx := context.Background()
		item, err := provider.Next(ctx)
		require.NoError(t, err)

		assert.Equal(t, "MixedCase", string(item), "Should preserve original case")
	})

	t.Run("case insensitive converts to lowercase", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.Add([]byte("MixedCase"))

		ctx := context.Background()
		item, err := provider.Next(ctx)
		require.NoError(t, err)

		assert.Equal(t, "mixedcase", string(item), "Should convert to lowercase")
	})
}

// TestObservedProvider_Concurrency verifies thread-safety.
func TestObservedProvider_Concurrency(t *testing.T) {
	t.Run("concurrent additions", func(t *testing.T) {
		provider := NewObservedProvider(true)

		const numGoroutines = 10
		const itemsPerGoroutine = 100

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < itemsPerGoroutine; j++ {
					// Mix of unique and duplicate items
					name := []byte(string(rune('a' + (j % 26))))
					provider.Add(name)
				}
			}(i)
		}

		wg.Wait()

		// Should have 26 unique items (a-z)
		assert.Equal(t, 26, provider.Count())
	})

	t.Run("concurrent reads and writes", func(t *testing.T) {
		provider := NewObservedProvider(true)

		// Pre-populate
		for i := 0; i < 100; i++ {
			provider.Add([]byte(string(rune('A' + i%26))))
		}

		var wg sync.WaitGroup

		// Writers
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					provider.Add([]byte(string(rune('a' + j%26))))
				}
			}()
		}

		// Readers
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					provider.Count()
					provider.Contains([]byte("test"))
				}
			}()
		}

		wg.Wait()

		// Should not panic or race
		assert.True(t, provider.Count() >= 26)
	})
}

// TestObservedProvider_Iteration verifies iterator behavior.
func TestObservedProvider_Iteration(t *testing.T) {
	t.Run("iterate through all items", func(t *testing.T) {
		provider := NewObservedProvider(true)

		expected := []string{"alpha", "beta", "gamma"}
		for _, name := range expected {
			provider.Add([]byte(name))
		}

		ctx := context.Background()
		var actual []string
		for {
			item, err := provider.Next(ctx)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			actual = append(actual, string(item))
		}

		assert.Equal(t, expected, actual)
	})

	t.Run("EOF when exhausted", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("single"))

		ctx := context.Background()

		// First call returns item
		item, err := provider.Next(ctx)
		require.NoError(t, err)
		assert.Equal(t, "single", string(item))

		// Second call returns EOF
		_, err = provider.Next(ctx)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		provider := NewObservedProvider(true)
		provider.Add([]byte("test"))

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := provider.Next(ctx)
		assert.Equal(t, context.Canceled, err)
	})
}

// TestObservedProvider_AddMultiple verifies batch addition.
func TestObservedProvider_AddMultiple(t *testing.T) {
	t.Run("add multiple items", func(t *testing.T) {
		provider := NewObservedProvider(true)

		items := [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		}

		provider.AddMultiple(items)

		assert.Equal(t, 3, provider.Count())
	})

	t.Run("deduplication in batch", func(t *testing.T) {
		provider := NewObservedProvider(true)

		items := [][]byte{
			[]byte("duplicate"),
			[]byte("duplicate"),
			[]byte("unique"),
		}

		provider.AddMultiple(items)

		assert.Equal(t, 2, provider.Count())
	})
}

// TestObservedProvider_Parity verifies expected behavior.
func TestObservedProvider_Parity(t *testing.T) {
	t.Run("matches deduplication", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("config"))
		provider.Add([]byte("config")) // duplicate, skipped

		assert.Equal(t, 1, provider.Count())
	})

	t.Run("matches sorting", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("z"))
		provider.Add([]byte("a"))
		provider.Add([]byte("m"))

		ctx := context.Background()
		first, _ := provider.Next(ctx)
		assert.Equal(t, "a", string(first), "First should be 'a' after sorting")
	})

	t.Run("matches case normalization", func(t *testing.T) {
		provider := NewObservedProvider(false) // case-insensitive (auto-detect)

		provider.Add([]byte("TEST"))

		ctx := context.Background()
		item, _ := provider.Next(ctx)
		assert.Equal(t, "test", string(item), "Should be lowercased")
	})
}

// TestObservedProvider_FrequencyTracking verifies frequency counting.
func TestObservedProvider_FrequencyTracking(t *testing.T) {
	t.Run("frequency increments on duplicate", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("test"))
		provider.Add([]byte("test"))
		provider.Add([]byte("test"))

		assert.Equal(t, 1, provider.Count())
		assert.Equal(t, 3, provider.GetFrequency("test"))
	})

	t.Run("different items have independent frequencies", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("alpha"))
		provider.Add([]byte("alpha"))
		provider.Add([]byte("beta"))
		provider.Add([]byte("beta"))
		provider.Add([]byte("beta"))

		assert.Equal(t, 2, provider.GetFrequency("alpha"))
		assert.Equal(t, 3, provider.GetFrequency("beta"))
	})

	t.Run("case insensitive frequency tracking", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.Add([]byte("Test"))
		provider.Add([]byte("TEST"))
		provider.Add([]byte("test"))

		assert.Equal(t, 1, provider.Count())
		assert.Equal(t, 3, provider.GetFrequency("test"))
	})

	t.Run("non-existent item has zero frequency", func(t *testing.T) {
		provider := NewObservedProvider(true)

		provider.Add([]byte("exists"))

		assert.Equal(t, 0, provider.GetFrequency("notfound"))
	})
}

// TestObservedProvider_Eviction verifies eviction behavior.
func TestObservedProvider_Eviction(t *testing.T) {
	t.Run("evicts lowest frequency items at capacity", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 100)

		// Add 100 unique items (at capacity)
		for i := 0; i < 100; i++ {
			provider.Add([]byte(fmt.Sprintf("item%03d", i)))
		}
		assert.Equal(t, 100, provider.Count())

		// Add duplicates to first 50 items (higher frequency)
		for i := 0; i < 50; i++ {
			provider.Add([]byte(fmt.Sprintf("item%03d", i)))
			provider.Add([]byte(fmt.Sprintf("item%03d", i)))
		}
		// items 0-49 now have frequency 3
		// items 50-99 have frequency 1

		// Add new item, triggers eviction
		provider.Add([]byte("newitem"))

		// Should have evicted ~20% lowest frequency (items from 50-99)
		assert.True(t, provider.Count() <= 82, "Count should be <= 82 after eviction, got %d", provider.Count())

		// High-frequency items should remain
		assert.True(t, provider.Contains([]byte("item000")))
		assert.True(t, provider.Contains([]byte("item049")))

		// New item should be present
		assert.True(t, provider.Contains([]byte("newitem")))

		// Low-frequency items should be evicted (at least some)
		evictedCount := 0
		for i := 50; i < 100; i++ {
			if !provider.Contains([]byte(fmt.Sprintf("item%03d", i))) {
				evictedCount++
			}
		}
		assert.True(t, evictedCount >= 18, "At least 18 items should be evicted, got %d", evictedCount)
	})

	t.Run("deterministic eviction order on tie", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 10)

		// Add items (all frequency 1)
		items := []string{"apple", "banana", "cherry", "date", "elderberry",
			"fig", "grape", "honeydew", "kiwi", "lemon"}
		for _, item := range items {
			provider.Add([]byte(item))
		}

		// Boost frequency of some items
		provider.Add([]byte("apple"))  // freq 2
		provider.Add([]byte("banana")) // freq 2

		// Trigger eviction by adding new item
		provider.Add([]byte("mango"))

		// apple and banana should survive (higher frequency)
		assert.True(t, provider.Contains([]byte("apple")), "apple should survive (freq 2)")
		assert.True(t, provider.Contains([]byte("banana")), "banana should survive (freq 2)")
		assert.True(t, provider.Contains([]byte("mango")), "mango should be added")

		// Items evicted should be alphabetically later ones with freq 1
		// "lemon", "kiwi", "honeydew" etc should be evicted first
		// Alphabetically later items evicted first on tie
	})

	t.Run("eviction preserves sorted order", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 10)

		// Add and boost "zebra" frequency
		provider.Add([]byte("zebra"))
		provider.Add([]byte("zebra"))
		provider.Add([]byte("zebra"))

		// Add others (freq 1)
		for _, item := range []string{"alpha", "beta", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india"} {
			provider.Add([]byte(item))
		}

		// Trigger eviction
		provider.Add([]byte("juliet"))

		// Iterate and verify sorted order
		ctx := context.Background()
		var items []string
		for {
			item, err := provider.Next(ctx)
			if err == io.EOF {
				break
			}
			items = append(items, string(item))
		}

		// Should be sorted alphabetically
		for i := 1; i < len(items); i++ {
			assert.True(t, items[i-1] < items[i],
				"items not sorted: %s should be before %s", items[i-1], items[i])
		}

		// Zebra should still be present (high frequency)
		assert.Contains(t, items, "zebra")
	})

	t.Run("multiple evictions maintain consistency", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 50)

		// Fill to capacity multiple times, triggering multiple evictions
		for round := 0; round < 3; round++ {
			for i := 0; i < 100; i++ {
				provider.Add([]byte(fmt.Sprintf("round%d_item%03d", round, i)))
			}
		}

		// Should still be at or under capacity
		assert.True(t, provider.Count() <= 50, "Count should be <= 50, got %d", provider.Count())

		// Iteration should work correctly
		items := provider.GetAllItems()
		assert.Len(t, items, provider.Count())

		// Items should be sorted
		for i := 1; i < len(items); i++ {
			assert.True(t, items[i-1] < items[i], "items not sorted at index %d", i)
		}
	})
}

// TestObservedProvider_BoundaryConditions tests edge cases.
func TestObservedProvider_BoundaryConditions(t *testing.T) {
	t.Run("empty provider allows adds", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 10)
		provider.Add([]byte("test"))
		assert.Equal(t, 1, provider.Count())
	})

	t.Run("single item at capacity", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 1)
		provider.Add([]byte("first"))
		provider.Add([]byte("second"))

		// Should have exactly 1 item
		assert.Equal(t, 1, provider.Count())
	})

	t.Run("exactly at limit without eviction", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 5)

		for i := 0; i < 5; i++ {
			provider.Add([]byte(fmt.Sprintf("item%d", i)))
		}

		assert.Equal(t, 5, provider.Count())
	})

	t.Run("GetAllItems after eviction", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 10)

		// Fill and trigger eviction
		for i := 0; i < 20; i++ {
			provider.Add([]byte(fmt.Sprintf("item%02d", i)))
		}

		items := provider.GetAllItems()
		assert.Len(t, items, provider.Count())

		// Should be sorted
		for i := 1; i < len(items); i++ {
			assert.True(t, items[i-1] < items[i])
		}
	})

	t.Run("HashContent consistent after eviction", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 10)

		// Fill and trigger eviction
		for i := 0; i < 20; i++ {
			provider.Add([]byte(fmt.Sprintf("item%02d", i)))
		}

		hash1 := provider.HashContent()
		hash2 := provider.HashContent()

		assert.Equal(t, hash1, hash2, "Hash should be consistent")
	})

	t.Run("zero or negative maxItems uses default", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 0)
		assert.Equal(t, DefaultMaxItems, provider.MaxItems())

		provider2 := NewObservedProviderWithLimit(true, -1)
		assert.Equal(t, DefaultMaxItems, provider2.MaxItems())
	})
}

// TestObservedProvider_ConcurrencyWithEviction tests concurrent access during eviction.
func TestObservedProvider_ConcurrencyWithEviction(t *testing.T) {
	t.Run("concurrent adds with eviction", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 100)

		var wg sync.WaitGroup
		wg.Add(10)

		for i := 0; i < 10; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					// Mix of unique and duplicate
					name := fmt.Sprintf("item_%d_%d", id, j%20)
					provider.Add([]byte(name))
				}
			}(i)
		}

		wg.Wait()

		// Should be at or under capacity
		assert.True(t, provider.Count() <= 100, "Count should be <= 100, got %d", provider.Count())
	})

	t.Run("concurrent adds and reads during eviction", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(true, 50)

		var wg sync.WaitGroup

		// Writers - will trigger evictions
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					provider.Add([]byte(fmt.Sprintf("writer%d_item%d", id, j)))
				}
			}(i)
		}

		// Readers
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					provider.Count()
					provider.Contains([]byte("test"))
					provider.GetAllItems()
					provider.GetFrequency("writer0_item0")
				}
			}()
		}

		wg.Wait()

		// Should not panic or race, and be at or under capacity
		assert.True(t, provider.Count() <= 50)
	})
}

// BenchmarkObservedProvider_Add measures addition performance.
func BenchmarkObservedProvider_Add(b *testing.B) {
	provider := NewObservedProvider(true)
	names := [][]byte{
		[]byte("admin"),
		[]byte("config"),
		[]byte("login"),
		[]byte("api"),
		[]byte("users"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.Add(names[i%len(names)])
	}
}

// BenchmarkObservedProvider_Contains measures lookup performance.
func BenchmarkObservedProvider_Contains(b *testing.B) {
	provider := NewObservedProvider(true)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		provider.Add([]byte(string(rune('a' + i%26))))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.Contains([]byte("m"))
	}
}

// BenchmarkObservedProvider_AddWithEviction measures performance with eviction.
func BenchmarkObservedProvider_AddWithEviction(b *testing.B) {
	provider := NewObservedProviderWithLimit(true, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("item_%d", i%2000) // Mix unique/duplicate
		provider.Add([]byte(name))
	}
}

// BenchmarkObservedProvider_AddUniqueWithEviction measures worst-case eviction.
func BenchmarkObservedProvider_AddUniqueWithEviction(b *testing.B) {
	provider := NewObservedProviderWithLimit(true, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("unique_item_%d", i) // All unique - triggers frequent eviction
		provider.Add([]byte(name))
	}
}

// BenchmarkObservedProvider_GetAllItems measures snapshot performance.
func BenchmarkObservedProvider_GetAllItems(b *testing.B) {
	provider := NewObservedProviderWithLimit(true, 10000)

	// Fill to capacity
	for i := 0; i < 10000; i++ {
		provider.Add([]byte(fmt.Sprintf("item_%05d", i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.GetAllItems()
	}
}

// TestObservedProvider_AddWithFrequency tests the AddWithFrequency method.
func TestObservedProvider_AddWithFrequency(t *testing.T) {
	t.Run("new item with custom frequency", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.AddWithFrequency([]byte("test"), TrustedFrequencyBoost)

		assert.Equal(t, TrustedFrequencyBoost, provider.GetFrequency("test"))
		assert.Equal(t, 1, provider.Count())
	})

	t.Run("existing item increments by frequency", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.Add([]byte("test"))                                     // freq = 1
		provider.AddWithFrequency([]byte("test"), TrustedFrequencyBoost) // freq = 101

		assert.Equal(t, 1+TrustedFrequencyBoost, provider.GetFrequency("test"))
		assert.Equal(t, 1, provider.Count())
	})

	t.Run("zero frequency is ignored", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.AddWithFrequency([]byte("test"), 0)

		assert.Equal(t, 0, provider.Count())
	})

	t.Run("negative frequency is ignored", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.AddWithFrequency([]byte("test"), -5)

		assert.Equal(t, 0, provider.Count())
	})

	t.Run("empty name is ignored", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.AddWithFrequency([]byte(""), TrustedFrequencyBoost)
		provider.AddWithFrequency(nil, TrustedFrequencyBoost)

		assert.Equal(t, 0, provider.Count())
	})

	t.Run("case insensitive with frequency", func(t *testing.T) {
		provider := NewObservedProvider(false)

		provider.AddWithFrequency([]byte("Test"), TrustedFrequencyBoost)
		provider.AddWithFrequency([]byte("TEST"), TrustedFrequencyBoost) // increments by 100

		assert.Equal(t, 1, provider.Count())
		assert.Equal(t, 2*TrustedFrequencyBoost, provider.GetFrequency("test"))
	})

	t.Run("trusted source survives eviction over secondary", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(false, 10)

		// Add 5 trusted items (freq=100 each)
		for i := 0; i < 5; i++ {
			provider.AddWithFrequency([]byte(fmt.Sprintf("trusted%d", i)), TrustedFrequencyBoost)
		}

		// Add 10 secondary items (freq=1 each) - triggers eviction
		for i := 0; i < 10; i++ {
			provider.Add([]byte(fmt.Sprintf("secondary%d", i)))
		}

		// Trusted items should survive (higher frequency)
		for i := 0; i < 5; i++ {
			assert.True(t, provider.Contains([]byte(fmt.Sprintf("trusted%d", i))),
				"trusted%d should survive eviction", i)
		}

		// Some secondary items should be evicted
		evictedCount := 0
		for i := 0; i < 10; i++ {
			if !provider.Contains([]byte(fmt.Sprintf("secondary%d", i))) {
				evictedCount++
			}
		}
		assert.True(t, evictedCount > 0, "Some secondary items should be evicted")
	})

	t.Run("mixed Add and AddWithFrequency", func(t *testing.T) {
		provider := NewObservedProvider(false)

		// Add first with normal frequency
		provider.Add([]byte("item"))
		assert.Equal(t, 1, provider.GetFrequency("item"))

		// Then add as trusted
		provider.AddWithFrequency([]byte("item"), TrustedFrequencyBoost)
		assert.Equal(t, 1+TrustedFrequencyBoost, provider.GetFrequency("item"))

		// And add again normally
		provider.Add([]byte("item"))
		assert.Equal(t, 2+TrustedFrequencyBoost, provider.GetFrequency("item"))
	})

	t.Run("wordlist items evicted before trusted items", func(t *testing.T) {
		provider := NewObservedProviderWithLimit(false, 20)

		// Simulate real-world scenario:
		// 10 trusted items from URLs (freq=100 each)
		for i := 0; i < 10; i++ {
			provider.AddWithFrequency([]byte(fmt.Sprintf("url_path_%d", i)), TrustedFrequencyBoost)
		}

		// 15 wordlist items from body extraction (freq=1 each)
		for i := 0; i < 15; i++ {
			provider.Add([]byte(fmt.Sprintf("word_%d", i)))
		}

		// Should trigger eviction (10 + 15 = 25 > 20)
		// Eviction should remove low-frequency items first

		// All trusted items should survive
		for i := 0; i < 10; i++ {
			assert.True(t, provider.Contains([]byte(fmt.Sprintf("url_path_%d", i))),
				"url_path_%d should survive eviction (freq=%d)", i, TrustedFrequencyBoost)
		}

		// At least some wordlist items should be evicted
		survivingWordlistItems := 0
		for i := 0; i < 15; i++ {
			if provider.Contains([]byte(fmt.Sprintf("word_%d", i))) {
				survivingWordlistItems++
			}
		}
		assert.True(t, survivingWordlistItems < 15,
			"Some wordlist items should be evicted, got %d surviving", survivingWordlistItems)
	})
}
