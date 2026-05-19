package payload

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"sync"
)

// Default configuration for ObservedProvider.
const (
	// DefaultMaxItems is the maximum number of unique items before eviction triggers.
	DefaultMaxItems = 50000

	// EvictionPercent is the fraction of items to remove when at capacity.
	EvictionPercent = 0.20

	// MinEvictBatch ensures we evict at least this many items to avoid frequent evictions.
	MinEvictBatch = 100

	// TrustedFrequencyBoost is the frequency value added for items from trusted sources
	// (URLs, spider links, JS paths). Items from trusted sources get much higher frequency
	// than items from wordlist extraction (which use frequency=1), ensuring they survive
	// eviction when capacity is reached.
	TrustedFrequencyBoost = 100
)

// ObservedProvider provides filenames discovered during spidering with frequency-based
// bounded storage. When the capacity limit is reached, the least frequently observed
// items are evicted to make room for new discoveries.
//
// Thread-safe for concurrent additions during discovery.
type ObservedProvider struct {
	mu sync.RWMutex

	// frequencies tracks how many times each item has been observed.
	// Key is the normalized name (lowercased if case-insensitive).
	frequencies map[string]int

	// filenames maintains sorted order for iteration.
	// Rebuilt lazily after eviction via needsRebuild flag.
	filenames [][]byte

	// index is the current position for Next() iteration.
	index int

	// caseSensitive controls whether names are normalized to lowercase.
	caseSensitive bool

	// maxItems is the maximum number of unique items before eviction.
	maxItems int

	// needsRebuild indicates filenames slice needs to be rebuilt from frequencies.
	needsRebuild bool
}

// NewObservedProvider creates an empty observed provider with default capacity.
// caseSensitive controls whether names are normalized to lowercase.
func NewObservedProvider(caseSensitive bool) *ObservedProvider {
	return NewObservedProviderWithLimit(caseSensitive, DefaultMaxItems)
}

// NewObservedProviderWithLimit creates an observed provider with custom capacity.
// caseSensitive controls whether names are normalized to lowercase.
// maxItems sets the maximum number of unique items before eviction triggers.
func NewObservedProviderWithLimit(caseSensitive bool, maxItems int) *ObservedProvider {
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	initialCap := min(maxItems, 1000)
	return &ObservedProvider{
		frequencies:   make(map[string]int, initialCap),
		filenames:     make([][]byte, 0, initialCap),
		index:         0,
		caseSensitive: caseSensitive,
		maxItems:      maxItems,
		needsRebuild:  false,
	}
}

// Add adds a new observed filename to the provider or increments its frequency
// if already present. Thread-safe.
//
// When at capacity, triggers eviction of lowest-frequency items before adding.
func (o *ObservedProvider) Add(filename []byte) {
	if len(filename) == 0 {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.addUnsafe(filename)
}

// AddWithFrequency adds a filename with custom frequency. Thread-safe.
// For existing items, increments frequency by the specified amount.
// For new items, sets initial frequency to the specified value.
// Use this for items from trusted sources (URLs, spider links, JS paths)
// which should have higher frequency than wordlist extraction items.
func (o *ObservedProvider) AddWithFrequency(filename []byte, frequency int) {
	if len(filename) == 0 || frequency <= 0 {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.addUnsafeWithFrequency(filename, frequency)
}

// addUnsafe adds a filename without acquiring lock (internal helper).
// CALLER MUST HOLD o.mu LOCK.
func (o *ObservedProvider) addUnsafe(filename []byte) {
	o.addUnsafeWithFrequency(filename, 1)
}

// addUnsafeWithFrequency adds a filename with custom frequency without acquiring lock.
// For existing items, increments frequency by the specified amount.
// For new items, sets initial frequency to the specified value.
// CALLER MUST HOLD o.mu LOCK.
func (o *ObservedProvider) addUnsafeWithFrequency(filename []byte, frequency int) {
	// Convert to string and apply case normalization
	nameStr := string(filename)
	if !o.caseSensitive {
		nameStr = strings.ToLower(nameStr)
	}

	// Check if already exists - increment frequency by specified amount
	if _, exists := o.frequencies[nameStr]; exists {
		o.frequencies[nameStr] += frequency
		return
	}

	// Check capacity before adding new item
	if len(o.frequencies) >= o.maxItems {
		o.evictLowFrequency()
	}

	// Add new item with specified frequency
	o.frequencies[nameStr] = frequency

	// Insert into sorted slice
	o.insertSorted([]byte(nameStr))
}

// insertSorted inserts an item into the filenames slice maintaining sorted order.
// CALLER MUST HOLD o.mu LOCK.
func (o *ObservedProvider) insertSorted(item []byte) {
	// Binary search for insertion point
	pos := sort.Search(len(o.filenames), func(i int) bool {
		return bytes.Compare(o.filenames[i], item) >= 0
	})

	// Insert at position
	o.filenames = append(o.filenames, nil)
	copy(o.filenames[pos+1:], o.filenames[pos:])
	o.filenames[pos] = item
}

// evictLowFrequency removes the lowest-frequency items to make room for new ones.
// When items have equal frequency, alphabetically later items are evicted first
// (deterministic: "zebra" before "apple").
// CALLER MUST HOLD o.mu LOCK.
func (o *ObservedProvider) evictLowFrequency() {
	// Calculate eviction count: 20% of capacity, at least 1
	evictCount := max(1, int(float64(o.maxItems)*EvictionPercent))

	// For normal capacities, apply minimum batch size
	if evictCount < MinEvictBatch && o.maxItems >= MinEvictBatch*2 {
		evictCount = MinEvictBatch
	}

	// Never evict more than half, but ensure at least 1 for small collections
	evictCount = min(evictCount, max(1, len(o.frequencies)/2))

	// Build sortable slice of items with frequencies
	type freqItem struct {
		name string
		freq int
	}
	items := make([]freqItem, 0, len(o.frequencies))
	for name, freq := range o.frequencies {
		items = append(items, freqItem{name, freq})
	}

	// Sort: lowest frequency first, then alphabetically later first (for ties)
	sort.Slice(items, func(i, j int) bool {
		if items[i].freq != items[j].freq {
			return items[i].freq < items[j].freq // Lower frequency first (to evict)
		}
		return items[i].name > items[j].name // Alphabetically later first (to evict)
	})

	// Remove lowest frequency items
	for i := 0; i < evictCount && i < len(items); i++ {
		delete(o.frequencies, items[i].name)
	}

	// Mark that sorted slice needs rebuild
	o.needsRebuild = true
}

// rebuildFilenames reconstructs the sorted filenames slice from frequencies map.
// CALLER MUST HOLD o.mu LOCK.
func (o *ObservedProvider) rebuildFilenames() {
	if !o.needsRebuild {
		return
	}

	o.filenames = make([][]byte, 0, len(o.frequencies))
	for name := range o.frequencies {
		o.filenames = append(o.filenames, []byte(name))
	}

	// Sort alphabetically
	sort.Slice(o.filenames, func(i, j int) bool {
		return bytes.Compare(o.filenames[i], o.filenames[j]) < 0
	})

	// Reset iterator position if beyond new length
	if o.index > len(o.filenames) {
		o.index = len(o.filenames)
	}

	o.needsRebuild = false
}

// AddMultiple adds multiple observed filenames at once.
// Thread-safe. Uses the same deduplication and frequency tracking as Add().
func (o *ObservedProvider) AddMultiple(filenames [][]byte) {
	if len(filenames) == 0 {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	for _, filename := range filenames {
		if len(filename) > 0 {
			o.addUnsafe(filename)
		}
	}
}

// AddMultipleWithFrequency adds multiple filenames with custom frequency boost.
// Thread-safe. Single lock acquisition for all items.
// Use for items from trusted sources (URLs, spider links, JS paths, third-party archives).
func (o *ObservedProvider) AddMultipleWithFrequency(filenames [][]byte, frequency int) {
	if len(filenames) == 0 || frequency <= 0 {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	for _, filename := range filenames {
		if len(filename) > 0 {
			o.addUnsafeWithFrequency(filename, frequency)
		}
	}
}

// AddWithExternalLock adds a filename assuming caller holds external synchronization.
// CRITICAL: This method acquires o.mu lock internally. If caller holds another lock
// that could conflict, use this method to maintain proper lock ordering.
//
// Use case: Engine's addObservedExtensionIfNew holds observedExtensionsMu and needs
// to add to observedExtensions without nested locking issues.
func (o *ObservedProvider) AddWithExternalLock(filename []byte) {
	if len(filename) == 0 {
		return
	}

	// This method is identical to Add() but is explicitly named to signal
	// it's being called from a context with external locks
	o.mu.Lock()
	defer o.mu.Unlock()

	o.addUnsafe(filename)
}

// Next returns the next observed filename or io.EOF when exhausted.
func (o *ObservedProvider) Next(ctx context.Context) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Rebuild if needed after eviction
	o.rebuildFilenames()

	if o.index >= len(o.filenames) {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	filename := o.filenames[o.index]
	o.index++
	return filename, nil
}

// Count returns the current number of observed filenames.
func (o *ObservedProvider) Count() int {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return len(o.frequencies)
}

// Name returns a descriptive name for this provider.
func (o *ObservedProvider) Name() string {
	return "observed"
}

// Contains checks if a filename is already in the observed set.
// Thread-safe.
func (o *ObservedProvider) Contains(filename []byte) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	nameStr := string(filename)
	if !o.caseSensitive {
		nameStr = strings.ToLower(nameStr)
	}

	_, exists := o.frequencies[nameStr]
	return exists
}

// GetFrequency returns the observation frequency of a filename.
// Returns 0 if the filename has not been observed.
// Thread-safe.
func (o *ObservedProvider) GetFrequency(filename string) int {
	o.mu.RLock()
	defer o.mu.RUnlock()

	nameStr := filename
	if !o.caseSensitive {
		nameStr = strings.ToLower(nameStr)
	}

	return o.frequencies[nameStr]
}

// GetAllItems returns a snapshot of all current observed items as strings.
// Thread-safe. Used for creating static snapshots for dynamic task generation.
func (o *ObservedProvider) GetAllItems() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Rebuild if needed after eviction
	o.rebuildFilenames()

	items := make([]string, len(o.filenames))
	for i, item := range o.filenames {
		items[i] = string(item)
	}
	return items
}

// SnapshotBytes returns a snapshot of all current observed items as [][]byte.
// The returned slice shares the underlying byte slices with the provider.
// Thread-safe. Used by LazyObservedProvider for memory-efficient snapshots.
func (o *ObservedProvider) SnapshotBytes() [][]byte {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Rebuild if needed after eviction
	o.rebuildFilenames()

	// Return a copy of the slice but share the underlying byte arrays
	items := make([][]byte, len(o.filenames))
	copy(items, o.filenames)
	return items
}

// Close releases any resources held by the provider.
func (o *ObservedProvider) Close() error {
	return nil
}

// HashContent returns a FNV-1a 64-bit hash of the provider's content.
// Hashes the current snapshot of observed items plus case sensitivity flag.
// Thread-safe.
func (o *ObservedProvider) HashContent() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Rebuild if needed to ensure consistent state
	o.rebuildFilenames()

	h := fnv.New64a()

	// Hash all filenames in sorted order
	for _, item := range o.filenames {
		h.Write(item)
		h.Write([]byte{0}) // Separator
	}

	// Include case sensitivity in hash
	if o.caseSensitive {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	return h.Sum64()
}

// MaxItems returns the maximum capacity of this provider.
func (o *ObservedProvider) MaxItems() int {
	return o.maxItems
}

// GetAllItemsWithFrequencies returns a snapshot of all items with their frequencies.
// Thread-safe. Used for persisting observed data to database.
func (o *ObservedProvider) GetAllItemsWithFrequencies() map[string]int {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// Create a copy of the frequencies map
	result := make(map[string]int, len(o.frequencies))
	for k, v := range o.frequencies {
		result[k] = v
	}
	return result
}
