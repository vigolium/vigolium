package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// TestHashDeduplication_DepthExcluded verifies that depth is NOT part of task hash.
// This prevents infinite task duplication when the same file is discovered at multiple depths.
//
// Scenario: index.php discovered → creates ExtensionVariantTask[index.bak, depth=1]
//
//	→ discovers index.bak → creates ExtensionVariantTask[index.bak, depth=2]
//	→ Without depth exclusion, this creates DIFFERENT hashes and runs infinitely
//
// Expected: Tasks with same config but different depths have IDENTICAL hashes
func TestHashDeduplication_DepthExcluded(t *testing.T) {
	t.Run("WordlistTask - same hash regardless of depth", func(t *testing.T) {
		provider := payload.NewStaticProvider([][]byte{
			[]byte("admin"),
			[]byte("config"),
		})

		task1 := NewWordlistTask(&WordlistTaskConfig{
			TaskType:   ShortFilesNoExt,
			Provider:   provider,
			SchemeHost: []byte("http://example.com"),
			Path:       []byte("/api/"),
			Depth:      0, // Discovered at depth 0
		})

		task2 := NewWordlistTask(&WordlistTaskConfig{
			TaskType:   ShortFilesNoExt,
			Provider:   provider,
			SchemeHost: []byte("http://example.com"),
			Path:       []byte("/api/"),
			Depth:      5, // Discovered at depth 5
		})

		hash1 := task1.Hash()
		hash2 := task2.Hash()

		assert.Equal(t, hash1, hash2,
			"WordlistTask: Same config at different depths should have IDENTICAL hash to prevent duplicates")
	})

	t.Run("ExtensionVariantTask - same hash regardless of depth", func(t *testing.T) {
		extProvider := payload.NewExtensionProvider()

		task1 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
			SchemeHost:  []byte("http://example.com"),
			Path:        []byte("/admin/"),
			Filename:    []byte("index"),
			OriginalExt: []byte("php"),
			FullName:    []byte("index.php"),
			ExtProvider: extProvider,
			Depth:       1, // Discovered from depth 0 → depth 1
		})

		task2 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
			SchemeHost:  []byte("http://example.com"),
			Path:        []byte("/admin/"),
			Filename:    []byte("index"),
			OriginalExt: []byte("php"),
			FullName:    []byte("index.php"),
			ExtProvider: extProvider,
			Depth:       12, // Discovered from depth 11 → depth 12
		})

		hash1 := task1.Hash()
		hash2 := task2.Hash()

		assert.Equal(t, hash1, hash2,
			"ExtensionVariantTask: Same config at different depths should have IDENTICAL hash to prevent duplicates")
	})

	t.Run("NumericFuzzTask - same hash regardless of depth", func(t *testing.T) {
		task1 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
			BaseURL:       []byte("http://example.com"),
			PathTemplate:  []byte("/api/user"),
			OriginalValue: 123,
			StartOffset:   9,
			EndOffset:     12,
			Depth:         2, // Discovered at depth 2
		})

		task2 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
			BaseURL:       []byte("http://example.com"),
			PathTemplate:  []byte("/api/user"),
			OriginalValue: 123,
			StartOffset:   9,
			EndOffset:     12,
			Depth:         9, // Discovered at depth 9
		})

		hash1 := task1.Hash()
		hash2 := task2.Hash()

		assert.Equal(t, hash1, hash2,
			"NumericFuzzTask: Same config at different depths should have IDENTICAL hash to prevent duplicates")
	})
}

// TestRealWorldScenario_IndexBackupDuplication simulates the exact bug from logs.
// Shows how index.bak would be discovered at depths 5, 9, 10, 11, 12... without the fix.
func TestRealWorldScenario_IndexBackupDuplication(t *testing.T) {
	extProvider := payload.NewExtensionProvider()

	// Simulate discovering index.bak multiple times at different depths
	// This happens in real scans when:
	// - Spider finds index.php (depth 0) → creates variant task (depth 1)
	// - Variant task discovers index.bak → creates new variant task (depth 2)
	// - New variant task discovers index.bak again → creates task (depth 3)
	// - Infinite loop without deduplication!

	depths := []uint16{1, 5, 9, 10, 11, 12, 13, 14, 15}
	var hashes []uint64

	for _, depth := range depths {
		task := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
			SchemeHost:  []byte("http://testphp.vulnweb.com"),
			Path:        []byte("/"),
			Filename:    []byte("index"),
			OriginalExt: []byte("bak"),
			FullName:    []byte("index.bak"),
			ExtProvider: extProvider,
			Depth:       depth,
		})

		hashes = append(hashes, task.Hash())
	}

	// All hashes should be IDENTICAL despite different depths
	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i],
			"All ExtensionVariantTask[index.bak] instances should have the same hash regardless of depth."+
				" Different hashes would cause the same file to be tested multiple times (infinite loop)."+
				" Depth %d has different hash than depth %d", depths[i], depths[0])
	}

	t.Logf("✓ All %d tasks for index.bak have identical hash: %x", len(hashes), hashes[0])
	t.Logf("✓ This prevents the infinite loop seen in production logs")
}

// TestRealWorldScenario_NumericPathDuplication verifies numeric tasks don't duplicate.
// Example: /api/user123 discovered at different depths should create same hash.
func TestRealWorldScenario_NumericPathDuplication(t *testing.T) {
	// Simulate discovering /api/user123 at multiple depths
	// This can happen when:
	// - Initial scan finds /api/user100 (depth 0)
	// - Numeric task finds /api/user123 (depth 1)
	// - New numeric task created for user123 → discovers /api/user124 (depth 2)
	// - Without deduplication, infinite loop!

	depths := []uint16{0, 1, 2, 3, 5, 10, 15}
	var hashes []uint64

	for _, depth := range depths {
		task := NewNumericFuzzTask(&NumericFuzzTaskConfig{
			BaseURL:       []byte("http://example.com"),
			PathTemplate:  []byte("/api/user123"),
			OriginalValue: 123,
			StartOffset:   9,  // Position of '1' in "123"
			EndOffset:     12, // Position after '3'
			Depth:         depth,
		})

		hashes = append(hashes, task.Hash())
	}

	// All hashes must be identical
	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i],
			"NumericFuzzTask[user123] at depth %d should have same hash as depth %d."+
				" Different hashes cause duplicate task execution.", depths[i], depths[0])
	}

	t.Logf("✓ All %d NumericFuzzTask instances have identical hash: %x", len(hashes), hashes[0])
	t.Logf("✓ Depth does NOT affect task deduplication")
}
