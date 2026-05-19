package storage

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

func setupTestObservedDB(t *testing.T) (*bun.DB, *ObservedRepository) {
	t.Helper()

	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:")
	require.NoError(t, err)

	db := bun.NewDB(sqldb, sqlitedialect.New())

	// Create table via DDL
	ctx := context.Background()
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS observed (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL,
		type INTEGER NOT NULL,
		value TEXT NOT NULL,
		frequency INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0
	)`)
	require.NoError(t, err)

	// Create unique index
	_, err = db.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_hostname_type_value ON observed(hostname, type, value)")
	require.NoError(t, err)

	return db, NewObservedRepository(db)
}

func TestObservedRepository_BatchUpsertObserved(t *testing.T) {
	t.Run("insert new items", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		items := map[string]int{
			"admin":  5,
			"config": 3,
			"test":   1,
		}

		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, items)
		require.NoError(t, err)

		// Verify items were inserted
		result, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result, 3)

		// Check frequencies
		freqMap := make(map[string]int)
		for _, item := range result {
			freqMap[item.Value] = item.Frequency
		}
		assert.Equal(t, 5, freqMap["admin"])
		assert.Equal(t, 3, freqMap["config"])
		assert.Equal(t, 1, freqMap["test"])
	})

	t.Run("update with MAX frequency on conflict", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		// First insert
		items1 := map[string]int{
			"admin":  5,
			"config": 10,
		}
		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, items1)
		require.NoError(t, err)

		// Second insert with different frequencies
		items2 := map[string]int{
			"admin":  8,  // Higher than 5, should update
			"config": 3,  // Lower than 10, should NOT update
			"new":    15, // New item
		}
		err = repo.BatchUpsertObserved("example.com", ObservedTypeName, items2)
		require.NoError(t, err)

		// Verify MAX logic
		result, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result, 3)

		freqMap := make(map[string]int)
		for _, item := range result {
			freqMap[item.Value] = item.Frequency
		}
		assert.Equal(t, 8, freqMap["admin"])   // MAX(5, 8) = 8
		assert.Equal(t, 10, freqMap["config"]) // MAX(10, 3) = 10
		assert.Equal(t, 15, freqMap["new"])    // New item
	})

	t.Run("empty items does nothing", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, map[string]int{})
		require.NoError(t, err)

		result, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result, 0)
	})

	t.Run("different types are stored separately", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		names := map[string]int{"admin": 5}
		extensions := map[string]int{".php": 3, ".js": 7}
		paths := map[string]int{"/api/v1": 10}

		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, names)
		require.NoError(t, err)
		err = repo.BatchUpsertObserved("example.com", ObservedTypeExtension, extensions)
		require.NoError(t, err)
		err = repo.BatchUpsertObserved("example.com", ObservedTypePath, paths)
		require.NoError(t, err)

		// Verify by type
		nameResults, err := repo.GetByHostnameAndType("example.com", ObservedTypeName)
		require.NoError(t, err)
		assert.Len(t, nameResults, 1)

		extResults, err := repo.GetByHostnameAndType("example.com", ObservedTypeExtension)
		require.NoError(t, err)
		assert.Len(t, extResults, 2)

		pathResults, err := repo.GetByHostnameAndType("example.com", ObservedTypePath)
		require.NoError(t, err)
		assert.Len(t, pathResults, 1)
	})

	t.Run("different hostnames are isolated", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		items1 := map[string]int{"admin": 5}
		items2 := map[string]int{"admin": 10, "config": 3}

		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, items1)
		require.NoError(t, err)
		err = repo.BatchUpsertObserved("other.com", ObservedTypeName, items2)
		require.NoError(t, err)

		// Verify isolation
		result1, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result1, 1)
		assert.Equal(t, 5, result1[0].Frequency)

		result2, err := repo.GetByHostname("other.com")
		require.NoError(t, err)
		assert.Len(t, result2, 2)
	})
}

func TestObservedRepository_GetByHostname(t *testing.T) {
	t.Run("returns all items for hostname", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		// Insert different types
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeName, map[string]int{"admin": 1}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeExtension, map[string]int{".php": 2}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypePath, map[string]int{"/api": 3}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeFile, map[string]int{"app.js": 4}))

		result, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result, 4)
	})

	t.Run("returns empty for non-existent hostname", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		result, err := repo.GetByHostname("nonexistent.com")
		require.NoError(t, err)
		assert.Len(t, result, 0)
	})
}

func TestObservedRepository_GetByHostnameAndType(t *testing.T) {
	t.Run("filters by type correctly", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeName, map[string]int{"a": 1, "b": 2}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeExtension, map[string]int{".php": 3}))

		nameResults, err := repo.GetByHostnameAndType("example.com", ObservedTypeName)
		require.NoError(t, err)
		assert.Len(t, nameResults, 2)

		extResults, err := repo.GetByHostnameAndType("example.com", ObservedTypeExtension)
		require.NoError(t, err)
		assert.Len(t, extResults, 1)

		pathResults, err := repo.GetByHostnameAndType("example.com", ObservedTypePath)
		require.NoError(t, err)
		assert.Len(t, pathResults, 0)
	})
}

func TestObservedRepository_CountByHostname(t *testing.T) {
	t.Run("counts all items for hostname", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeName, map[string]int{"a": 1, "b": 2}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeExtension, map[string]int{".php": 3}))

		count, err := repo.CountByHostname("example.com")
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})

	t.Run("returns zero for non-existent hostname", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		count, err := repo.CountByHostname("nonexistent.com")
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestObservedRepository_DeleteByHostname(t *testing.T) {
	t.Run("deletes all items for hostname", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeName, map[string]int{"a": 1}))
		require.NoError(t, repo.BatchUpsertObserved("example.com", ObservedTypeExtension, map[string]int{".php": 2}))
		require.NoError(t, repo.BatchUpsertObserved("other.com", ObservedTypeName, map[string]int{"b": 3}))

		err := repo.DeleteByHostname("example.com")
		require.NoError(t, err)

		// Verify example.com is deleted
		result, err := repo.GetByHostname("example.com")
		require.NoError(t, err)
		assert.Len(t, result, 0)

		// Verify other.com is untouched
		result, err = repo.GetByHostname("other.com")
		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
}

func TestObservedRepository_LargeDataset(t *testing.T) {
	t.Run("handles large batch insert", func(t *testing.T) {
		_, repo := setupTestObservedDB(t)

		// Create 1000 items
		items := make(map[string]int, 1000)
		for i := 0; i < 1000; i++ {
			items[string(rune('a'+i%26))+string(rune('0'+i%10))] = i + 1
		}

		err := repo.BatchUpsertObserved("example.com", ObservedTypeName, items)
		require.NoError(t, err)

		count, err := repo.CountByHostname("example.com")
		require.NoError(t, err)
		assert.True(t, count > 0)
	})
}

func TestObservedType_String(t *testing.T) {
	tests := []struct {
		obsType  ObservedType
		expected string
	}{
		{ObservedTypeName, "name"},
		{ObservedTypeExtension, "extension"},
		{ObservedTypePath, "path"},
		{ObservedTypeFile, "file"},
		{ObservedType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.obsType.String())
		})
	}
}
