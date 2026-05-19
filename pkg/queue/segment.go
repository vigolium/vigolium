package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/vmihailenco/msgpack/v5"
	"go.uber.org/zap"
)

// Key prefixes for LevelDB storage.
const (
	prefixTask    = "task:"    // task:{id} → ScanTask JSON
	prefixPending = "pending:" // pending:{timestamp}:{id} → "" (for ordered iteration)
)

// Segment represents a single LevelDB database file containing tasks.
// Each segment has a maximum capacity and is sealed when full.
// marshalTask serializes a ScanTask using MessagePack for compact binary encoding.
func marshalTask(task *ScanTask) ([]byte, error) {
	return msgpack.Marshal(task)
}

// unmarshalTask deserializes a ScanTask. Supports both MessagePack (new format)
// and JSON (legacy format) for backward compatibility.
func unmarshalTask(data []byte, task *ScanTask) error {
	if len(data) > 0 && data[0] == '{' {
		return json.Unmarshal(data, task)
	}
	return msgpack.Unmarshal(data, task)
}

type Segment struct {
	id   uint64
	db   *leveldb.DB
	path string

	totalTasks     atomic.Int64 // Total tasks written to this segment
	completedTasks atomic.Int64 // Tasks that have been acked
	sealed         atomic.Bool  // No more writes allowed
	cachedDiskSize atomic.Int64 // Approximate disk usage, updated on writes

	mu sync.RWMutex
}

// SegmentConfig holds configuration for segment creation.
type SegmentConfig struct {
	// BaseDir is the root directory for all segments.
	BaseDir string

	// ID is the unique segment identifier.
	ID uint64
}

// NewSegment creates a new segment with a LevelDB database.
func NewSegment(cfg SegmentConfig) (*Segment, error) {
	segPath := filepath.Join(cfg.BaseDir, fmt.Sprintf("segment_%08d", cfg.ID))
	if err := os.MkdirAll(segPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create segment directory: %w", err)
	}

	dbPath := filepath.Join(segPath, "tasks.db")
	dbOpts := &opt.Options{
		Filter:              filter.NewBloomFilter(10),
		CompactionTableSize: 32 * opt.MiB,
		WriteBuffer:         4 * opt.MiB,
		BlockCacheCapacity:  2 * opt.MiB,
	}

	db, err := leveldb.OpenFile(dbPath, dbOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %w", err)
	}

	seg := &Segment{
		id:   cfg.ID,
		db:   db,
		path: segPath,
	}

	return seg, nil
}

// OpenSegment opens an existing segment from disk and recovers state.
func OpenSegment(segPath string, id uint64) (*Segment, error) {
	dbPath := filepath.Join(segPath, "tasks.db")
	dbOpts := &opt.Options{
		Filter:              filter.NewBloomFilter(10),
		CompactionTableSize: 32 * opt.MiB,
		WriteBuffer:         4 * opt.MiB,
		BlockCacheCapacity:  2 * opt.MiB,
	}

	db, err := leveldb.OpenFile(dbPath, dbOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %w", err)
	}

	seg := &Segment{
		id:   id,
		db:   db,
		path: segPath,
	}

	// Recover counters by iterating all tasks
	if err := seg.recoverState(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to recover state: %w", err)
	}

	return seg, nil
}

// recoverState rebuilds counters from disk after restart.
// Also resets "processing" tasks back to "pending" for retry.
func (s *Segment) recoverState() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var total, completed int64
	var processingToReset []string

	iter := s.db.NewIterator(util.BytesPrefix([]byte(prefixTask)), nil)
	defer iter.Release()

	for iter.Next() {
		total++

		var task ScanTask
		if err := unmarshalTask(iter.Value(), &task); err != nil {
			zap.L().Warn("Failed to unmarshal task during recovery",
				zap.String("key", string(iter.Key())),
				zap.Error(err))
			continue
		}

		switch task.Status {
		case TaskStatusCompleted:
			completed++
		case TaskStatusProcessing:
			// Reset to pending for retry
			processingToReset = append(processingToReset, task.ID)
		}
	}

	if err := iter.Error(); err != nil {
		return err
	}

	// Reset processing tasks to pending
	for _, taskID := range processingToReset {
		if err := s.resetToPending(taskID); err != nil {
			zap.L().Warn("Failed to reset task to pending",
				zap.String("task_id", taskID),
				zap.Error(err))
		}
	}

	s.totalTasks.Store(total)
	s.completedTasks.Store(completed)

	zap.L().Info("Segment state recovered",
		zap.Uint64("segment_id", s.id),
		zap.Int64("total", total),
		zap.Int64("completed", completed),
		zap.Int("reset_to_pending", len(processingToReset)))

	return nil
}

// resetToPending resets a task from processing back to pending.
func (s *Segment) resetToPending(taskID string) error {
	taskKey := []byte(prefixTask + taskID)
	data, err := s.db.Get(taskKey, nil)
	if err != nil {
		return err
	}

	var task ScanTask
	if err := unmarshalTask(data, &task); err != nil {
		return err
	}

	task.Status = TaskStatusPending
	task.UpdatedAt = time.Now()

	newData, err := marshalTask(&task)
	if err != nil {
		return err
	}

	// Re-add pending key for iteration
	pendingKey := s.makePendingKey(task.CreatedAt, taskID)

	batch := new(leveldb.Batch)
	batch.Put(taskKey, newData)
	batch.Put(pendingKey, nil)

	return s.db.Write(batch, nil)
}

// ID returns the segment ID.
func (s *Segment) ID() uint64 {
	return s.id
}

// Path returns the segment directory path.
func (s *Segment) Path() string {
	return s.path
}

// IsSealed returns true if the segment is sealed for writes.
func (s *Segment) IsSealed() bool {
	return s.sealed.Load()
}

// Seal marks the segment as read-only.
func (s *Segment) Seal() {
	s.sealed.Store(true)
	zap.L().Debug("Segment sealed",
		zap.Uint64("segment_id", s.id),
		zap.Int64("total_tasks", s.totalTasks.Load()))
}

// TotalTasks returns the total number of tasks in this segment.
func (s *Segment) TotalTasks() int64 {
	return s.totalTasks.Load()
}

// CompletedTasks returns the number of completed tasks.
func (s *Segment) CompletedTasks() int64 {
	return s.completedTasks.Load()
}

// PendingTasks returns the number of pending tasks.
func (s *Segment) PendingTasks() int64 {
	return s.totalTasks.Load() - s.completedTasks.Load()
}

// WriteTask writes a task to the segment.
func (s *Segment) WriteTask(task *ScanTask) error {
	if s.sealed.Load() {
		return ErrSegmentSealed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	taskKey := []byte(prefixTask + task.ID)
	pendingKey := s.makePendingKey(task.CreatedAt, task.ID)

	taskData, err := marshalTask(task)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	batch := new(leveldb.Batch)
	batch.Put(taskKey, taskData)
	batch.Put(pendingKey, nil) // Empty value for pending index

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("failed to write task: %w", err)
	}

	s.totalTasks.Add(1)
	s.cachedDiskSize.Add(int64(len(taskData) + len(taskKey) + len(pendingKey) + 64))
	return nil
}

// WriteTasks writes multiple tasks in a single LevelDB batch, amortizing the
// WAL flush across all tasks. This is significantly faster than individual
// WriteTask calls for bulk enqueue operations.
func (s *Segment) WriteTasks(tasks []*ScanTask) error {
	if s.sealed.Load() {
		return ErrSegmentSealed
	}
	if len(tasks) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	batch := new(leveldb.Batch)
	var batchSize int64

	for _, task := range tasks {
		taskKey := []byte(prefixTask + task.ID)
		pendingKey := s.makePendingKey(task.CreatedAt, task.ID)

		taskData, err := marshalTask(task)
		if err != nil {
			return fmt.Errorf("failed to marshal task %s: %w", task.ID, err)
		}

		batch.Put(taskKey, taskData)
		batch.Put(pendingKey, nil)
		batchSize += int64(len(taskData) + len(taskKey) + len(pendingKey) + 64)
	}

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("failed to write task batch (%d tasks): %w", len(tasks), err)
	}

	s.totalTasks.Add(int64(len(tasks)))
	s.cachedDiskSize.Add(batchSize)
	return nil
}

// GetNextPending retrieves and marks the next pending task as processing.
// Returns nil if no pending tasks exist.
func (s *Segment) GetNextPending() (*ScanTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Iterate pending index to find first pending task
	iter := s.db.NewIterator(util.BytesPrefix([]byte(prefixPending)), nil)
	defer iter.Release()

	for iter.Next() {
		pendingKey := iter.Key()
		taskID := s.extractTaskIDFromPendingKey(pendingKey)
		if taskID == "" {
			continue
		}

		// Get the task
		taskKey := []byte(prefixTask + taskID)
		taskData, err := s.db.Get(taskKey, nil)
		if err != nil {
			// Task key missing, remove orphan pending key
			_ = s.db.Delete(pendingKey, nil)
			continue
		}

		var task ScanTask
		if err := unmarshalTask(taskData, &task); err != nil {
			zap.L().Warn("Failed to unmarshal task",
				zap.String("task_id", taskID),
				zap.Error(err))
			continue
		}

		// Only process pending tasks (skip if already processing/completed)
		if task.Status != TaskStatusPending {
			// Remove stale pending key
			_ = s.db.Delete(pendingKey, nil)
			continue
		}

		// Mark as processing
		task.Status = TaskStatusProcessing
		task.UpdatedAt = time.Now()

		newData, err := marshalTask(&task)
		if err != nil {
			return nil, err
		}

		batch := new(leveldb.Batch)
		batch.Put(taskKey, newData)
		batch.Delete(pendingKey) // Remove from pending index

		if err := s.db.Write(batch, nil); err != nil {
			return nil, err
		}

		return &task, nil
	}

	if err := iter.Error(); err != nil {
		return nil, err
	}

	return nil, nil // No pending tasks
}

// AckTask marks a task as completed.
func (s *Segment) AckTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	taskKey := []byte(prefixTask + taskID)
	taskData, err := s.db.Get(taskKey, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return ErrTaskNotFound
		}
		return err
	}

	var task ScanTask
	if err := unmarshalTask(taskData, &task); err != nil {
		return err
	}

	if task.Status == TaskStatusCompleted {
		return nil // Already completed
	}

	task.Status = TaskStatusCompleted
	task.UpdatedAt = time.Now()

	newData, err := marshalTask(&task)
	if err != nil {
		return err
	}

	if err := s.db.Put(taskKey, newData, nil); err != nil {
		return err
	}

	s.completedTasks.Add(1)
	return nil
}

// CanDelete returns true if all tasks are completed and segment can be deleted.
func (s *Segment) CanDelete() bool {
	return s.sealed.Load() && s.completedTasks.Load() >= s.totalTasks.Load()
}

// Delete closes and removes the segment from disk.
func (s *Segment) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		if err := s.db.Close(); err != nil {
			return err
		}
		s.db = nil
	}

	if err := os.RemoveAll(s.path); err != nil {
		return err
	}

	zap.L().Info("Segment deleted",
		zap.Uint64("segment_id", s.id))

	return nil
}

// Close closes the segment database without deleting files.
func (s *Segment) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// IsClosed returns true if the segment database has been closed.
func (s *Segment) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db == nil
}

// DiskSize returns the approximate disk usage of this segment in bytes.
// Walks the segment directory and sums file sizes.
func (s *Segment) DiskSize() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

// CachedDiskSize returns the approximate disk usage without filesystem access.
func (s *Segment) CachedDiskSize() int64 {
	return s.cachedDiskSize.Load()
}

// Iterator returns a LevelDB iterator for task keys.
func (s *Segment) Iterator() iterator.Iterator {
	return s.db.NewIterator(util.BytesPrefix([]byte(prefixTask)), nil)
}

// makePendingKey creates a pending index key with timestamp for ordering.
func (s *Segment) makePendingKey(createdAt time.Time, taskID string) []byte {
	// Format: pending:{unix_nano}:{task_id}
	return []byte(fmt.Sprintf("%s%020d:%s", prefixPending, createdAt.UnixNano(), taskID))
}

// extractTaskIDFromPendingKey extracts the task ID from a pending key.
func (s *Segment) extractTaskIDFromPendingKey(key []byte) string {
	// Key format: pending:{unix_nano}:{task_id}
	keyStr := string(key)
	if len(keyStr) <= len(prefixPending)+21 {
		return ""
	}
	return keyStr[len(prefixPending)+21:] // Skip "pending:" + 20 digits + ":"
}
