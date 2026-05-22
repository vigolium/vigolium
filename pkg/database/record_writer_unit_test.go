package database

import (
	"testing"
	"time"
)

func TestRecordWriterConfig_WithDefaults(t *testing.T) {
	// Zero config → all defaults applied.
	zero := (&RecordWriterConfig{}).withDefaults()
	if zero.BufferSize != 4096 {
		t.Errorf("BufferSize default = %d, want 4096", zero.BufferSize)
	}
	if zero.BatchSize != 128 {
		t.Errorf("BatchSize default = %d, want 128", zero.BatchSize)
	}
	if zero.FlushInterval != 50*time.Millisecond {
		t.Errorf("FlushInterval default = %v, want 50ms", zero.FlushInterval)
	}
	if zero.Shards != 4 {
		t.Errorf("Shards default = %d, want 4", zero.Shards)
	}
	if zero.FlushTimeout != 2*time.Minute {
		t.Errorf("FlushTimeout default = %v, want 2m", zero.FlushTimeout)
	}

	// Negative values are treated as unset and defaulted.
	neg := (&RecordWriterConfig{
		BufferSize:    -1,
		BatchSize:     -1,
		FlushInterval: -1,
		Shards:        -1,
		FlushTimeout:  -1,
	}).withDefaults()
	if neg.BufferSize != 4096 || neg.BatchSize != 128 || neg.Shards != 4 {
		t.Errorf("negative values not defaulted: %+v", neg)
	}

	// Explicit positive values are preserved.
	custom := (&RecordWriterConfig{
		BufferSize:    100,
		BatchSize:     7,
		FlushInterval: 5 * time.Second,
		Shards:        3,
		FlushTimeout:  30 * time.Second,
	}).withDefaults()
	if custom.BufferSize != 100 || custom.BatchSize != 7 || custom.Shards != 3 ||
		custom.FlushInterval != 5*time.Second || custom.FlushTimeout != 30*time.Second {
		t.Errorf("explicit values not preserved: %+v", custom)
	}
}

func TestNewRecordWriter_AppliesDefaultsAndShards(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	// Shards left at 0 → defaults to 4 shards.
	w := NewRecordWriter(repo, RecordWriterConfig{})
	defer w.Close()

	if len(w.shards) != 4 {
		t.Errorf("expected 4 default shards, got %d", len(w.shards))
	}
	if w.cfg.BatchSize != 128 {
		t.Errorf("cfg.BatchSize = %d, want default 128", w.cfg.BatchSize)
	}
}

func TestRecordWriter_Metrics_InitialZero(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
	defer w.Close()

	m := w.Metrics()
	if m.Enqueued != 0 || m.Flushed != 0 || m.FlushErrors != 0 || m.BatchCount != 0 || m.BufferDepth != 0 {
		t.Errorf("fresh writer metrics should be zero, got %+v", m)
	}
}

func TestRecordWriter_Metrics_TrackEnqueuedAndFlushed(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    256,
		BatchSize:     16,
		FlushInterval: 5 * time.Millisecond,
		Shards:        1,
	})

	const n = 50
	for i := 0; i < n; i++ {
		if _, err := w.Write(t.Context(), makeTestRequest(i), "metrics-test", DefaultProjectUUID); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	// Close drains remaining buffered records.
	w.Close()

	m := w.Metrics()
	if m.Enqueued != n {
		t.Errorf("Enqueued = %d, want %d", m.Enqueued, n)
	}
	if m.Flushed != n {
		t.Errorf("Flushed = %d, want %d", m.Flushed, n)
	}
	if m.FlushErrors != 0 {
		t.Errorf("FlushErrors = %d, want 0", m.FlushErrors)
	}
	if m.BatchCount == 0 {
		t.Error("BatchCount should be > 0 after flushing")
	}
	if m.BufferDepth != 0 {
		t.Errorf("BufferDepth after drain = %d, want 0", m.BufferDepth)
	}
}

func TestRecordWriter_ShardForSingleShard(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
	defer w.Close()

	// With one shard, every host routes to the same shard.
	if w.shardFor("a.com") != w.shardFor("b.com") {
		t.Error("single-shard writer must route all hosts to one shard")
	}
}

func TestRecordWriter_ShardForMultiShardDeterministic(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{Shards: 4})
	defer w.Close()

	// Same host hashes to the same shard every time (serialization guarantee).
	first := w.shardFor("host.example.com")
	for i := 0; i < 10; i++ {
		if w.shardFor("host.example.com") != first {
			t.Fatal("shardFor is not deterministic for a fixed host")
		}
	}
}
