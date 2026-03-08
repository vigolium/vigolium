package queue

import (
	"fmt"
	"time"
)

// Config holds configuration for creating a queue.
type Config struct {
	// Type is the queue type: "disk", "redis", or "hybrid".
	Type QueueType

	// Disk queue options
	DiskDir       string
	MaxPerSegment int

	// Hybrid queue options
	// MemBufferSize is the in-memory channel capacity for hybrid mode.
	// Tasks beyond this spill to the disk/redis backend. Default: 10000.
	MemBufferSize int

	// Redis queue options
	RedisAddr         string
	RedisPassword     string
	RedisDB           int
	RedisStreamName   string
	RedisGroupName    string
	RedisConsumer     string
	RedisBlockTimeout time.Duration
}

// NewQueue creates a queue based on the configuration.
func NewQueue(cfg Config) (Queue, error) {
	switch cfg.Type {
	case QueueTypeDisk, "":
		// Default to disk queue
		diskCfg := DiskQueueConfig{
			BaseDir:              cfg.DiskDir,
			MaxRecordsPerSegment: cfg.MaxPerSegment,
		}
		if diskCfg.MaxRecordsPerSegment == 0 {
			diskCfg.MaxRecordsPerSegment = 10000
		}
		return NewDiskQueue(diskCfg)

	case QueueTypeRedis:
		redisCfg := RedisQueueConfig{
			Addr:          cfg.RedisAddr,
			Password:      cfg.RedisPassword,
			DB:            cfg.RedisDB,
			StreamName:    cfg.RedisStreamName,
			ConsumerGroup: cfg.RedisGroupName,
			ConsumerName:  cfg.RedisConsumer,
			BlockTimeout:  cfg.RedisBlockTimeout,
		}
		return NewRedisQueue(redisCfg)

	case QueueTypeHybrid:
		// Create the backend (disk by default)
		backendCfg := DiskQueueConfig{
			BaseDir:              cfg.DiskDir,
			MaxRecordsPerSegment: cfg.MaxPerSegment,
		}
		if backendCfg.MaxRecordsPerSegment == 0 {
			backendCfg.MaxRecordsPerSegment = 10000
		}
		backend, err := NewDiskQueue(backendCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create hybrid backend: %w", err)
		}
		return NewHybridQueue(HybridQueueConfig{
			MemBufferSize: cfg.MemBufferSize,
			Backend:       backend,
		})

	default:
		return nil, fmt.Errorf("unknown queue type: %s", cfg.Type)
	}
}
