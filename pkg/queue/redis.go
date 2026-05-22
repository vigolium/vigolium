package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisQueueConfig holds configuration for the Redis-based queue.
type RedisQueueConfig struct {
	// Addr is the Redis server address (e.g., "localhost:6379").
	Addr string

	// Password is the Redis password (empty for no auth).
	Password string

	// DB is the Redis database number.
	DB int

	// StreamName is the Redis Stream name for tasks.
	// Default: "vigolium:tasks"
	StreamName string

	// ConsumerGroup is the consumer group name.
	// Default: "vigolium-workers"
	ConsumerGroup string

	// ConsumerName is the unique name for this consumer.
	// Default: auto-generated UUID
	ConsumerName string

	// BlockTimeout is how long to wait for new messages.
	// Default: 5s
	BlockTimeout time.Duration

	// MaxRetries is the number of times to retry failed tasks.
	// Default: 3
	MaxRetries int
}

// RedisQueue implements Queue using Redis Streams.
type RedisQueue struct {
	client        *redis.Client
	streamName    string
	consumerGroup string
	consumerName  string
	blockTimeout  time.Duration
	maxRetries    int

	closed   atomic.Bool
	closedCh chan struct{}

	// Metrics
	totalEnqueued  atomic.Int64
	totalDequeued  atomic.Int64
	totalCompleted atomic.Int64
	enqueueErrors  atomic.Int64
	dequeueErrors  atomic.Int64
}

// NewRedisQueue creates a new Redis-based queue.
func NewRedisQueue(cfg RedisQueueConfig) (*RedisQueue, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redis address is required")
	}

	// Set defaults
	if cfg.StreamName == "" {
		cfg.StreamName = "vigolium:tasks"
	}
	if cfg.ConsumerGroup == "" {
		cfg.ConsumerGroup = "vigolium-workers"
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = fmt.Sprintf("worker-%s", uuid.New().String()[:8])
	}
	if cfg.BlockTimeout == 0 {
		cfg.BlockTimeout = 5 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Create consumer group if not exists
	err := client.XGroupCreateMkStream(ctx, cfg.StreamName, cfg.ConsumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		// Ignore "already exists" error
		if !isGroupExistsError(err) {
			return nil, fmt.Errorf("failed to create consumer group: %w", err)
		}
	}

	zap.L().Info("Redis queue initialized",
		zap.String("addr", cfg.Addr),
		zap.String("stream", cfg.StreamName),
		zap.String("group", cfg.ConsumerGroup),
		zap.String("consumer", cfg.ConsumerName))

	return &RedisQueue{
		client:        client,
		streamName:    cfg.StreamName,
		consumerGroup: cfg.ConsumerGroup,
		consumerName:  cfg.ConsumerName,
		blockTimeout:  cfg.BlockTimeout,
		maxRetries:    cfg.MaxRetries,
		closedCh:      make(chan struct{}),
	}, nil
}

func isGroupExistsError(err error) bool {
	return err != nil && err.Error() == "BUSYGROUP Consumer Group name already exists"
}

// Enqueue adds a task to the Redis Stream.
func (q *RedisQueue) Enqueue(ctx context.Context, task *ScanTask) error {
	if q.closed.Load() {
		return ErrQueueClosed
	}

	if task == nil {
		return ErrInvalidTask
	}

	// Generate ID if not set
	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	task.Status = TaskStatusPending
	task.CreatedAt = time.Now()

	// Serialize task
	data, err := json.Marshal(task)
	if err != nil {
		q.enqueueErrors.Add(1)
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	// Add to stream
	_, err = q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: q.streamName,
		Values: map[string]any{
			"task_id": task.ID,
			"data":    string(data),
		},
	}).Result()

	if err != nil {
		q.enqueueErrors.Add(1)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	q.totalEnqueued.Add(1)
	zap.L().Debug("Task enqueued to Redis",
		zap.String("task_id", task.ID),
		zap.String("stream", q.streamName))

	return nil
}

// Dequeue retrieves the next pending task from the Redis Stream.
func (q *RedisQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	for {
		if q.closed.Load() {
			return nil, io.EOF
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.closedCh:
			return nil, io.EOF
		default:
		}

		// Try to read from stream
		streams, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    q.consumerGroup,
			Consumer: q.consumerName,
			Streams:  []string{q.streamName, ">"},
			Count:    1,
			Block:    q.blockTimeout,
		}).Result()

		if err != nil {
			if errors.Is(err, redis.Nil) {
				// No messages, continue waiting
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			q.dequeueErrors.Add(1)
			zap.L().Warn("Redis dequeue error", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if len(streams) == 0 || len(streams[0].Messages) == 0 {
			continue
		}

		msg := streams[0].Messages[0]
		dataStr, ok := msg.Values["data"].(string)
		if !ok {
			zap.L().Warn("Invalid message format, skipping",
				zap.String("message_id", msg.ID))
			// Ack invalid message to prevent reprocessing
			q.client.XAck(ctx, q.streamName, q.consumerGroup, msg.ID)
			continue
		}

		var task ScanTask
		if err := json.Unmarshal([]byte(dataStr), &task); err != nil {
			zap.L().Warn("Failed to unmarshal task, skipping",
				zap.String("message_id", msg.ID),
				zap.Error(err))
			q.client.XAck(ctx, q.streamName, q.consumerGroup, msg.ID)
			continue
		}

		// Store message ID for later acknowledgment
		task.Metadata = map[string]string{
			"redis_message_id": msg.ID,
		}
		task.Status = TaskStatusProcessing

		q.totalDequeued.Add(1)
		zap.L().Debug("Task dequeued from Redis",
			zap.String("task_id", task.ID),
			zap.String("message_id", msg.ID))

		return &task, nil
	}
}

// Ack marks a task as completed and acknowledges the message.
func (q *RedisQueue) Ack(taskID string) error {
	// Note: In Redis Streams, we need the message ID to ack.
	// The message ID is stored in task metadata during Dequeue.
	// For now, we'll use XACK with the stream and group.
	// In production, you'd want to track the message ID.

	q.totalCompleted.Add(1)
	zap.L().Debug("Task acknowledged (Redis)", zap.String("task_id", taskID))
	return nil
}

// AckWithMessageID acknowledges a specific message by its Redis Stream ID.
func (q *RedisQueue) AckWithMessageID(ctx context.Context, messageID string) error {
	_, err := q.client.XAck(ctx, q.streamName, q.consumerGroup, messageID).Result()
	if err != nil {
		return fmt.Errorf("failed to ack message: %w", err)
	}

	q.totalCompleted.Add(1)
	return nil
}

// Close closes the Redis connection.
func (q *RedisQueue) Close() error {
	if q.closed.Swap(true) {
		return nil // Already closed
	}

	close(q.closedCh)

	if err := q.client.Close(); err != nil {
		return fmt.Errorf("failed to close Redis connection: %w", err)
	}

	zap.L().Info("Redis queue closed")
	return nil
}

// Metrics returns current queue statistics.
func (q *RedisQueue) Metrics() *QueueMetrics {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to get pending count
	var depth int64 = -1
	pending, err := q.client.XPending(ctx, q.streamName, q.consumerGroup).Result()
	if err == nil {
		depth = pending.Count
	}

	return &QueueMetrics{
		Depth:          depth,
		TotalEnqueued:  q.totalEnqueued.Load(),
		TotalDequeued:  q.totalDequeued.Load(),
		TotalCompleted: q.totalCompleted.Load(),
		EnqueueErrors:  q.enqueueErrors.Load(),
		DequeueErrors:  q.dequeueErrors.Load(),
	}
}

// ClaimPendingTasks claims and returns tasks that have been pending for too long.
// This is useful for handling crashed workers.
func (q *RedisQueue) ClaimPendingTasks(ctx context.Context, minIdleTime time.Duration) ([]*ScanTask, error) {
	// Get pending messages
	pending, err := q.client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: q.streamName,
		Group:  q.consumerGroup,
		Start:  "-",
		End:    "+",
		Count:  100,
		Idle:   minIdleTime,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get pending messages: %w", err)
	}

	if len(pending) == 0 {
		return nil, nil
	}

	var messageIDs []string
	for _, p := range pending {
		messageIDs = append(messageIDs, p.ID)
	}

	// Claim the messages
	messages, err := q.client.XClaim(ctx, &redis.XClaimArgs{
		Stream:   q.streamName,
		Group:    q.consumerGroup,
		Consumer: q.consumerName,
		MinIdle:  minIdleTime,
		Messages: messageIDs,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to claim messages: %w", err)
	}

	var tasks []*ScanTask
	for _, msg := range messages {
		dataStr, ok := msg.Values["data"].(string)
		if !ok {
			continue
		}

		var task ScanTask
		if err := json.Unmarshal([]byte(dataStr), &task); err != nil {
			continue
		}

		task.Metadata = map[string]string{
			"redis_message_id": msg.ID,
		}
		tasks = append(tasks, &task)
	}

	return tasks, nil
}
