package hosterrors

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bluele/gcache"
	"go.uber.org/zap"
)

// Cache is a cache for host based errors. It allows skipping
// certain hosts based on an error threshold.
//
// It uses an LRU cache internally for skipping unresponsive hosts
// that remain so for a duration.
type Cache struct {
	MaxHostError  int
	verbose       bool
	failedTargets gcache.Cache
	TrackError    []string
}

type cacheItem struct {
	errors atomic.Int32
	sync.Once
}

const DefaultMaxHostsCount = 10000

// New returns a new host max errors cache
func New(maxHostError, maxHostsCount int, trackError []string) *Cache {
	gc := gcache.New(maxHostsCount).
		ARC().
		Build()
	return &Cache{failedTargets: gc, MaxHostError: maxHostError, TrackError: trackError}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// Close closes the host errors cache
func (c *Cache) Close() {
	c.failedTargets.Purge()
}

// ErrUnresponsiveHost is returned when a host is unresponsive
var ErrUnresponsiveHost = errors.New("skipping as host is unresponsive")

// Check returns true if a host should be skipped as it has been
// unresponsive for a certain number of times.
//
// The value should be in host:port format (e.g., "example.com:443").
func (c *Cache) Check(value string) bool {
	existingCacheItem, err := c.failedTargets.GetIFPresent(value)
	if err != nil {
		return false
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)

	if existingCacheItemValue.errors.Load() >= int32(c.MaxHostError) {
		existingCacheItemValue.Do(func() {
			zap.L().Error("Skipped host from target list as found unresponsive",
				zap.String("host", value),
				zap.Int32("error_count", existingCacheItemValue.errors.Load()))
		})
		return true
	}
	return false
}

// MarkFailed marks a host as failed previously.
// The value should be in host:port format (e.g., "example.com:443").
func (c *Cache) MarkFailed(value string, err error, ignoreTimeout bool) {
	if !c.checkError(err, ignoreTimeout) {
		return
	}
	existingCacheItem, err := c.failedTargets.GetIFPresent(value)
	if err != nil || existingCacheItem == nil {
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(1)
		_ = c.failedTargets.Set(value, newItem)
		return
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)
	existingCacheItemValue.errors.Add(1)
	_ = c.failedTargets.Set(value, existingCacheItemValue)
}

// MarkSuccess resets the error counter for a host on successful request.
// The value should be in host:port format (e.g., "example.com:443").
func (c *Cache) MarkSuccess(value string) {
	existingCacheItem, err := c.failedTargets.GetIFPresent(value)
	if err != nil || existingCacheItem == nil {
		return
	}

	existingCacheItemValue := existingCacheItem.(*cacheItem)

	// Don't reset if already quarantined
	if existingCacheItemValue.errors.Load() >= int32(c.MaxHostError) {
		return
	}

	existingCacheItemValue.errors.Store(0)
	_ = c.failedTargets.Set(value, existingCacheItemValue)
}

var reCheckError = regexp.MustCompile(`(no address found for host|Client\.Timeout exceeded while awaiting headers|could not resolve host|connection refused|connection reset by peer|i/o timeout|could not connect to any address found for host|timeout awaiting response headers)`)

var reCheckErrorIgnoreTimeout = regexp.MustCompile(`(no address found for host|could not resolve host|connection refused|connection reset by peer|i/o timeout|could not connect to any address found for host)`)

// checkError checks if an error represents a type that should be
// added to the host skipping table.
func (c *Cache) checkError(err error, ignoreTimeout bool) bool {
	if err == nil {
		return false
	}
	errString := err.Error()
	for _, msg := range c.TrackError {
		if strings.Contains(errString, msg) {
			return true
		}
	}
	if ignoreTimeout {
		return reCheckErrorIgnoreTimeout.MatchString(errString)
	}
	return reCheckError.MatchString(errString)
}
