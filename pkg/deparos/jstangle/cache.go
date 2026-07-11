package jstangle

import (
	"container/list"
	"sync"
)

// byteLRU is a small, byte-bounded LRU. Values are immutable after insertion;
// callers clone mutable scan results before returning them to consumers.
type byteLRU[T any] struct {
	mu       sync.Mutex
	maxBytes int64
	bytes    int64
	items    map[string]*list.Element
	lru      *list.List
}

type byteLRUEntry[T any] struct {
	key   string
	value T
	size  int64
}

func newByteLRU[T any](maxBytes int64) *byteLRU[T] {
	return &byteLRU[T]{
		maxBytes: max(0, maxBytes),
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

func (c *byteLRU[T]) get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.items[key]; ok {
		c.lru.MoveToFront(element)
		return element.Value.(*byteLRUEntry[T]).value, true
	}
	var zero T
	return zero, false
}

func (c *byteLRU[T]) add(key string, value T, size int64) bool {
	if c.maxBytes <= 0 || size <= 0 || size > c.maxBytes {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.items[key]; ok {
		entry := element.Value.(*byteLRUEntry[T])
		c.bytes -= entry.size
		entry.value = value
		entry.size = size
		c.bytes += size
		c.lru.MoveToFront(element)
	} else {
		entry := &byteLRUEntry[T]{key: key, value: value, size: size}
		element := c.lru.PushFront(entry)
		c.items[key] = element
		c.bytes += size
	}

	for c.bytes > c.maxBytes {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*byteLRUEntry[T])
		delete(c.items, entry.key)
		c.bytes -= entry.size
		c.lru.Remove(oldest)
	}
	return true
}

func (c *byteLRU[T]) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.items[key]; ok {
		entry := element.Value.(*byteLRUEntry[T])
		delete(c.items, key)
		c.bytes -= entry.size
		c.lru.Remove(element)
	}
}

func (c *byteLRU[T]) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.lru.Init()
	c.bytes = 0
}

func (c *byteLRU[T]) lenAndBytes() (int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items), c.bytes
}
