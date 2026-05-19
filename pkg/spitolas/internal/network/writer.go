package network

// Writer defines the interface for writing traffic entries.
type Writer interface {
	Write(entry *TrafficEntry) error
	Close() error
}

// NopWriter is a no-op writer that discards all entries. Useful for tests.
type NopWriter struct{}

func (NopWriter) Write(_ *TrafficEntry) error { return nil }
func (NopWriter) Close() error                { return nil }
