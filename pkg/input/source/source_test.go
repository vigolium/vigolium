package source

import (
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// fakeSource is an in-test InputSource that yields a fixed list of work items
// (carrying a marker label as their first enabled-module entry) and then io.EOF.
// It records whether Close was called. No real I/O involved.
type fakeSource struct {
	labels   []string
	idx      int
	mu       sync.Mutex
	closed   bool
	failNext error // when set, Next returns this error instead of an item
}

func newFakeSource(labels ...string) *fakeSource {
	return &fakeSource{labels: labels}
}

func (f *fakeSource) Next(ctx context.Context) (*work.WorkItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, err
	}
	if f.idx >= len(f.labels) {
		return nil, io.EOF
	}
	label := f.labels[f.idx]
	f.idx++
	return work.NewWithModules(nil, []string{label}), nil
}

func (f *fakeSource) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeSource) Count() int64 { return int64(len(f.labels)) }

// label extracts the marker label from a fakeSource-produced WorkItem.
func label(item *work.WorkItem) string {
	if item == nil || len(item.EnableModules) == 0 {
		return ""
	}
	return item.EnableModules[0]
}

// drain pulls all items from a source until io.EOF, returning the labels.
func drain(t *testing.T, src InputSource) []string {
	t.Helper()
	var got []string
	for {
		item, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		got = append(got, label(item))
	}
	return got
}

func TestIsEOF(t *testing.T) {
	assert.True(t, IsEOF(io.EOF))
	assert.False(t, IsEOF(errors.New("other")))
	assert.False(t, IsEOF(nil))
}

func TestGetTotal(t *testing.T) {
	// Countable source reports its count; non-countable reports 0.
	assert.Equal(t, int64(3), GetTotal(newFakeSource("a", "b", "c")))
	assert.Equal(t, int64(0), GetTotal(&nonCountable{}))
}

// nonCountable is an InputSource that does not implement Countable.
type nonCountable struct{}

func (n *nonCountable) Next(ctx context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (n *nonCountable) Close() error                                     { return nil }

func TestSingleSource(t *testing.T) {
	rr, err := httpmsg.GetRawRequestFromURL("http://example.com/")
	require.NoError(t, err)

	s := NewSingleSource(rr, []string{"mod"})
	assert.Equal(t, int64(1), s.Count())

	item, err := s.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, item)
	assert.Equal(t, rr, item.Request)

	// Second call is EOF.
	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, s.Close())
}

func TestSingleSource_ContextCancelled(t *testing.T) {
	rr, err := httpmsg.GetRawRequestFromURL("http://example.com/")
	require.NoError(t, err)
	s := NewSingleSource(rr, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSliceSource(t *testing.T) {
	rr1, _ := httpmsg.GetRawRequestFromURL("http://example.com/1")
	rr2, _ := httpmsg.GetRawRequestFromURL("http://example.com/2")

	s := NewSliceSource([]*httpmsg.HttpRequestResponse{rr1, rr2}, nil)
	assert.Equal(t, int64(2), s.Count())

	i1, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rr1, i1.Request)
	i2, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rr2, i2.Request)

	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, s.Close())
}

func TestSliceSource_ContextCancelled(t *testing.T) {
	s := NewSliceSource(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestTargetSource(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a", "http://example.com/b"}, []string{"mod"})
	assert.Equal(t, int64(2), s.Count())

	i1, err := s.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "example.com", i1.Request.Service().Host())
	assert.Equal(t, []string{"mod"}, i1.EnableModules)

	_, err = s.Next(context.Background())
	require.NoError(t, err)

	_, err = s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

func TestTargetSource_ClosedReturnsEOF(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a"}, nil)
	require.NoError(t, s.Close())
	_, err := s.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

func TestTargetSource_ContextCancelled(t *testing.T) {
	s := NewTargetSource([]string{"http://example.com/a"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMultiSource_SequentialOrdering(t *testing.T) {
	// MultiSource drains sources in order: first fully, then second.
	a := newFakeSource("a1", "a2")
	b := newFakeSource("b1")
	m := NewMultiSource(a, b)

	got := drain(t, m)
	assert.Equal(t, []string{"a1", "a2", "b1"}, got)
	assert.Equal(t, int64(3), m.Count())

	require.NoError(t, m.Close())
	assert.True(t, a.closed)
	assert.True(t, b.closed)

	// After Close, Next returns EOF.
	_, err := m.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
}

func TestMultiSource_PropagatesError(t *testing.T) {
	a := newFakeSource("a1")
	a.failNext = errors.New("boom")
	m := NewMultiSource(a)

	_, err := m.Next(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestConcurrentMultiSource_ForwardsAllItems(t *testing.T) {
	// Reads from all sources concurrently; every item must be forwarded
	// exactly once (order across sources is not guaranteed).
	a := newFakeSource("a1", "a2")
	b := newFakeSource("b1", "b2", "b3")
	cs := NewConcurrentMultiSource(a, b)

	got := drain(t, cs)
	sort.Strings(got)
	assert.Equal(t, []string{"a1", "a2", "b1", "b2", "b3"}, got)

	require.NoError(t, cs.Close())
	assert.True(t, a.closed)
	assert.True(t, b.closed)
}

func TestConcurrentMultiSource_PropagatesError(t *testing.T) {
	a := newFakeSource()
	a.failNext = errors.New("kaboom")
	cs := NewConcurrentMultiSource(a)
	defer func() { _ = cs.Close() }()

	// The error item should surface from Next.
	var sawErr error
	for {
		_, err := cs.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sawErr = err
			break
		}
	}
	require.Error(t, sawErr)
	assert.Contains(t, sawErr.Error(), "kaboom")
}

func TestConcurrentMultiSource_ContextCancelStopsStreaming(t *testing.T) {
	a := newFakeSource("a1", "a2")
	cs := NewConcurrentMultiSource(a)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := cs.Next(ctx)
	assert.ErrorIs(t, err, context.Canceled)

	require.NoError(t, cs.Close())
}

func TestNewInputSource_NoSource(t *testing.T) {
	_, err := NewInputSource(SourceConfig{})
	assert.Error(t, err)
}

func TestNewInputSource_SingleTarget(t *testing.T) {
	// One source configured -> returned directly (not wrapped in MultiSource).
	src, err := NewInputSource(SourceConfig{Targets: []string{"http://example.com/"}})
	require.NoError(t, err)
	_, ok := src.(*TargetSource)
	assert.True(t, ok)
}

func TestNewInputSource_MultipleSources(t *testing.T) {
	// Targets + stdin -> combined MultiSource.
	src, err := NewInputSource(SourceConfig{
		Targets:  []string{"http://example.com/"},
		UseStdin: true,
	})
	require.NoError(t, err)
	_, ok := src.(*MultiSource)
	assert.True(t, ok)
	_ = src.Close()
}

func TestSupportedFormats(t *testing.T) {
	assert.Contains(t, SupportedFormats(), "urls")
	assert.Contains(t, SupportedFormats(), "nuclei")
}
