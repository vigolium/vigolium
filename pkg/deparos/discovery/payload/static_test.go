package payload

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticProvider_Basic(t *testing.T) {
	payloads := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
	}

	provider := NewStaticProvider(payloads)

	ctx := context.Background()

	// First iteration
	val, err := provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("test1"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("test2"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("test3"), val)

	// Exhausted - returns io.EOF
	val, err = provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)
}

func TestStaticProvider_Count(t *testing.T) {
	payloads := [][]byte{
		[]byte("x"),
		[]byte("y"),
		[]byte("z"),
	}

	provider := NewStaticProvider(payloads)
	assert.Equal(t, 3, provider.Count())

	// Count doesn't change after Next()
	_, _ = provider.Next(context.Background())
	assert.Equal(t, 3, provider.Count())
}

func TestStaticProvider_Empty(t *testing.T) {
	provider := NewStaticProvider([][]byte{})

	ctx := context.Background()
	val, err := provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)

	assert.Equal(t, 0, provider.Count())
}

func TestStaticProvider_SingleItem(t *testing.T) {
	// Common case: single extension for dynamic task generation
	provider := NewStaticProvider([][]byte{[]byte("inc")})

	ctx := context.Background()

	val, err := provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("inc"), val)

	// Exhausted after one - returns io.EOF
	val, err = provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)

	assert.Equal(t, 1, provider.Count())
}

func TestNewStaticListProvider(t *testing.T) {
	items := []string{"one", "two", "three"}

	provider, err := NewStaticListProvider(items)
	require.NoError(t, err)
	require.NotNil(t, provider)

	assert.Equal(t, 3, provider.Count())

	ctx := context.Background()
	val, _ := provider.Next(ctx)
	assert.Equal(t, []byte("one"), val)

	val, _ = provider.Next(ctx)
	assert.Equal(t, []byte("two"), val)

	val, _ = provider.Next(ctx)
	assert.Equal(t, []byte("three"), val)

	val, err = provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)
}
