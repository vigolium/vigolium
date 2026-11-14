package cli

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestOASTPoll_NeedsScanOrOpen: exactly one session selector.
func TestOASTPoll_NeedsScanOrOpen(t *testing.T) {
	defer func(s string, o bool) { oastPollScan, oastPollOpen = s, o }(oastPollScan, oastPollOpen)
	for _, tc := range []struct {
		scan string
		open bool
	}{{"", false}, {"s1", true}} {
		oastPollScan, oastPollOpen = tc.scan, tc.open
		err := runOASTPoll(oastPollCmd, nil)
		require.Error(t, err)
		require.Equal(t, ExitUsageError, classifyExitCode(err))
	}
	cmd, _, err := rootCmd.Find([]string{"oast", "poll"})
	require.NoError(t, err)
	require.Equal(t, "poll", cmd.Name())
}

// TestOASTSessionPoller_TicksUntilCancelled: the server's poller calls poll on
// every tick and stops with its context.
func TestOASTSessionPoller_TicksUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int64
	done := make(chan struct{})
	go func() {
		runOASTSessionPoller(ctx, nil, 5*time.Millisecond, func(context.Context, *database.Repository) int {
			calls.Add(1)
			return 0
		})
		close(done)
	}()
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 2*time.Second, 5*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not stop on cancel")
	}
}
