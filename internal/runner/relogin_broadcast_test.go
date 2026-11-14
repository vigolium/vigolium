package runner

import "testing"

// A successful re-login reaches every crawl subscribed to it, and
// notifications coalesce rather than block.
func TestReloginBroadcast(t *testing.T) {
	var b reloginBroadcast
	a, c := b.subscribe(), b.subscribe()
	b.notify()
	b.notify() // coalesced, must not block
	for i, ch := range []chan struct{}{a, c} {
		select {
		case <-ch:
		default:
			t.Errorf("subscriber %d not notified", i)
		}
	}
}
