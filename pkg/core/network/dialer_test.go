package network

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// TestNewDialer_Standalone exercises NewDialer without touching the shared
// global state. If a dialer can't be constructed in this environment (e.g. no
// resolver config available), the test skips rather than failing.
func TestNewDialer_Standalone(t *testing.T) {
	d, err := NewDialer(&types.Options{})
	if err != nil {
		t.Skipf("cannot build dialer in this environment: %v", err)
	}
	if d == nil {
		t.Fatal("NewDialer returned nil dialer without an error")
	}
	d.Close()
}

// TestInitCloseLifecycle verifies the reference-counted Init/Close semantics on
// the package-global dialer: the dialer is created on first Init, survives while
// any reference is held, is torn down on the final Close, and extra Close calls
// are ignored rather than tearing down a dialer still in use.
func TestInitCloseLifecycle(t *testing.T) {
	if CurrentDialer() != nil {
		t.Skip("global dialer already initialized elsewhere; skipping lifecycle assertions")
	}

	opts := &types.Options{}
	if err := Init(opts); err != nil {
		t.Skipf("cannot initialize dialer in this environment: %v", err)
	}
	if CurrentDialer() == nil {
		t.Fatal("expected a dialer after the first Init")
	}

	// Second reference.
	if err := Init(opts); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	// Release one reference — the dialer must stay alive.
	Close()
	if CurrentDialer() == nil {
		t.Fatal("dialer was torn down while a reference was still held")
	}

	// Release the final reference — now it should be gone.
	Close()
	if CurrentDialer() != nil {
		t.Fatal("expected nil dialer after the final Close")
	}

	// An extra Close (more Closes than Inits) must be a harmless no-op.
	Close()
	if CurrentDialer() != nil {
		t.Fatal("extra Close should not resurrect the dialer")
	}
}
