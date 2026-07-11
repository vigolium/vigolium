package state

import "testing"

// TestNormalizeVolatileCollapsesVolatileContent verifies that two DOM snapshots
// differing only in volatile content (tokens, timestamps, counters) normalize to
// the same string — so they hash to the same state ID instead of exploding.
func TestNormalizeVolatileCollapsesVolatileContent(t *testing.T) {
	pairs := []struct {
		name string
		a, b string
	}{
		{
			"csrf token",
			`<input name="_csrf" value="a1b2c3d4e5f6a7b8c9d0e1f2"><div>Dashboard</div>`,
			`<input name="_csrf" value="00112233445566778899aabbccddeeff"><div>Dashboard</div>`,
		},
		{
			"live clock",
			`<span>Server time: 14:03:22</span><div>Home</div>`,
			`<span>Server time: 09:41:07</span><div>Home</div>`,
		},
		{
			"iso datetime",
			`<time>2026-07-12T14:03:22Z</time><div>Report</div>`,
			`<time>2019-01-01T00:00:00Z</time><div>Report</div>`,
		},
		{
			"cache-buster asset hash",
			`<a href="/static/app.9f8e7d6c5b4a3f2e1d0c.js">Go</a>`,
			`<a href="/static/app.1122334455667788aabb.js">Go</a>`,
		},
		{
			"uuid",
			`<div data-req="550e8400-e29b-41d4-a716-446655440000">X</div>`,
			`<div data-req="6ba7b810-9dad-11d1-80b4-00c04fd430c8">X</div>`,
		},
		{
			"long counter",
			`<span>Order #100000042</span>`,
			`<span>Order #999999999</span>`,
		},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			na, nb := NormalizeVolatile(p.a), NormalizeVolatile(p.b)
			if na != nb {
				t.Errorf("volatile-only difference not collapsed:\n a=%q\n b=%q", na, nb)
			}
		})
	}
}

// TestNormalizeVolatilePreservesStructure verifies that genuinely different pages
// are NOT collapsed and that short human-readable content survives.
func TestNormalizeVolatilePreservesStructure(t *testing.T) {
	distinct := []struct{ a, b string }{
		{`<h1>Login</h1><form>`, `<h1>Dashboard</h1><nav>`},
		{`<div>Products</div>`, `<div>Settings</div>`},
		{`<span>Total: 42</span>`, `<span>Total: 7</span>`}, // short numbers must stay distinct
	}
	for _, d := range distinct {
		if NormalizeVolatile(d.a) == NormalizeVolatile(d.b) {
			t.Errorf("distinct pages wrongly collapsed: %q vs %q", d.a, d.b)
		}
	}

	// Short readable content is untouched.
	in := `<h1>Welcome back</h1><p>Choose an option</p>`
	if got := NormalizeVolatile(in); got != in {
		t.Errorf("readable content altered: got %q, want %q", got, in)
	}
}
