package payloads

import "testing"

func TestByClassAndAliases(t *testing.T) {
	if got, ok := ByClass("sqli"); !ok || len(got) == 0 {
		t.Fatalf("sqli: ok=%v len=%d", ok, len(got))
	}
	// Alias resolves to the same canonical list.
	canon, _ := ByClass("path_traversal")
	alias, ok := ByClass("traversal")
	if !ok || len(alias) != len(canon) {
		t.Fatalf("alias traversal should equal path_traversal: %d vs %d", len(alias), len(canon))
	}
	if _, ok := ByClass("nope"); ok {
		t.Fatal("unknown class should return ok=false")
	}
}

func TestByClassReturnsCopy(t *testing.T) {
	a, _ := ByClass("xss")
	if len(a) == 0 {
		t.Fatal("xss empty")
	}
	a[0] = "MUTATED"
	b, _ := ByClass("xss")
	if b[0] == "MUTATED" {
		t.Fatal("ByClass must return a copy; caller mutation leaked into the catalog")
	}
}

func TestClasses(t *testing.T) {
	cs := Classes()
	if len(cs) < 10 {
		t.Fatalf("expected the full class set, got %d", len(cs))
	}
	for i := 1; i < len(cs); i++ {
		if cs[i-1] > cs[i] {
			t.Fatalf("Classes() not sorted: %v", cs)
		}
	}
}
