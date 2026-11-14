package state

import (
	"fmt"
	"strings"
	"testing"
)

func listPage(items int, text string) string {
	var b strings.Builder
	b.WriteString("<html><body><nav><a>Home</a><a>Products</a></nav><main><h1>" + text + "</h1><ul>")
	for i := 0; i < items; i++ {
		fmt.Fprintf(&b, "<li><a>%s %d</a><span>x</span></li>", text, i)
	}
	b.WriteString("</ul></main><footer><p>c</p></footer></body></html>")
	return b.String()
}

// MISS-28a: renderings of one template are structural clones; a different
// template is not.
func TestStructSimHash(t *testing.T) {
	a := StructSimHash(listPage(20, "alpha"))
	b := StructSimHash(listPage(20, "beta 2026-11-15"))
	if d := StructHamming(a, b); d != 0 {
		t.Errorf("same structure, different text: hamming %d, want 0", d)
	}
	c := StructSimHash(listPage(21, "alpha"))
	if d := StructHamming(a, c); d > structMaxHamming {
		t.Errorf("one extra list item: hamming %d, want <= %d", d, structMaxHamming)
	}
	form := StructSimHash("<html><body><form><input><input><select><option></option></select><textarea></textarea><button></button></form><table><tr><td></td></tr></table></body></html>")
	if d := StructHamming(a, form); d <= structMaxHamming {
		t.Errorf("different template: hamming %d, want > %d", d, structMaxHamming)
	}
	if URLTemplate("https://App.test/users/123/orders/9f1c2b3a-1111-2222-3333-444455556666?x=1") != "https://app.test/users/{}/orders/{}" {
		t.Errorf("URLTemplate = %s", URLTemplate("https://App.test/users/123/orders/9f1c2b3a-1111-2222-3333-444455556666?x=1"))
	}
}

func TestGraphFoldsStructuralClones(t *testing.T) {
	g := NewGraph()
	s1 := New("https://app.test/users/1", listPage(20, "alice"), listPage(20, "alice"), 1)
	s2 := New("https://app.test/users/2", listPage(20, "bob"), listPage(20, "bob"), 1)
	if _, added := g.PutIfAbsent(s1); !added {
		t.Fatal("first state must be added")
	}
	canon, added := g.PutIfAbsent(s2)
	if added || canon.ID != s1.ID {
		t.Errorf("structural clone must fold into %s, got added=%v id=%s", s1.ID, added, canon.ID)
	}
	if g.StructClones() != 1 {
		t.Errorf("StructClones = %d, want 1", g.StructClones())
	}
	other := New("https://app.test/settings", "<html><body><form><input></form></body></html>", "<html><body><form><input></form></body></html>", 1)
	if _, added := g.PutIfAbsent(other); !added {
		t.Error("a different template must be a new state")
	}
	if !SameStructure(listPage(20, "carol"), s1) {
		t.Error("SameStructure must accept a clone rendering")
	}
}
