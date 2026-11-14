package mab

import "testing"

// MISS-28c: a new arm whose signature paid off elsewhere starts ahead of an
// unseen one; the memory survives the per-state removal of pulled arms.
func TestSignatureSeedsNewArms(t *testing.T) {
	p := NewMABExp3Policy(10)
	p.AddState("s1")
	p.AddActionWithSignature("s1", "a1", "a|click|next|/page/#")
	_ = p.GetProbability("s1", "a1")
	p.Update("s1", "a1", 1.0)
	p.RemoveAction("s1", "a1")
	if mean, n := p.SignatureMean("a|click|next|/page/#"); n != 1 || mean != 1.0 {
		t.Fatalf("signature mean = %v over %d pulls, want 1.0 over 1", mean, n)
	}

	p.AddState("s2")
	p.AddActionWithSignature("s2", "known", "a|click|next|/page/#")
	p.AddActionWithSignature("s2", "fresh", "button|click|help|")
	pk, pf := p.GetProbability("s2", "known"), p.GetProbability("s2", "fresh")
	if pk <= pf {
		t.Errorf("seeded arm p=%v must exceed unseen arm p=%v", pk, pf)
	}
}
