package network

import "testing"

// A request written while its body fetch failed is provisional: a
// later copy with its body is still written; a further complete copy is a
// duplicate.
func TestWriteEntryProvisionalUpgrade(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:           mock,
		logged:           make(map[string]struct{}),
		seenHashes:       make(map[string]bool),
		shapeVariants:    make(map[string]int),
		maxParamVariants: 3,
		noColor:          true,
	}
	failed := createTestEntry("https://example.com/api/data")
	failed.BodySource = BodySourceFailed
	capture.writeEntry(failed)

	again := createTestEntry("https://example.com/api/data")
	again.BodySource = BodySourceFailed
	capture.writeEntry(again)
	if n := mock.getWriteCount(); n != 1 {
		t.Fatalf("a second body-less copy must be a duplicate; writes = %d", n)
	}

	full := createTestEntry("https://example.com/api/data")
	full.BodySource = BodySourceCDP
	capture.writeEntry(full)
	if n := mock.getWriteCount(); n != 2 {
		t.Fatalf("the complete copy must upgrade the provisional write; writes = %d", n)
	}
	dup := createTestEntry("https://example.com/api/data")
	dup.BodySource = BodySourceCDP
	capture.writeEntry(dup)
	if n := mock.getWriteCount(); n != 2 {
		t.Errorf("a complete repeat is a duplicate; writes = %d", n)
	}
}
