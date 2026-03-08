package authzutil

import (
	"encoding/base64"
	"strconv"
	"testing"
)

func TestGenerateNeighborIDs_SequentialInt(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		count    int
		wantLen  int
		wantHas  []string
		wantNone []string
	}{
		{
			name:    "simple integer",
			value:   "42",
			count:   3,
			wantLen: 3,
			wantHas: []string{"43", "41", "52"},
		},
		{
			name:    "value 1 does not include 1 as neighbor",
			value:   "1",
			count:   3,
			wantLen: 3,
			wantHas: []string{"2", "11"},
		},
		{
			name:     "zero-padded preserves padding",
			value:    "0042",
			count:    3,
			wantLen:  3,
			wantHas:  []string{"0043", "0041", "0052"},
			wantNone: []string{"43", "41"},
		},
		{
			name:    "small value avoids negatives",
			value:   "0",
			count:   5,
			wantHas: []string{"1", "10"},
		},
		{
			name:    "count limit respected",
			value:   "100",
			count:   2,
			wantLen: 2,
		},
		{
			name:    "value 5 generates correct neighbors",
			value:   "5",
			count:   5,
			wantHas: []string{"6", "4", "15", "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateNeighborIDs(tt.value, SequentialInt, tt.count)
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d; got %v", len(got), tt.wantLen, got)
			}
			for _, want := range tt.wantHas {
				if !contains(got, want) {
					t.Errorf("missing expected neighbor %q in %v", want, got)
				}
			}
			for _, bad := range tt.wantNone {
				if contains(got, bad) {
					t.Errorf("should not contain %q in %v", bad, got)
				}
			}
			// Must never contain original
			if contains(got, tt.value) {
				t.Errorf("must not contain original value %q in %v", tt.value, got)
			}
		})
	}
}

func TestGenerateNeighborIDs_StructuredCode(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		count   int
		wantHas []string
	}{
		{
			name:    "standard code",
			value:   "ORD-00042",
			count:   3,
			wantHas: []string{"ORD-00041", "ORD-00043"},
		},
		{
			name:    "multi-segment code uses last segment",
			value:   "INV-001-50",
			count:   3,
			wantHas: []string{"INV-001-49", "INV-001-51"},
		},
		{
			name:    "no padding",
			value:   "USR-100",
			count:   3,
			wantHas: []string{"USR-99", "USR-101"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateNeighborIDs(tt.value, StructuredCode, tt.count)
			for _, want := range tt.wantHas {
				if !contains(got, want) {
					t.Errorf("missing expected neighbor %q in %v", want, got)
				}
			}
			if contains(got, tt.value) {
				t.Errorf("must not contain original value %q", tt.value)
			}
		})
	}
}

func TestGenerateNeighborIDs_Base64Int(t *testing.T) {
	// Encode "42" in standard base64
	encoded42 := base64.StdEncoding.EncodeToString([]byte("42"))

	got := GenerateNeighborIDs(encoded42, Base64Int, 3)
	if len(got) == 0 {
		t.Fatal("expected neighbors for base64-encoded int")
	}

	// Decode each neighbor and verify they are ±1
	for _, neighbor := range got {
		decoded, err := base64.StdEncoding.DecodeString(neighbor)
		if err != nil {
			t.Errorf("failed to decode neighbor %q: %v", neighbor, err)
			continue
		}
		n, err := strconv.ParseInt(string(decoded), 10, 64)
		if err != nil {
			t.Errorf("decoded neighbor %q is not an integer: %v", string(decoded), err)
			continue
		}
		if n != 43 && n != 41 {
			t.Errorf("unexpected neighbor value %d (expected 41 or 43)", n)
		}
	}
}

func TestGenerateNeighborIDs_UUIDv1(t *testing.T) {
	uuid := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	got := GenerateNeighborIDs(uuid, UUIDv1, 3)
	if len(got) == 0 {
		t.Fatal("expected neighbors for UUIDv1")
	}

	// Verify last byte was modified
	for _, neighbor := range got {
		if len(neighbor) != 36 {
			t.Errorf("neighbor UUID has wrong length: %d", len(neighbor))
		}
		// Should share the same prefix
		if neighbor[:34] != uuid[:34] {
			t.Errorf("neighbor prefix changed: %q vs %q", neighbor[:34], uuid[:34])
		}
		if neighbor == uuid {
			t.Error("neighbor should differ from original")
		}
	}
}

func TestGenerateNeighborIDs_UUIDv1_EdgeByte(t *testing.T) {
	// Last byte is 00, so -1 should be skipped (underflow)
	uuid := "6ba7b810-9dad-11d1-80b4-00c04fd43000"
	got := GenerateNeighborIDs(uuid, UUIDv1, 3)
	// Should still produce at least +1
	if len(got) == 0 {
		t.Fatal("expected at least one neighbor")
	}
	for _, neighbor := range got {
		if neighbor == uuid {
			t.Error("must not contain original")
		}
	}
}

func TestGenerateNeighborIDs_Email(t *testing.T) {
	got := GenerateNeighborIDs("john@example.com", Email, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 neighbors, got %d: %v", len(got), got)
	}

	for _, neighbor := range got {
		if neighbor == "john@example.com" {
			t.Error("must not contain original")
		}
		if neighbor[len(neighbor)-12:] != "@example.com" {
			t.Errorf("domain changed: %q", neighbor)
		}
	}
}

func TestGenerateNeighborIDs_Email_AdminOriginal(t *testing.T) {
	// When original is "admin", first candidate is skipped
	got := GenerateNeighborIDs("admin@example.com", Email, 3)
	for _, neighbor := range got {
		if neighbor == "admin@example.com" {
			t.Error("must not contain original")
		}
	}
}

func TestGenerateNeighborIDs_Unpredictable(t *testing.T) {
	tests := []struct {
		name   string
		idType IDType
		value  string
	}{
		{"UUIDv4", UUIDv4, "550e8400-e29b-41d4-a716-446655440000"},
		{"Hex", Hex, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
		{"Unknown", Unknown, "something"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateNeighborIDs(tt.value, tt.idType, 3)
			if got != nil {
				t.Errorf("expected nil for %s, got %v", tt.name, got)
			}
		})
	}
}

func TestGenerateNeighborIDs_EmptyAndZeroCount(t *testing.T) {
	if got := GenerateNeighborIDs("", SequentialInt, 3); got != nil {
		t.Errorf("empty value should return nil, got %v", got)
	}
	if got := GenerateNeighborIDs("42", SequentialInt, 0); got != nil {
		t.Errorf("zero count should return nil, got %v", got)
	}
	if got := GenerateNeighborIDs("42", SequentialInt, -1); got != nil {
		t.Errorf("negative count should return nil, got %v", got)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
