package storage

import (
	"testing"
)

func TestValidateKey(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    string
	}{
		{"ugc/source.zip", false, "ugc/source.zip"},
		{"native-scans/uuid-123/results.tar.gz", false, "native-scans/uuid-123/results.tar.gz"},
		{"simple.txt", false, "simple.txt"},

		// traversal attacks
		{"../other-project/ugc/secret.zip", true, ""},
		{"../../etc/passwd", true, ""},
		{"ugc/../../other-project/file.zip", true, ""},
		{"ugc/../../../etc/passwd", true, ""},
		{"native-scans/../../other-project/results.tar.gz", true, ""},
		{"..", true, ""},
		{"foo/..", true, ""},
		{"foo/../bar", false, "bar"}, // filepath.Clean normalizes this to "bar" — safe

		// backslash attempts
		{"ugc\\..\\..\\other", true, ""},

		// empty
		{"", true, ""},
	}

	for _, tt := range tests {
		got, err := ValidateKey(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ValidateKey(%q) = %q, nil; want error", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("ValidateKey(%q) error: %v", tt.input, err)
			} else if got != tt.want {
				t.Errorf("ValidateKey(%q) = %q; want %q", tt.input, got, tt.want)
			}
		}
	}
}

func TestValidateProjectUUID(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"my-project", false},
		{"00000000-0000-0000-0000-000000000001", false},

		// traversal attacks
		{"../other-project", true},
		{"foo/bar", true},
		{"foo\\bar", true},
		{"..", true},
		{"", true},
	}

	for _, tt := range tests {
		err := ValidateProjectUUID(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ValidateProjectUUID(%q) = nil; want error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ValidateProjectUUID(%q) error: %v", tt.input, err)
		}
	}
}

func TestParseGCSPath_RejectsTraversal(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"gs://project-uuid/ugc/source.zip", false},
		{"gs://project-uuid/native-scans/uuid/results.tar.gz", false},

		// project UUID traversal
		{"gs://../other-project/ugc/secret.zip", true},
		{"gs://foo/bar/../../other-project/file", true},

		// key traversal
		{"gs://project-uuid/../../etc/passwd", true},
		{"gs://project-uuid/../other-project/ugc/file.zip", true},
	}

	for _, tt := range tests {
		_, _, err := ParseGCSPath(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ParseGCSPath(%q) = nil; want error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ParseGCSPath(%q) error: %v", tt.input, err)
		}
	}
}
