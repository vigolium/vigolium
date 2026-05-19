package tool

import "testing"

func TestIsCatastrophic(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		// Catastrophic
		{"rm -rf /", true},
		{"rm -rf / ", true},
		{"rm -rf /*", true},
		{"rm -rf /*.txt", true},
		{"sudo rm -rf /", true},
		{"rm -rf ~", true},
		{"rm -rf ~/", true},
		{"rm -rf ~/*", true},
		{"rm -rf $HOME", true},
		{"rm -rf $HOME/*", true},
		{"rm -rf ${HOME}", true},
		{"rm -Rf /", true},
		{"rm -fr /", true},
		{":(){:|:&};:", true},
		{"dd if=/dev/zero of=/dev/sda bs=1M", true},
		{"dd if=/dev/zero of=/dev/disk0", true},
		{"mkfs.ext4 /dev/sdb", true},
		{"echo hi > /dev/sda", true},

		// Legitimate (must pass)
		{"rm -rf /tmp/olium-test-victim/sub", false},
		{"rm -rf node_modules", false},
		{"rm -rf ./build", false},
		{"rm -rf /tmp/mycache", false},
		{"rm -f /tmp/foo.txt", false},
		{"rm /tmp/foo.txt", false},
		{"rm -rf ~/projects/scratch", false}, // paths under ~, not ~ itself
		{"rm -rf $HOME/projects/old", false}, // paths under $HOME, not $HOME itself
		{"echo rm -rf /", false},             // literal text, not invocation (quoted/echoed)
		{"dd if=/dev/random of=/tmp/noise bs=1M count=1", false},
		{"mkfs.ext4 disk.img", false}, // disk image file, not a device
	}

	for _, tc := range cases {
		got := IsCatastrophic(tc.cmd)
		if got != tc.want {
			t.Errorf("IsCatastrophic(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}
