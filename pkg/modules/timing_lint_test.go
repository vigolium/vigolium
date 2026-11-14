package modules

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestActiveModulesDoNotTimeTheQueue (MISS-14) fails when an active module
// wraps Execute in its own wall clock: `time.Since` within a few lines after
// `.Execute(`. Execute's caller-side clock includes the rate token and the
// host-slot wait, which at a low --rate-limit exceeds a sleep payload. Use
// modkit.SendTimed, which returns the requester-measured latency.
func TestActiveModulesDoNotTimeTheQueue(t *testing.T) {
	const window = 6
	root := filepath.Join("active")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !strings.Contains(line, ".Execute(") {
				continue
			}
			for j := i + 1; j <= i+window && j < len(lines); j++ {
				if strings.Contains(lines[j], "time.Since(") {
					offenders = append(offenders, path+":"+strconv.Itoa(j+1))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offenders {
		t.Errorf("%s: time.Since right after Execute measures queue wait; use modkit.SendTimed", o)
	}
}
