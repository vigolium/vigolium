package anomaly

import (
	"os"
	"testing"
)

func TestMimetypeDetector(t *testing.T) {
	m := NewMimetypeDetector(map[string][]string{"content-type": {"text/html;charset=urf-8"}}, readTestFile("../../test/pkg-testdata/anomaly/2.txt"))
	t.Log(m.GetInferredMimeType())
	t.Log(m.GetStatedMimeType())
}

func readTestFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(content)
}
