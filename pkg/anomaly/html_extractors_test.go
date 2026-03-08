package anomaly

import (
	"os"
	"testing"
)

func Test_getCommentChecksum(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getCommentChecksum()
	t.Log(a)

}

func Test_getHTMLTagsStructure(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getHTMLStructure()
	t.Log(a)

}
func Test_getVisibleTextChecksum(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getVisibleTextChecksum()
	t.Log(a)
}
func Test_getTitleHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/6.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getTitleHash()
	t.Log(a)
}
func Test_getFirstHeaderTagHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/6.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getFirstHeaderTagHash()
	t.Log(a)
}
func Test_getHeaderTags(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/3.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getHeaderTags()
	t.Log(a)
}
func Test_getDivIdsHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/3.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getDivIdsHash()
	t.Log(a)
}

func Test_getTagIdsHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/3.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(string(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getTagIdsHash()
	t.Log(a)
}

func Test_getButtonSubmitLabels(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/2.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(b2s(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getButtonSubmitLabels()
	t.Log(a)
}

func Test_getCanonicalLink(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/3.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(b2s(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getCanonicalLink()
	t.Log(a)
}

func Test_getInputSubmitLabelsHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/2.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(b2s(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getInputSubmitLabelsHash()
	t.Log(a)
}

func Test_getInputImageLabelsHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(b2s(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getInputImageLabelsHash()
	t.Log(a)
}
func Test_getAnchorLabelsHash(t *testing.T) {
	content, err := os.ReadFile("../../test/pkg-testdata/anomaly/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	analyzer, err := NewHTMLAnalyzer(b2s(content))
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer.getAnchorLabelsHash()
	t.Log(a)
}
