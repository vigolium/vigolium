package htmlutils

import (
	"bytes"
	"io"

	"github.com/gogs/chardet"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	xunicode "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// FastParse parses html.Node from the specified reader without caring about
// text encoding. It always assume that the input uses UTF-8 encoding.
func FastParse(r io.Reader) (*html.Node, error) {
	return html.Parse(r)
}

// Parse parses html.Node from the specified reader while converting the character
// encoding into UTF-8. This function is useful to correctly parse web pages that
// uses custom text encoding, e.g. web pages from Asian websites. However, since it
// has to detect charset before parsing, this function is quite slow and expensive
// so if you sure the reader uses valid UTF-8, just use FastParse.
func Parse(r io.Reader) (*html.Node, error) {
	// Split the reader using tee
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Detect page encoding
	res, err := chardet.NewHtmlDetector().DetectBest(content)
	if err != nil {
		return nil, err
	}

	pageEncoding, _ := charset.Lookup(res.Charset)
	if pageEncoding == nil {
		pageEncoding = xunicode.UTF8
	}

	// Parse HTML using the page encoding
	r = bytes.NewReader(content)
	r = transform.NewReader(r, pageEncoding.NewDecoder())
	r = normalizeTextEncoding(r)
	return html.Parse(r)
}

// normalizeTextEncoding convert text encoding from NFD to NFC.
// It also remove soft hyphen since apparently it's useless in web.
// See: https://web.archive.org/web/19990117011731/http://www.hut.fi/~jkorpela/shy.html
func normalizeTextEncoding(r io.Reader) io.Reader {
	fnSoftHyphen := func(r rune) bool { return r == '\u00AD' }
	softHyphenSet := runes.Predicate(fnSoftHyphen)
	transformer := transform.Chain(norm.NFD, runes.Remove(softHyphenSet), norm.NFC)
	return transform.NewReader(r, transformer)
}
