package anomaly

import (
	"errors"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/anomaly/htmlutils"
	"golang.org/x/net/html"
)

var (
	number0Bytes   = []byte("0")
	errInvalidType = errors.New("invalid type")
)

type HTMLAnalyzer struct {
	dom *html.Node
	idx *domIndex // lazily built, single DFS shared by every extractor
}

// domIndex holds the DOM flattened by a single pre-order DFS, so the ~18
// per-attribute extractors can iterate pre-collected slices instead of each
// re-walking the whole tree. The traversal order (pre-order from
// dom.FirstChild, node-then-children) is identical to the original per-extractor
// finders and to htmlutils.GetElementsBy*, so every checksum sees the same nodes
// in the same order and produces byte-identical results.
type domIndex struct {
	elements  []*html.Node            // all ElementNodes, pre-order
	textNodes []*html.Node            // all TextNodes, pre-order
	comments  []*html.Node            // all CommentNodes, pre-order
	doctypes  []*html.Node            // all DoctypeNodes, pre-order
	byTag     map[string][]*html.Node // ElementNodes for the queried tags only (see byTagWanted), pre-order
}

// byTagWanted is the exact set of tags any extractor looks up via elementsByTag.
// Bucketing only these (instead of every distinct tag on the page) keeps byTag
// at a handful of entries rather than one slice per tag kind.
var byTagWanted = map[string]struct{}{
	"title": {}, "div": {}, "button": {}, "link": {}, "a": {}, "input": {},
}

func NewHTMLAnalyzer(content string) (*HTMLAnalyzer, error) {
	node, err := htmlutils.FastParse(strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	return &HTMLAnalyzer{dom: node}, nil
}

// index returns the (lazily built, cached) single-pass DOM index. Building it
// once and reusing it across all GetAttribute calls turns ~18 full tree walks
// per HTML response into one.
func (s *HTMLAnalyzer) index() *domIndex {
	if s.idx != nil {
		return s.idx
	}
	idx := &domIndex{byTag: make(map[string][]*html.Node)}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			idx.elements = append(idx.elements, n)
			if _, want := byTagWanted[n.Data]; want {
				idx.byTag[n.Data] = append(idx.byTag[n.Data], n)
			}
		case html.TextNode:
			idx.textNodes = append(idx.textNodes, n)
		case html.CommentNode:
			idx.comments = append(idx.comments, n)
		case html.DoctypeNode:
			idx.doctypes = append(idx.doctypes, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		walk(child)
	}
	s.idx = idx
	return idx
}

// elementsByTag returns the pre-order element slice for a tag (nil if none),
// matching htmlutils.GetElementsByTagName semantics (exact tag-name match).
func (s *HTMLAnalyzer) elementsByTag(tag string) []*html.Node {
	return s.index().byTag[tag]
}

func isHeaderTag(tn string) bool {
	return tn == "h1" || tn == "h2" || tn == "h3" || tn == "h4" || tn == "h5" || tn == "h6"
}

func (s *HTMLAnalyzer) GetAttribute(t Type) (uint32, error) {
	switch t {
	case TAG_NAMES:
		return s.getHTMLStructure(), nil
	case CSS_CLASSES:
		return s.getCSSStructure(), nil
	case COMMENTS:
		return s.getCommentChecksum(), nil
	case VISIBLE_TEXT:
		return s.getVisibleTextChecksum(), nil
	case VISIBLE_WORD_COUNT:
		return s.getVisibleTextCountChecksum(), nil
	case PAGE_TITLE:
		return s.getTitleHash(), nil
	case FIRST_HEADER_TAG:
		return s.getFirstHeaderTagHash(), nil
	case HEADER_TAGS:
		return s.getHeaderTags(), nil
	case DIV_IDS:
		return s.getDivIdsHash(), nil
	case TAG_IDS:
		return s.getTagIdsHash(), nil
	case BUTTON_SUBMIT_LABELS:
		return s.getButtonSubmitLabels(), nil
	case CANONICAL_LINK:
		return s.getCanonicalLink(), nil
	case INPUT_SUBMIT_LABELS:
		return s.getInputSubmitLabelsHash(), nil
	case INPUT_IMAGE_LABELS:
		return s.getInputImageLabelsHash(), nil
	case ANCHOR_LABELS:
		return s.getAnchorLabelsHash(), nil
	case OUTBOUND_EDGE_COUNT:
		return s.getOutboundEdgeCountHash(), nil
	case OUTBOUND_EDGE_TAG_NAMES:
		return s.getOutboundEdgeTagNamesHash(), nil
	case NON_HIDDEN_FORM_INPUT_TYPES:
		return s.getNonHiddenFormInputTypesHash(), nil
	}
	return 0, errInvalidType
}

func (s *HTMLAnalyzer) getCommentChecksum() uint32 {
	cs := crc32.NewIEEE()
	idx := s.index()
	for _, node := range idx.doctypes {
		o := htmlutils.OuterHTML(node)
		_, _ = cs.Write(s2b(o))
	}
	for _, node := range idx.comments {
		_, _ = cs.Write(s2b(strings.TrimSpace(node.Data)))
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getHTMLStructure() uint32 {
	htmlChecksum := crc32.NewIEEE()
	for _, node := range s.index().elements {
		_, _ = htmlChecksum.Write(s2b(node.Data))
		_, _ = htmlChecksum.Write(number0Bytes)
	}
	return htmlChecksum.Sum32()
}

func (s *HTMLAnalyzer) getCSSStructure() uint32 {
	cssChecksum := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if css := htmlutils.GetAttributeTrimSpace(node, "class"); css != "" {
			_, _ = cssChecksum.Write(s2b(css))
			_, _ = cssChecksum.Write(number0Bytes)
		}
	}
	return cssChecksum.Sum32()
}

func (s *HTMLAnalyzer) getVisibleTextChecksum() uint32 {
	visibleTextCRC32 := crc32.NewIEEE()
	for _, node := range s.index().textNodes {
		if nodeText := strings.TrimSpace(node.Data); nodeText != "" {
			_, _ = visibleTextCRC32.Write(s2b(nodeText))
		}
	}
	return visibleTextCRC32.Sum32()
}

func (s *HTMLAnalyzer) getVisibleTextCountChecksum() uint32 {
	visibleTextCountCRC32 := crc32.NewIEEE()
	var visibleTextCount int64
	for _, node := range s.index().textNodes {
		if nodeText := strings.TrimSpace(node.Data); nodeText != "" {
			visibleTextCount += int64(countWords(nodeText))
		}
	}

	_, _ = visibleTextCountCRC32.Write(s2b(strconv.FormatInt(visibleTextCount, 10))) // 10 == decimal
	return visibleTextCountCRC32.Sum32()
}

func countWords(text string) int {
	count := 0
	inWord := false
	for _, r := range text {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			inWord = false
		} else if !inWord {
			inWord = true
			count++
		}
	}
	return count
}

func (s *HTMLAnalyzer) getTitleHash() uint32 {
	tags := s.elementsByTag("title")
	if len(tags) > 0 {
		tag := tags[0]
		txt := strings.TrimSpace(htmlutils.TextContent(tag))
		return crc32.ChecksumIEEE(s2b(txt))
	}
	return 0
}

func (s *HTMLAnalyzer) getFirstHeaderTagHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if isHeaderTag(node.Data) {
			txt := strings.TrimSpace(htmlutils.TextContent(node))
			if txt != "" {
				_, _ = cs.Write(s2b(txt))
				break // first header tag (document order) with non-empty text
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getHeaderTags() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if isHeaderTag(node.Data) {
			txt := strings.TrimSpace(htmlutils.TextContent(node))
			if txt != "" {
				_, _ = cs.Write(s2b(txt))
				_, _ = cs.Write(number0Bytes)
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getDivIdsHash() uint32 {
	cs := crc32.NewIEEE()
	for _, tag := range s.elementsByTag("div") {
		if value := htmlutils.GetAttributeTrimSpace(tag, "id"); value != "" {
			_, _ = cs.Write(s2b(value))
			_, _ = cs.Write(number0Bytes)
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getTagIdsHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if idAttr := htmlutils.GetAttributeTrimSpace(node, "id"); idAttr != "" {
			_, _ = cs.Write(s2b(idAttr))
			_, _ = cs.Write(number0Bytes)
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getButtonSubmitLabels() uint32 {
	checksum := crc32.NewIEEE()
	for _, tag := range s.elementsByTag("button") {
		if value := htmlutils.GetAttributeTrimSpace(tag, "type"); strings.EqualFold(value, "submit") {
			if txt := strings.TrimSpace(htmlutils.TextContent(tag)); txt != "" {
				_, _ = checksum.Write(s2b(txt))
			}
		}
	}
	return checksum.Sum32()
}

func (s *HTMLAnalyzer) getCanonicalLink() uint32 {
	checksum := crc32.NewIEEE()
	for _, tag := range s.elementsByTag("link") {
		if value := htmlutils.GetAttributeTrimSpace(tag, "rel"); strings.EqualFold(value, "canonical") {
			if value = htmlutils.GetAttributeTrimSpace(tag, "href"); value != "" {
				_, _ = checksum.Write(s2b(value))
				_, _ = checksum.Write(number0Bytes)
			}
		}
	}
	return checksum.Sum32()
}

func (s *HTMLAnalyzer) getInputSubmitLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if attr := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(attr, "submit") {
			if value := htmlutils.GetAttributeTrimSpace(node, "value"); value != "" {
				cs.Write(s2b(value))
				cs.Write(number0Bytes)
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getInputImageLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if attr := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(attr, "image") {
			if value := htmlutils.GetAttributeTrimSpace(node, "alt"); value != "" {
				cs.Write(s2b(value))
				cs.Write(number0Bytes)
			}
			if value := htmlutils.GetAttributeTrimSpace(node, "src"); value != "" {
				// cs.Write(s2b(value))
				cs.Write(number0Bytes)
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getAnchorLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		tn := node.Data
		if tn == "a" || tn == "img" {
			if value := htmlutils.GetAttributeTrimSpace(node, "alt"); value != "" {
				cs.Write(s2b(value))
			} else {
				cs.Write(number0Bytes)
			}

			if value := htmlutils.GetAttributeTrimSpace(node, "src"); value != "" {
				cs.Write(s2b(value))
			} else {
				cs.Write(number0Bytes)
			}

			// inner_text
			if value := strings.TrimSpace(htmlutils.TextContent(node)); value != "" {
				cs.Write(s2b(value))
			} else {
				cs.Write(number0Bytes)
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getOutboundEdgeCountHash() uint32 {
	var counter int
	for _, tag := range s.elementsByTag("a") {
		counter++ // also counting <a> tags
		if value := htmlutils.GetAttributeTrimSpace(tag, "type"); strings.EqualFold(value, "submit") {
			counter++
		}
	}
	return uint32(counter)
}

func (s *HTMLAnalyzer) getOutboundEdgeTagNamesHash() uint32 {
	cs := crc32.NewIEEE()
	for _, node := range s.index().elements {
		if value := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(value, "submit") || strings.EqualFold(value, "image") {
			cs.Write(s2b(node.Data))
			cs.Write(number0Bytes)
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getNonHiddenFormInputTypesHash() uint32 {
	checksum := crc32.NewIEEE()
	for _, tag := range s.elementsByTag("input") {
		if value := htmlutils.GetAttributeTrimSpace(tag, "type"); value != "" && !strings.EqualFold(value, "hidden") {
			checksum.Write(s2b(value))
			checksum.Write(number0Bytes)
		}
	}
	return checksum.Sum32()
}
