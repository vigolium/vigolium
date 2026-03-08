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
}

func NewHTMLAnalyzer(content string) (*HTMLAnalyzer, error) {
	node, err := htmlutils.FastParse(strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	return &HTMLAnalyzer{dom: node}, nil
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
	nodes := htmlutils.GetElementsByElementNode(s.dom, html.DoctypeNode)
	for _, node := range nodes {
		o := htmlutils.OuterHTML(node)
		_, _ = cs.Write(s2b(o))
	}
	nodes = htmlutils.GetElementsByElementNode(s.dom, html.CommentNode)
	for _, node := range nodes {
		_, _ = cs.Write(s2b(strings.TrimSpace(node.Data)))
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getHTMLStructure() uint32 {
	var finder func(*html.Node)
	htmlChecksum := crc32.NewIEEE()

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			_, _ = htmlChecksum.Write(s2b(node.Data))
			_, _ = htmlChecksum.Write(number0Bytes)
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return htmlChecksum.Sum32()
}

func (s *HTMLAnalyzer) getCSSStructure() uint32 {
	var finder func(*html.Node)
	cssChecksum := crc32.NewIEEE()

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if css := htmlutils.GetAttributeTrimSpace(node, "class"); css != "" {
				_, _ = cssChecksum.Write(s2b(css))
				_, _ = cssChecksum.Write(number0Bytes)
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cssChecksum.Sum32()
}
func (s *HTMLAnalyzer) getVisibleTextChecksum() uint32 {
	visibleTextCRC32 := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.TextNode {
			if nodeText := strings.TrimSpace(node.Data); nodeText != "" {
				_, _ = visibleTextCRC32.Write(s2b(nodeText))
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}

	return visibleTextCRC32.Sum32()
}

func (s *HTMLAnalyzer) getVisibleTextCountChecksum() uint32 {
	visibleTextCountCRC32 := crc32.NewIEEE()
	var visibleTextCount int64
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.TextNode {
			if nodeText := strings.TrimSpace(node.Data); nodeText != "" {
				// fmt.Println(nodeText)
				visibleTextCount += int64(countWords(nodeText))
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
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
	tags := htmlutils.GetElementsByTagName(s.dom, "title")
	if len(tags) > 0 {
		tag := tags[0]
		txt := strings.TrimSpace(htmlutils.TextContent(tag))
		return crc32.ChecksumIEEE(s2b(txt))
	}
	return 0
}

func (s *HTMLAnalyzer) getFirstHeaderTagHash() uint32 {
	cs := crc32.NewIEEE()
	found := false
	var finder func(*html.Node)
	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			tn := node.Data
			if tn == "h1" || tn == "h2" || tn == "h3" || tn == "h4" || tn == "h5" || tn == "h6" {
				txt := strings.TrimSpace(htmlutils.TextContent(node))
				if txt != "" {
					_, _ = cs.Write(s2b(txt))
					found = true
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if found {
				break
			}
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		if found {
			break
		}
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getHeaderTags() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)
	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			tn := node.Data
			if tn == "h1" || tn == "h2" || tn == "h3" || tn == "h4" || tn == "h5" || tn == "h6" {
				txt := strings.TrimSpace(htmlutils.TextContent(node))
				if txt != "" {
					_, _ = cs.Write(s2b(txt))
					_, _ = cs.Write(number0Bytes)
					// fmt.Println(txt)
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getDivIdsHash() uint32 {
	cs := crc32.NewIEEE()
	tags := htmlutils.GetElementsByTagName(s.dom, "div")
	if len(tags) > 0 {
		for _, tag := range tags {
			if value := htmlutils.GetAttributeTrimSpace(tag, "id"); value != "" {
				_, _ = cs.Write(s2b(value))
				_, _ = cs.Write(number0Bytes)
				// fmt.Println(value)
			}
		}
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getTagIdsHash() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if idAttr := htmlutils.GetAttributeTrimSpace(node, "id"); idAttr != "" {
				// fmt.Println(idAttr)
				_, _ = cs.Write(s2b(idAttr))
				_, _ = cs.Write(number0Bytes)
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getButtonSubmitLabels() uint32 {
	checksum := crc32.NewIEEE()
	tags := htmlutils.GetElementsByTagName(s.dom, "button")
	if len(tags) > 0 {
		for _, tag := range tags {
			if value := htmlutils.GetAttributeTrimSpace(tag, "type"); strings.EqualFold(value, "submit") {
				if txt := strings.TrimSpace(htmlutils.TextContent(tag)); txt != "" {
					_, _ = checksum.Write(s2b(txt))
					// fmt.Println(txt)
				}
			}
		}
	}
	return checksum.Sum32()
}

func (s *HTMLAnalyzer) getCanonicalLink() uint32 {
	checksum := crc32.NewIEEE()
	tags := htmlutils.GetElementsByTagName(s.dom, "link")
	if len(tags) > 0 {
		for _, tag := range tags {
			if value := htmlutils.GetAttributeTrimSpace(tag, "rel"); strings.EqualFold(value, "canonical") {
				if value = htmlutils.GetAttributeTrimSpace(tag, "href"); value != "" {
					// fmt.Println(value)
					_, _ = checksum.Write(s2b(value))
					_, _ = checksum.Write(number0Bytes)
				}
			}
		}
	}
	return checksum.Sum32()
}

func (s *HTMLAnalyzer) getInputSubmitLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if attr := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(attr, "submit") {
				if value := htmlutils.GetAttributeTrimSpace(node, "value"); value != "" {
					// fmt.Println(value)
					cs.Write(s2b(value))
					cs.Write(number0Bytes)
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getInputImageLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if attr := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(attr, "image") {
				if value := htmlutils.GetAttributeTrimSpace(node, "alt"); value != "" {
					// fmt.Println(value)
					cs.Write(s2b(value))
					cs.Write(number0Bytes)
				}
				if value := htmlutils.GetAttributeTrimSpace(node, "src"); value != "" {
					// fmt.Println(value)
					// cs.Write(s2b(value))
					cs.Write(number0Bytes)
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getAnchorLabelsHash() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			tn := node.Data
			if tn == "a" || tn == "img" {
				if value := htmlutils.GetAttributeTrimSpace(node, "alt"); value != "" {
					// fmt.Println(value)
					cs.Write(s2b(value))
				} else {
					cs.Write(number0Bytes)
				}

				if value := htmlutils.GetAttributeTrimSpace(node, "src"); value != "" {
					// fmt.Println(value)
					cs.Write(s2b(value))
				} else {
					cs.Write(number0Bytes)
				}

				// inner_text
				if value := strings.TrimSpace(htmlutils.TextContent(node)); value != "" {
					// fmt.Println(value)
					cs.Write(s2b(value))
				} else {
					cs.Write(number0Bytes)
				}
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getOutboundEdgeCountHash() uint32 {
	var counter int
	tags := htmlutils.GetElementsByTagName(s.dom, "a")
	for _, tag := range tags {
		counter++ // also counting <a> tags
		if value := htmlutils.GetAttributeTrimSpace(tag, "type"); strings.EqualFold(value, "submit") {
			counter++
		}
	}
	return uint32(counter)
}

func (s *HTMLAnalyzer) getOutboundEdgeTagNamesHash() uint32 {
	cs := crc32.NewIEEE()
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if value := htmlutils.GetAttributeTrimSpace(node, "type"); strings.EqualFold(value, "submit") || strings.EqualFold(value, "image") {
				cs.Write(s2b(node.Data))
				cs.Write(number0Bytes)
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := s.dom.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}
	return cs.Sum32()
}

func (s *HTMLAnalyzer) getNonHiddenFormInputTypesHash() uint32 {
	checksum := crc32.NewIEEE()
	tags := htmlutils.GetElementsByTagName(s.dom, "input")
	if len(tags) > 0 {
		for _, tag := range tags {
			if value := htmlutils.GetAttributeTrimSpace(tag, "type"); value != "" && !strings.EqualFold(value, "hidden") {
				checksum.Write(s2b(value))
				checksum.Write(number0Bytes)
			}
		}
	}
	return checksum.Sum32()
}
