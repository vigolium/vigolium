package htmlutils

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// https://github.com/antchfx/htmlquery
var (
	rxPunctuation      = regexp.MustCompile(`\s+([.?!,;])\s*(\S*)`)
	rxTempNewline      = regexp.MustCompile(`\s*\|\\/\|\s*`)
	rxDisplayNone      = regexp.MustCompile(`(?i)display:\s*none`)
	rxVisibilityHidden = regexp.MustCompile(`(?i)visibility:\s*(:?hidden|collapse)`)
)

// QuerySelectorAll returns array of document's elements that match
// the specified group of selectors.
func QuerySelectorAll(doc *html.Node, selectors string) []*html.Node {
	matcher, err := cascadia.ParseGroup(selectors)
	if err != nil {
		return nil
	}

	return cascadia.QueryAll(doc, matcher)
}

// QuerySelector returns the first document's element that match
// the specified group of selectors.
func QuerySelector(doc *html.Node, selectors string) *html.Node {
	matcher, err := cascadia.ParseGroup(selectors)
	if err != nil {
		return nil
	}

	return cascadia.Query(doc, matcher)
}

// GetElementByID returns a Node object representing the element whose id
// property matches the specified string.
func GetElementByID(doc *html.Node, id string) *html.Node {
	if id == "" {
		return nil
	}

	var results []*html.Node
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		nodeID := GetAttribute(node, "id")
		nodeID = strings.TrimSpace(nodeID)

		if node.Type == html.ElementNode && nodeID == id {
			results = append(results, node)
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}

	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		finder(child)

		if len(results) > 0 {
			return results[0]
		}
	}

	return nil
}

// GetElementsByClassName returns an array of all child elements which
// have all of the given class name(s).
func GetElementsByClassName(doc *html.Node, classNames string) []*html.Node {
	// Convert class name to map
	classes := map[string]struct{}{}
	for _, class := range strings.Fields(classNames) {
		classes[class] = struct{}{}
	}

	nClasses := len(classes)
	if nClasses == 0 {
		return nil
	}

	// Create finder method
	var results []*html.Node
	var finder func(*html.Node)
	var allClassExist = func(node *html.Node) bool {
		matchCount := 0
		nodeClasses := GetAttribute(node, "class")
		for _, nodeClass := range strings.Fields(nodeClasses) {
			if _, exist := classes[nodeClass]; exist {
				matchCount++
			}
		}

		return matchCount == nClasses
	}

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode && allClassExist(node) {
			results = append(results, node)
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}

	// Check all nodes
	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}

	return results
}

// GetElementsByTagName returns a collection of all elements in the document with
// the specified tag name, as an array of Node object.
// The special tag "*" will represents all elements.
func GetElementsByTagName(doc *html.Node, tagName string) []*html.Node {
	var results []*html.Node
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == html.ElementNode && (tagName == "*" || node.Data == tagName) {
			results = append(results, node)
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}

	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}

	return results
}

func GetElementsByElementNode(doc *html.Node, nodeType html.NodeType) []*html.Node {
	var results []*html.Node
	var finder func(*html.Node)

	finder = func(node *html.Node) {
		if node.Type == nodeType {
			results = append(results, node)
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}
	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		finder(child)
	}

	return results
}

// CreateElement creates a new ElementNode with specified tag.
func CreateElement(tagName string) *html.Node {
	return &html.Node{
		Type: html.ElementNode,
		Data: tagName,
	}
}

// CreateTextNode creates a new Text node.
func CreateTextNode(data string) *html.Node {
	return &html.Node{
		Type: html.TextNode,
		Data: data,
	}
}

// TagName returns the tag name of a Node.
// If it's not ElementNode, return empty string.
func TagName(node *html.Node) string {
	if node == nil {
		return ""
	}

	if node.Type != html.ElementNode {
		return ""
	}

	return node.Data
}

// GetAttribute returns the value of a specified attribute on
// the element. If the given attribute does not exist, the value
// returned will be an empty string.
func GetAttribute(node *html.Node, attrName string) string {
	for i := 0; i < len(node.Attr); i++ {
		if node.Attr[i].Key == attrName {
			return node.Attr[i].Val
		}
	}
	return ""
}

func GetAttributeTrimSpace(node *html.Node, attrName string) string {
	return strings.TrimSpace(GetAttribute(node, attrName))
}

// SetAttribute sets attribute for node. If attribute already exists,
// it will be replaced.
func SetAttribute(node *html.Node, attrName string, attrValue string) {
	attrIdx := -1
	for i := 0; i < len(node.Attr); i++ {
		if node.Attr[i].Key == attrName {
			attrIdx = i
			break
		}
	}

	if attrIdx >= 0 {
		node.Attr[attrIdx].Val = attrValue
	} else {
		node.Attr = append(node.Attr, html.Attribute{
			Key: attrName,
			Val: attrValue,
		})
	}
}

// RemoveAttribute removes attribute with given name.
func RemoveAttribute(node *html.Node, attrName string) {
	attrIdx := -1
	for i := 0; i < len(node.Attr); i++ {
		if node.Attr[i].Key == attrName {
			attrIdx = i
			break
		}
	}

	if attrIdx >= 0 {
		a := node.Attr
		a = append(a[:attrIdx], a[attrIdx+1:]...)
		node.Attr = a
	}
}

// HasAttribute returns a Boolean value indicating whether the
// specified node has the specified attribute or not.
func HasAttribute(node *html.Node, attrName string) bool {
	for i := 0; i < len(node.Attr); i++ {
		if node.Attr[i].Key == attrName {
			return true
		}
	}
	return false
}

// TextContent returns the text content of the specified node,
// and all its descendants.
func TextContent(node *html.Node) string {
	var buffer bytes.Buffer
	var finder func(*html.Node)

	finder = func(n *html.Node) {
		if n.Type == html.TextNode {
			buffer.WriteString(n.Data)
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}

	finder(node)
	return buffer.String()
}

// InnerText in JS used to capture text from an element while excluding text from hidden
// children. A child is hidden if it's computed width is 0, whether because its CSS (e.g
// `display: none`, `visibility: hidden`, etc), or if the child has `hidden` attribute.
// Since we can't compute stylesheet, we only look at `hidden` attribute and inline style.
//
// Besides excluding text from hidden children, difference between this function and
// `TextContent` is the latter will skip <br> tag while this function will preserve
// <br> as newline.
func InnerText(node *html.Node) string {
	var buffer bytes.Buffer
	var finder func(*html.Node)

	finder = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			buffer.WriteString(" " + n.Data + " ")

		case html.ElementNode:
			if n.Data == "br" {
				buffer.WriteString(`|\/|`)
				return
			}

			if HasAttribute(n, "hidden") {
				return
			}

			styleAttr := GetAttribute(n, "style")
			if rxDisplayNone.MatchString(styleAttr) || rxVisibilityHidden.MatchString(styleAttr) {
				return
			}
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			finder(child)
		}
	}

	finder(node)
	text := buffer.String()
	text = strings.Join(strings.Fields(text), " ")
	text = rxPunctuation.ReplaceAllString(text, "$1 $2")
	text = rxTempNewline.ReplaceAllString(text, "\n")
	return text
}

// OuterHTML returns an HTML serialization of the element and its descendants.
// The returned HTML value is escaped.
func OuterHTML(node *html.Node) string {
	if node == nil {
		return ""
	}

	var buffer bytes.Buffer
	err := html.Render(&buffer, node)
	if err != nil {
		return ""
	}

	return buffer.String()
}

// InnerHTML returns the HTML content (inner HTML) of an element.
// The returned HTML value is escaped.
func InnerHTML(node *html.Node) string {
	var err error
	var buffer bytes.Buffer

	if node == nil {
		return ""
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		err = html.Render(&buffer, child)
		if err != nil {
			return ""
		}
	}

	return strings.TrimSpace(buffer.String())
}

// func GetNodeTagName(node *html.Node) string {
//
// }

// DocumentElement returns the Element that is the root element
// of the document. Since we are working with HTML document,
// the root will be <html> element for HTML documents).
func DocumentElement(doc *html.Node) *html.Node {
	if nodes := GetElementsByTagName(doc, "html"); len(nodes) > 0 {
		return nodes[0]
	}
	return nil
}

// ID returns the value of the id attribute of the specified element.
func ID(node *html.Node) string {
	id := GetAttribute(node, "id")
	id = strings.TrimSpace(id)
	return id
}

// ClassName returns the value of the class attribute of
// the specified element.
func ClassName(node *html.Node) string {
	className := GetAttribute(node, "class")
	className = strings.TrimSpace(className)
	className = strings.Join(strings.Fields(className), " ")
	return className
}

// Children returns an HTMLCollection of the direct child elements of Node.
func Children(node *html.Node) []*html.Node {
	var children []*html.Node
	if node == nil {
		return nil
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			children = append(children, child)
		}
	}

	return children
}

// ChildNodes returns list of a node's direct children.
func ChildNodes(node *html.Node) []*html.Node {
	var childNodes []*html.Node
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		childNodes = append(childNodes, child)
	}
	return childNodes
}

// FirstElementChild returns the object's first child Element,
// or nil if there are no child elements.
func FirstElementChild(node *html.Node) *html.Node {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			return child
		}
	}
	return nil
}

// PreviousElementSibling returns the the Element immediately prior
// to the specified one in its parent's children list, or null if
// the specified element is the first one in the list.
func PreviousElementSibling(node *html.Node) *html.Node {
	for sibling := node.PrevSibling; sibling != nil; sibling = sibling.PrevSibling {
		if sibling.Type == html.ElementNode {
			return sibling
		}
	}
	return nil
}

// NextElementSibling returns the Element immediately following
// the specified one in its parent's children list, or nil if the
// specified Element is the last one in the list.
func NextElementSibling(node *html.Node) *html.Node {
	for sibling := node.NextSibling; sibling != nil; sibling = sibling.NextSibling {
		if sibling.Type == html.ElementNode {
			return sibling
		}
	}
	return nil
}

// AppendChild adds a node to the end of the list of children of a
// specified parent node. If the given child is a reference to an
// existing node in the document, AppendChild() moves it from its
// current position to the new position.
func AppendChild(node *html.Node, child *html.Node) {
	// Make sure node is not void
	if !IsVoidElement(node) {
		detachChild(child)
		node.AppendChild(child)
	}
}

// PrependChild works like AppendChild() except it adds a node to the
// beginning of the list of children of a specified parent node.
func PrependChild(node *html.Node, child *html.Node) {
	// Make sure node is not void
	if !IsVoidElement(node) {
		detachChild(child)
		if node.FirstChild != nil {
			node.InsertBefore(child, node.FirstChild)
		} else {
			node.AppendChild(child)
		}
	}
}

// ReplaceChild replaces oldChild with newChild under parent, first detaching
// newChild from its current position. It returns (newChild, oldChild) unchanged
// when the replacement cannot be performed: a nil/void parent, a nil oldChild,
// or an oldChild that is not actually a child of parent.
func ReplaceChild(parent *html.Node, newChild *html.Node, oldChild *html.Node) (*html.Node, *html.Node) {
	// Parent must be specified and able to hold children (not a void element).
	// The order matters: IsVoidElement dereferences its argument, so we must
	// short-circuit on nil with ||. The previous `parent == nil && !IsVoidElement`
	// form both inverted the void check and panicked on a nil parent.
	if parent == nil || IsVoidElement(parent) {
		return newChild, oldChild
	}

	// oldChild must exist and actually be a child of parent.
	if oldChild == nil || oldChild.Parent != parent {
		return newChild, oldChild
	}

	// Detach the new child
	detachChild(newChild)
	parent.InsertBefore(newChild, oldChild)
	parent.RemoveChild(oldChild)
	return newChild, oldChild
}

// IncludeNode determines if node is included inside nodeList.
func IncludeNode(nodeList []*html.Node, node *html.Node) bool {
	for i := 0; i < len(nodeList); i++ {
		if nodeList[i] == node {
			return true
		}
	}
	return false
}

// Clone returns a clone of the node and (if specified) its children.
// However, it will be detached from the original's parents and siblings.
func Clone(src *html.Node, deep bool) *html.Node {
	clone := &html.Node{
		Type:     src.Type,
		DataAtom: src.DataAtom,
		Data:     src.Data,
		Attr:     append([]html.Attribute{}, src.Attr...),
	}

	if deep {
		for child := src.FirstChild; child != nil; child = child.NextSibling {
			clone.AppendChild(Clone(child, deep))
		}
	}

	return clone
}

// GetAllNodesWithTag is wrapper for GetElementsByTagName()
// which allow to get several tags at once.
func GetAllNodesWithTag(node *html.Node, tagNames ...string) []*html.Node {
	var result []*html.Node
	for i := 0; i < len(tagNames); i++ {
		result = append(result, GetElementsByTagName(node, tagNames[i])...)
	}
	return result
}

// ForEachNode iterates over a NodeList and runs fn on each node.
func ForEachNode(nodeList []*html.Node, fn func(*html.Node, int)) {
	for i := 0; i < len(nodeList); i++ {
		fn(nodeList[i], i)
	}
}

// RemoveNodes iterates over a NodeList, calls `filterFn` for each node
// and removes node if function returned `true`. If function is not
// passed, removes all the nodes in node list.
func RemoveNodes(nodeList []*html.Node, filterFn func(*html.Node) bool) {
	for i := len(nodeList) - 1; i >= 0; i-- {
		node := nodeList[i]
		parentNode := node.Parent
		if parentNode != nil && (filterFn == nil || filterFn(node)) {
			parentNode.RemoveChild(node)
		}
	}
}

// SetTextContent sets the text content of the specified node.
func SetTextContent(node *html.Node, text string) {
	if IsVoidElement(node) {
		return
	}

	child := node.FirstChild
	for child != nil {
		nextSibling := child.NextSibling
		node.RemoveChild(child)
		child = nextSibling
	}

	node.AppendChild(&html.Node{
		Type: html.TextNode,
		Data: text,
	})
}

// SetInnerHTML sets inner HTML of the specified node.
func SetInnerHTML(node *html.Node, rawHTML string) {
	// Parse raw HTML
	parsedHTML, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil || parsedHTML == nil {
		return
	}

	// Remove node's current children
	child := node.FirstChild
	for child != nil {
		nextSibling := child.NextSibling
		node.RemoveChild(child)
		child = nextSibling
	}

	// Put content of parsed HTML to the node
	if body := QuerySelector(parsedHTML, "body"); body != nil {
		bodyChild := body.FirstChild
		for bodyChild != nil {
			nextSibling := bodyChild.NextSibling
			AppendChild(node, bodyChild)
			bodyChild = nextSibling
		}
	}
}

// IsVoidElement check whether a node can have any contents or not.
// Return true if element is void (can't have any children).
func IsVoidElement(n *html.Node) bool {
	// If it's not element, it's void
	if n.Type != html.ElementNode {
		return true
	}

	// Check tag name
	switch n.Data {
	case "area", "base", "br", "col", "embed", "hr",
		"img", "input", "keygen", "link", "meta",
		"param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}

func detachChild(child *html.Node) {
	if child.Parent != nil || child.PrevSibling != nil || child.NextSibling != nil {
		if child.Parent != nil {
			if child.Parent.FirstChild == child {
				child.Parent.FirstChild = child.NextSibling
			}

			if child.Parent.LastChild == child {
				child.Parent.LastChild = child.PrevSibling
			}
		}

		if child.PrevSibling != nil {
			child.PrevSibling.NextSibling = child.NextSibling
		}

		if child.NextSibling != nil {
			child.NextSibling.PrevSibling = child.PrevSibling
		}

		child.Parent = nil
		child.PrevSibling = nil
		child.NextSibling = nil
	}
}
