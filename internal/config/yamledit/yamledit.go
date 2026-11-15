// Package yamledit edits a YAML file in place, as text, so everything the edit
// does not touch stays byte-identical: comments, blank lines, key order, quoting
// and, most importantly, `${VAR}` placeholders.
//
// The config writers must never load a file through the environment-expanding
// loader and marshal the result back: that writes every expanded secret in clear
// and freezes every `${VAR:-default}`. They parse the raw file with Parse, edit
// the node tree through Doc's helpers, and write Doc.Bytes back.
//
// How the text is produced: each helper records which part of the source it
// changed. A scalar replaced by a scalar is rewritten in its own span on its own
// line. A new key is encoded on its own and inserted after the last entry of its
// mapping, at that mapping's indentation. Anything else (a list or map value, a
// flow collection, a deleted key) re-encodes just that entry's lines. The
// spliced text is then parsed again and compared with the edited tree; if the
// two disagree, the whole tree is re-encoded instead, which keeps comments but
// not blank lines. A wrong splice can therefore cost formatting, never content.
package yamledit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"bufio"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

// Doc is a parsed YAML document plus the text edits made to it so far.
type Doc struct {
	src     []byte
	lines   []string // source lines without their "\n"
	trailNL bool     // source ended with "\n"
	crlf    bool
	doc     *yaml.Node // DocumentNode
	root    *yaml.Node // the top-level mapping
	indent  int

	parents map[*yaml.Node]owner // original nodes only
	edits   []*edit
	seq     int
	full    bool // re-encode the whole tree instead of splicing

	reencoded bool // the last Bytes call re-encoded the whole tree
}

// owner is where a node sits: its parent container and, in a mapping, its key.
type owner struct {
	parent *yaml.Node
	key    *yaml.Node
}

type editKind int

const (
	editSpan   editKind = iota // replace bytes [col0,col1) of one line
	editLines                  // replace lines [line0,line1] (1-based, inclusive)
	editInsert                 // insert lines after line0 (0 = top of file)
)

type edit struct {
	kind         editKind
	node         *yaml.Node // what the edit renders; coverage is decided on it
	line0, line1 int
	col0, col1   int // byte offsets within the line, for editSpan
	seq          int
	render       func() ([]string, error)
}

// Parse parses src for editing. An empty or comment-only document becomes an
// empty mapping; a document whose top level is not a mapping is an error.
func Parse(src []byte) (*Doc, error) {
	d := &Doc{src: src, parents: map[*yaml.Node]owner{}, indent: 2}
	text := string(src)
	d.crlf = strings.Contains(text, "\r\n")
	if d.crlf {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	d.trailNL = strings.HasSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\n")
	if text != "" {
		d.lines = strings.Split(text, "\n")
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	switch {
	case doc.Kind == 0:
		// Empty or comment-only: a new top-level mapping appended at the end.
		d.doc = &yaml.Node{Kind: yaml.DocumentNode}
		d.root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		d.doc.Content = []*yaml.Node{d.root}
		d.parents[d.root] = owner{}
		return d, nil
	case len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode:
		d.doc = &doc
		d.root = doc.Content[0]
	case len(doc.Content) == 1 && isNull(doc.Content[0]):
		d.doc = &doc
		d.root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content[0] = d.root
		d.full = true
	default:
		return nil, errors.New("the top level of the document is not a mapping")
	}
	d.indexParents(d.root, owner{})
	d.indent = detectIndent(d.root)
	return d, nil
}

func (d *Doc) indexParents(n *yaml.Node, o owner) {
	d.parents[n] = o
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			d.parents[n.Content[i]] = owner{parent: n}
			d.indexParents(n.Content[i+1], owner{parent: n, key: n.Content[i]})
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			d.indexParents(c, owner{parent: n})
		}
	}
}

// detectIndent returns the step between the first block mapping key and its
// first nested block mapping key, or 2.
func detectIndent(root *yaml.Node) int {
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if v.Kind == yaml.MappingNode && v.Style&yaml.FlowStyle == 0 && len(v.Content) > 0 {
			if step := v.Content[0].Column - k.Column; step > 0 && step <= 8 {
				return step
			}
		}
	}
	return 2
}

// Get returns the value node at path, or nil when any segment is missing or
// passes through something that is not a mapping.
func (d *Doc) Get(path []string) *yaml.Node {
	n := d.root
	for _, seg := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		_, n = lookup(n, seg)
	}
	return n
}

func lookup(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || (n.Tag == "" && (n.Value == "" || n.Value == "~" || n.Value == "null")))
}

// Node encodes a Go value as a detached node, for Set and AppendUnique.
func Node(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// Set writes value at path, creating missing mappings on the way. A null on the
// way is replaced by a mapping; any other non-mapping is an error.
func (d *Doc) Set(path []string, value *yaml.Node) error {
	if len(path) == 0 {
		return errors.New("empty path")
	}
	value = clean(value)
	m := d.root
	for i, seg := range path[:len(path)-1] {
		k, v := lookup(m, seg)
		if k == nil {
			return d.insertKey(m, seg, chain(path[i+1:], value))
		}
		if v.Kind == yaml.AliasNode && v.Alias != nil && v.Alias.Kind == yaml.MappingNode {
			// Editing through an alias would edit the anchor; give this key its own copy.
			cp := deepCopy(v.Alias)
			cp.Anchor = ""
			d.replaceValue(m, k, v, cp)
			v = cp
		}
		if v.Kind != yaml.MappingNode {
			if !isNull(v) {
				return fmt.Errorf("%s is not a mapping", strings.Join(path[:i+1], "."))
			}
			sub := chain(path[i+1:], value)
			d.replaceValue(m, k, v, sub)
			return nil
		}
		m = v
	}
	leaf := path[len(path)-1]
	k, v := lookup(m, leaf)
	if k == nil {
		return d.insertKey(m, leaf, value)
	}
	if v.Kind == yaml.ScalarNode && value.Kind == yaml.ScalarNode {
		d.replaceScalar(m, k, v, value)
		return nil
	}
	if (v.Kind == yaml.SequenceNode || v.Kind == yaml.MappingNode) && v.Style&yaml.FlowStyle != 0 && value.Kind == v.Kind {
		// Keep a flow collection in flow style: `[all]` stays on its line.
		value.Style |= yaml.FlowStyle
	}
	if value.LineComment == "" {
		value.LineComment = v.LineComment
	}
	d.replaceValue(m, k, v, value)
	return nil
}

// Delete removes the key at path. It reports whether the key existed.
func (d *Doc) Delete(path []string) (bool, error) {
	if len(path) == 0 {
		return false, errors.New("empty path")
	}
	m := d.Get(path[:len(path)-1])
	if m == nil || m.Kind != yaml.MappingNode {
		return false, nil
	}
	idx := -1
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == path[len(path)-1] {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	k, v := m.Content[idx], m.Content[idx+1]
	m.Content = append(m.Content[:idx], m.Content[idx+2:]...)
	if m.Line == 0 || k.Line == 0 {
		return true, nil
	}
	if len(m.Content) == 0 || m.Style&yaml.FlowStyle != 0 {
		// An emptied block mapping must become `{}`, not a null.
		if len(m.Content) == 0 {
			m.Style |= yaml.FlowStyle
		}
		d.replaceNode(m)
		return true, nil
	}
	d.addEntryEdit(m, k, v)
	return true, nil
}

// AppendUnique appends the items that the sequence at path does not already
// hold (compared by scalar value) and returns how many it added. A missing or
// null key becomes a new block sequence.
func (d *Doc) AppendUnique(path []string, items ...*yaml.Node) (int, error) {
	v := d.Get(path)
	if v == nil || isNull(v) {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		seq.Content = uniqueScalars(nil, items)
		if len(seq.Content) == 0 {
			return 0, nil
		}
		return len(seq.Content), d.Set(path, seq)
	}
	if v.Kind != yaml.SequenceNode {
		return 0, fmt.Errorf("%s is not a list", strings.Join(path, "."))
	}
	add := uniqueScalars(v.Content, items)
	if len(add) == 0 {
		return 0, nil
	}
	lastOrig := lastOriginal(v.Content, 1)
	v.Content = append(v.Content, add...)
	if v.Line == 0 {
		return len(add), nil
	}
	o := d.parents[v]
	if v.Style&yaml.FlowStyle != 0 || lastOrig == nil || o.key == nil || o.parent.Style&yaml.FlowStyle != 0 {
		d.replaceNode(v)
		return len(add), nil
	}
	dash, ok := d.dashColumn(lastOrig)
	if !ok {
		d.replaceNode(v)
		return len(add), nil
	}
	end := d.entryEnd(o.key, v)
	d.addEdit(&edit{kind: editInsert, node: v, line0: end, render: func() ([]string, error) {
		var out []string
		for _, it := range v.Content {
			if it.Line != 0 {
				continue
			}
			text, err := encodeInline(it)
			if err != nil {
				return nil, err
			}
			out = append(out, strings.Repeat(" ", dash)+"- "+text)
		}
		return out, nil
	}})
	return len(add), nil
}

// RemoveItems removes every scalar item of the sequence at path whose value is
// in values and returns how many it removed.
func (d *Doc) RemoveItems(path []string, values ...string) (int, error) {
	v := d.Get(path)
	if v == nil || isNull(v) {
		return 0, nil
	}
	if v.Kind != yaml.SequenceNode {
		return 0, fmt.Errorf("%s is not a list", strings.Join(path, "."))
	}
	drop := make(map[string]bool, len(values))
	for _, s := range values {
		drop[s] = true
	}
	kept := v.Content[:0:0]
	removed := 0
	for _, it := range v.Content {
		if it.Kind == yaml.ScalarNode && drop[it.Value] {
			removed++
			continue
		}
		kept = append(kept, it)
	}
	if removed == 0 {
		return 0, nil
	}
	v.Content = kept
	if len(kept) == 0 {
		v.Style |= yaml.FlowStyle
	}
	if v.Line != 0 {
		d.replaceNode(v)
	}
	return removed, nil
}

func uniqueScalars(have, items []*yaml.Node) []*yaml.Node {
	seen := map[string]bool{}
	for _, h := range have {
		if h.Kind == yaml.ScalarNode {
			seen[h.Value] = true
		}
	}
	var out []*yaml.Node
	for _, it := range items {
		it = clean(it)
		if it.Kind == yaml.ScalarNode {
			if seen[it.Value] {
				continue
			}
			seen[it.Value] = true
		}
		out = append(out, it)
	}
	return out
}

// lastOriginal returns the last node of content (stepping by step) that came
// from the source.
func lastOriginal(content []*yaml.Node, step int) *yaml.Node {
	for i := len(content) - step; i >= 0; i -= step {
		if content[i].Line != 0 {
			return content[i]
		}
	}
	return nil
}

// chain wraps value in one mapping per path segment.
func chain(path []string, value *yaml.Node) *yaml.Node {
	if len(path) == 0 {
		return value
	}
	inner := chain(path[1:], value)
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{scalarKey(path[0]), inner}}
}

func scalarKey(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// clean returns n with its DocumentNode wrapper (if any) removed.
func clean(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

// replaceScalar rewrites scalar v (the value of k in m) in place.
func (d *Doc) replaceScalar(m, k, v, value *yaml.Node) {
	oldStyle := v.Style
	span, spanOK := d.scalarSpan(v)
	v.Value = value.Value
	v.Tag = value.Tag
	switch {
	case value.Style != 0:
		v.Style = value.Style
	case value.Tag == "!!str" && oldStyle&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0:
		v.Style = oldStyle
	default:
		v.Style = 0
	}
	if v.Line == 0 {
		return
	}
	if m.Style&yaml.FlowStyle != 0 || !spanOK {
		d.replaceValue(m, k, v, v)
		return
	}
	if probe, err := encodeInline(v); err != nil || strings.Contains(probe, "\n") {
		d.replaceValue(m, k, v, v)
		return
	}
	d.addEdit(&edit{kind: editSpan, node: v, line0: v.Line, col0: span[0], col1: span[1],
		render: func() ([]string, error) {
			text, err := encodeInline(v)
			return []string{text}, err
		}})
}

// scalarSpan returns the byte range of scalar v's source text on its line, or
// false for anything but a single-line plain or quoted scalar.
func (d *Doc) scalarSpan(v *yaml.Node) ([2]int, bool) {
	if v.Line == 0 || v.Line > len(d.lines) || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return [2]int{}, false
	}
	if v.Anchor != "" || (v.Style&yaml.TaggedStyle) != 0 {
		return [2]int{}, false
	}
	line := strings.TrimSuffix(d.lines[v.Line-1], "\r")
	start, ok := byteOffset(line, v.Column-1)
	if !ok || start >= len(line) {
		return [2]int{}, false
	}
	switch {
	case v.Style&yaml.DoubleQuotedStyle != 0:
		if line[start] != '"' {
			return [2]int{}, false
		}
		for i := start + 1; i < len(line); i++ {
			switch line[i] {
			case '\\':
				i++
			case '"':
				return [2]int{start, i + 1}, true
			}
		}
		return [2]int{}, false
	case v.Style&yaml.SingleQuotedStyle != 0:
		if line[start] != '\'' {
			return [2]int{}, false
		}
		for i := start + 1; i < len(line); i++ {
			if line[i] == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				return [2]int{start, i + 1}, true
			}
		}
		return [2]int{}, false
	default:
		end := len(line)
		if i := strings.Index(line[start:], " #"); i >= 0 {
			end = start + i
		}
		if i := strings.Index(line[start:], "\t#"); i >= 0 && start+i < end {
			end = start + i
		}
		end = start + len(strings.TrimRight(line[start:end], " \t"))
		if end <= start {
			return [2]int{}, false
		}
		return [2]int{start, end}, true
	}
}

// byteOffset converts a 0-based rune column to a byte offset in line.
func byteOffset(line string, col int) (int, bool) {
	if col < 0 {
		return 0, false
	}
	n := 0
	for i := range line {
		if n == col {
			return i, true
		}
		n++
	}
	if n == col {
		return len(line), true
	}
	return 0, false
}

// replaceValue sets the value of key k in mapping m to value and records the
// entry's lines for re-encoding.
func (d *Doc) replaceValue(m, k, old, value *yaml.Node) {
	for i := 1; i < len(m.Content); i += 2 {
		if m.Content[i] == old {
			m.Content[i] = value
		}
	}
	if m.Line == 0 || k.Line == 0 {
		return
	}
	if m.Style&yaml.FlowStyle != 0 {
		d.replaceNode(m)
		return
	}
	d.addEntryEdit(m, k, old)
}

// addEntryEdit records that the lines of the entry k (in block mapping m,
// whose source value was old) are re-encoded from whatever value k holds when
// the document is rendered, or removed when k is gone by then.
func (d *Doc) addEntryEdit(m, k, old *yaml.Node) {
	end := d.entryEnd(k, old)
	indent := k.Column - 1
	d.addEdit(&edit{kind: editLines, node: old, line0: k.Line, line1: end, render: func() ([]string, error) {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i] == k {
				return d.encodeEntry(k, m.Content[i+1], indent, true)
			}
		}
		return nil, nil
	}})
}

// replaceNode re-encodes the entry that holds n, climbing out of flow
// collections and sequences to the nearest block-mapping entry. With no such
// entry the whole document is re-encoded.
func (d *Doc) replaceNode(n *yaml.Node) {
	for {
		o, ok := d.parents[n]
		if !ok || o.parent == nil {
			d.full = true
			return
		}
		p := o.parent
		if p.Kind == yaml.MappingNode && p.Style&yaml.FlowStyle == 0 && o.key != nil {
			d.addEntryEdit(p, o.key, n)
			return
		}
		n = p
	}
}

// insertKey appends key: value to mapping m.
func (d *Doc) insertKey(m *yaml.Node, key string, value *yaml.Node) error {
	if m.Kind != yaml.MappingNode {
		return errors.New("not a mapping")
	}
	lastKey := lastOriginal(m.Content, 2)
	wasEmpty := len(m.Content) == 0
	m.Content = append(m.Content, scalarKey(key), value)
	if m.Line == 0 && m != d.root {
		return nil
	}
	if m.Style&yaml.FlowStyle != 0 {
		if wasEmpty {
			m.Style &^= yaml.FlowStyle
		}
		d.replaceNode(m)
		return nil
	}
	line, indent := len(d.lines), 0
	if lastKey != nil {
		_, lastVal := lookup(m, lastKey.Value)
		line, indent = d.entryEnd(lastKey, lastVal), lastKey.Column-1
	} else if m != d.root {
		d.replaceNode(m)
		return nil
	}
	d.addEdit(&edit{kind: editInsert, node: m, line0: line, render: func() ([]string, error) {
		var out []string
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Line != 0 {
				continue
			}
			lines, err := d.encodeEntry(m.Content[i], m.Content[i+1], indent, false)
			if err != nil {
				return nil, err
			}
			out = append(out, lines...)
		}
		return out, nil
	}})
	return nil
}

// entryEnd returns the last source line of the mapping entry whose key is k:
// the last non-blank, non-comment line indented deeper than k (or, for a
// block sequence written at k's own indentation, the last of its items).
func (d *Doc) entryEnd(k, v *yaml.Node) int {
	keyIndent := k.Column - 1
	sameIndentSeq := v != nil && v.Kind == yaml.SequenceNode && v.Style&yaml.FlowStyle == 0
	end := k.Line
	for ln := k.Line + 1; ln <= len(d.lines); ln++ {
		s := strings.TrimSuffix(d.lines[ln-1], "\r")
		trimmed := strings.TrimSpace(s)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := len(s) - len(strings.TrimLeft(s, " "))
		if ind > keyIndent {
			end = ln
			continue
		}
		if ind == keyIndent && sameIndentSeq && (trimmed == "-" || strings.HasPrefix(trimmed, "- ")) {
			end = ln
			continue
		}
		break
	}
	return end
}

// dashColumn returns the byte column of the "-" that introduces sequence item
// it, when the item starts on its own dash line.
func (d *Doc) dashColumn(it *yaml.Node) (int, bool) {
	if it.Line == 0 || it.Line > len(d.lines) {
		return 0, false
	}
	line := strings.TrimSuffix(d.lines[it.Line-1], "\r")
	pos, ok := byteOffset(line, it.Column-1)
	if !ok {
		return 0, false
	}
	for i := pos - 1; i >= 0; i-- {
		switch line[i] {
		case ' ':
			continue
		case '-':
			if strings.TrimSpace(line[:i]) == "" {
				return i, true
			}
			return 0, false
		default:
			return 0, false
		}
	}
	return 0, false
}

// encodeEntry renders `k: v` indented by indent spaces. With keepLineComment
// the key keeps its line comment; head and foot comments, which sit outside
// the replaced lines, are dropped from the copy so they are not duplicated.
func (d *Doc) encodeEntry(k, v *yaml.Node, indent int, keepLineComment bool) ([]string, error) {
	kc := *k
	kc.HeadComment, kc.FootComment = "", ""
	if !keepLineComment {
		kc.LineComment = ""
	}
	vc := deepCopy(v)
	stripTrailingFootComments(vc)
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{&kc, vc}}
	text, err := d.encode(m)
	if err != nil {
		return nil, err
	}
	pad := strings.Repeat(" ", indent)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return lines, nil
}

func stripTrailingFootComments(n *yaml.Node) {
	for n != nil {
		n.FootComment = ""
		if len(n.Content) == 0 {
			return
		}
		n = n.Content[len(n.Content)-1]
	}
}

func (d *Doc) encode(n *yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(d.indent)
	if err := enc.Encode(n); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// encodeInline renders a scalar on one line.
func encodeInline(n *yaml.Node) (string, error) {
	c := *n
	c.HeadComment, c.LineComment, c.FootComment = "", "", ""
	out, err := yaml.Marshal(&c)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

func deepCopy(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	if len(n.Content) > 0 {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			c.Content[i] = deepCopy(ch)
		}
	}
	return &c
}

// addEdit records e unless an existing whole-entry edit already re-renders the
// node it touches, and drops existing edits that e re-renders.
func (d *Doc) addEdit(e *edit) {
	for _, x := range d.edits {
		if x.kind == e.kind && x.line0 == e.line0 && (x.node == e.node || e.kind == editLines) {
			return
		}
		if x.kind == editLines && d.within(e.node, x.node) {
			return
		}
	}
	if e.kind == editLines {
		kept := d.edits[:0]
		for _, x := range d.edits {
			if !d.within(x.node, e.node) {
				kept = append(kept, x)
			}
		}
		d.edits = kept
	}
	d.seq++
	e.seq = d.seq
	d.edits = append(d.edits, e)
}

// within reports whether n is anc or one of its descendants.
func (d *Doc) within(n, anc *yaml.Node) bool {
	for n != nil {
		if n == anc {
			return true
		}
		o, ok := d.parents[n]
		if !ok {
			return false
		}
		if o.key != nil && o.key == anc {
			return true
		}
		n = o.parent
	}
	return false
}

// Changed reports whether any edit was made.
func (d *Doc) Changed() bool { return d.full || len(d.edits) > 0 }

// Bytes renders the edited document.
func (d *Doc) Bytes() ([]byte, error) {
	if !d.Changed() {
		return d.src, nil
	}
	if !d.full {
		if out, err := d.splice(); err == nil && d.sameContent(out) {
			return out, nil
		}
	}
	d.reencoded = true
	text, err := d.encode(d.doc)
	if err != nil {
		return nil, err
	}
	if d.crlf {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	return []byte(text), nil
}

func (d *Doc) splice() ([]byte, error) {
	lines := append([]string(nil), d.lines...)
	edits := append([]*edit(nil), d.edits...)
	pos := func(e *edit) float64 {
		switch e.kind {
		case editInsert:
			return float64(e.line0) + 0.5
		default:
			return float64(e.line0)
		}
	}
	sort.SliceStable(edits, func(i, j int) bool {
		pi, pj := pos(edits[i]), pos(edits[j])
		if pi != pj {
			return pi > pj
		}
		if edits[i].kind == editSpan && edits[j].kind == editSpan {
			return edits[i].col0 > edits[j].col0
		}
		return edits[i].seq > edits[j].seq
	})
	// Overlapping line edits mean the bookkeeping went wrong; let the caller
	// fall back to a full re-encode.
	for i := 0; i < len(edits); i++ {
		for j := i + 1; j < len(edits); j++ {
			if overlaps(edits[i], edits[j]) {
				return nil, errors.New("overlapping edits")
			}
		}
	}
	for _, e := range edits {
		text, err := e.render()
		if err != nil {
			return nil, err
		}
		switch e.kind {
		case editSpan:
			if e.line0 < 1 || e.line0 > len(lines) || len(text) != 1 {
				return nil, errors.New("bad span edit")
			}
			l := lines[e.line0-1]
			cr := strings.HasSuffix(l, "\r")
			l = strings.TrimSuffix(l, "\r")
			if e.col1 > len(l) {
				return nil, errors.New("bad span edit")
			}
			l = l[:e.col0] + text[0] + l[e.col1:]
			if cr {
				l += "\r"
			}
			lines[e.line0-1] = l
		case editLines:
			if e.line0 < 1 || e.line1 > len(lines) || e.line1 < e.line0 {
				return nil, errors.New("bad line edit")
			}
			lines = append(lines[:e.line0-1], append(text, lines[e.line1:]...)...)
		case editInsert:
			if e.line0 < 0 || e.line0 > len(lines) {
				return nil, errors.New("bad insert edit")
			}
			lines = append(lines[:e.line0], append(text, lines[e.line0:]...)...)
		}
	}
	sep := "\n"
	if d.crlf {
		sep = "\r\n"
	}
	out := strings.Join(lines, sep)
	if d.trailNL || len(d.lines) == 0 {
		out += sep
	}
	return []byte(out), nil
}

func overlaps(a, b *edit) bool {
	r := func(e *edit) (float64, float64) {
		switch e.kind {
		case editInsert:
			return float64(e.line0) + 0.5, float64(e.line0) + 0.5
		case editSpan:
			return float64(e.line0), float64(e.line0)
		default:
			return float64(e.line0), float64(e.line1)
		}
	}
	a0, a1 := r(a)
	b0, b1 := r(b)
	if a.kind == editSpan && b.kind == editSpan {
		return a.line0 == b.line0 && a.col0 < b.col1 && b.col0 < a.col1
	}
	return a0 <= b1 && b0 <= a1
}

// sameContent reports whether out decodes to the same data as the edited tree.
func (d *Doc) sameContent(out []byte) bool {
	var want, got any
	if err := d.doc.Decode(&want); err != nil {
		return false
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		return false
	}
	return reflect.DeepEqual(normalize(want), normalize(got))
}

// normalize maps a nil document to an empty mapping so an emptied file and a
// `{}` compare equal.
func normalize(v any) any {
	if v == nil {
		return map[string]any{}
	}
	return v
}

// Options tunes EditFile.
type Options struct {
	// Validate checks the rendered bytes before they are written; an error
	// aborts the write.
	Validate func([]byte) error
	// Perm is the mode of a newly created file (default 0600). An existing
	// file keeps its mode.
	Perm os.FileMode
}

// Result is what EditFile did.
type Result struct {
	// Changed reports that the file was written; an edit that changes nothing
	// writes nothing.
	Changed bool
	// Reencoded reports that an existing file could not be edited in place and
	// the whole tree was re-encoded: comments survive, blank lines and
	// formatting may not. The caller decides how to tell the operator.
	Reencoded bool
}

// EditFile parses the file at path (a missing file is an empty document),
// applies edit, validates the result and writes it atomically.
func EditFile(path string, edit func(*Doc) error, opts Options) (Result, error) {
	src, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	doc, err := Parse(src)
	if err != nil {
		return Result{}, fmt.Errorf("%s does not parse, refusing to rewrite it: %w", path, err)
	}
	if err := edit(doc); err != nil {
		return Result{}, err
	}
	out, err := doc.Bytes()
	if err != nil {
		return Result{}, err
	}
	if existed && bytes.Equal(out, src) {
		return Result{}, nil
	}
	if opts.Validate != nil {
		if err := opts.Validate(out); err != nil {
			return Result{}, err
		}
	}
	perm := opts.Perm
	if perm == 0 {
		perm = 0o600
	}
	if fi, statErr := os.Stat(path); statErr == nil {
		perm = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Result{}, err
	}
	if err := atomicfile.WriteFile(path, perm, func(w *bufio.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(out))
		return err
	}); err != nil {
		return Result{}, err
	}
	return Result{Changed: true, Reencoded: doc.reencoded && len(bytes.TrimSpace(src)) > 0}, nil
}
