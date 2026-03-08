package fragment

// VisualBlock represents a visual block in the VIPS algorithm.
// This mirrors Java Crawljax's visual block concept from VipsSeleniumParser.
type VisualBlock struct {
	// Identification
	ID       int
	ParentID int

	// DOM properties
	XPath    string
	Selector string
	TagName  string

	// Visual properties
	Rect Rect

	// VIPS-specific properties
	DoC            int  // Degree of Coherence (1-11)
	IsDividable    bool // Can be further divided
	IsVisualBlock  bool // Is marked as a visual block
	AlreadyDivided bool // Has been processed

	// Content properties
	DOMHash     string
	ContentHash string
	SubtreeSize int

	// Hierarchy
	Children []*VisualBlock
	Parent   *VisualBlock

	// Additional VIPS metadata
	PCount         int  // Paragraph count
	ImageCount     int  // Image count
	ContainsTable  bool // Contains table element
	LinkTextLength int  // Total link text length

	// Style properties (from computed styles)
	BackgroundColor string
	FontSize        int
	FontWeight      string
}

// NewVisualBlock creates a new visual block.
func NewVisualBlock(id int, xpath string, rect Rect) *VisualBlock {
	return &VisualBlock{
		ID:            id,
		ParentID:      -1,
		XPath:         xpath,
		Rect:          rect,
		DoC:           11, // Default DoC
		IsDividable:   true,
		IsVisualBlock: false,
		Children:      make([]*VisualBlock, 0),
	}
}

// AddChild adds a child visual block.
func (vb *VisualBlock) AddChild(child *VisualBlock) {
	child.Parent = vb
	child.ParentID = vb.ID
	vb.Children = append(vb.Children, child)
}

// IsLeaf returns true if this block has no children.
func (vb *VisualBlock) IsLeaf() bool {
	return len(vb.Children) == 0
}

// IsRoot returns true if this block has no parent.
func (vb *VisualBlock) IsRoot() bool {
	return vb.Parent == nil
}

// GetArea returns the area of this block.
func (vb *VisualBlock) GetArea() float64 {
	return vb.Rect.Area()
}

// Contains checks if this block contains another block.
func (vb *VisualBlock) Contains(other *VisualBlock) bool {
	return vb.Rect.Contains(other.Rect)
}

// ToFragment converts this visual block to a Fragment.
func (vb *VisualBlock) ToFragment() *Fragment {
	frag := NewFragment(vb.ID, vb.XPath, vb.Rect, vb.SubtreeSize)
	frag.Selector = vb.Selector
	frag.TagName = vb.TagName
	frag.DOMHash = vb.DOMHash
	frag.ContentHash = vb.ContentHash
	frag.ParentID = vb.ParentID

	// Map DoC to influence (higher DoC = more coherent = higher influence)
	frag.Influence = float64(vb.DoC) / 11.0

	// Add child IDs
	for _, child := range vb.Children {
		frag.ChildIDs = append(frag.ChildIDs, child.ID)
	}

	return frag
}

// VipsRectangle represents a VIPS visual rectangle output.
// This mirrors Java Crawljax's VipsRectangle class.
type VipsRectangle struct {
	ID       int
	ParentID int
	XPath    string
	Rect     Rect
	DoC      int

	// NestedBlocks stores the DOM node references (as XPaths) within this block
	NestedBlocks []string
}

// NewVipsRectangle creates a new VipsRectangle.
func NewVipsRectangle(id, parentID int, xpath string, rect Rect) *VipsRectangle {
	return &VipsRectangle{
		ID:           id,
		ParentID:     parentID,
		XPath:        xpath,
		Rect:         rect,
		DoC:          11,
		NestedBlocks: make([]string, 0),
	}
}

// AddNestedBlock adds a nested block XPath.
func (vr *VipsRectangle) AddNestedBlock(xpath string) {
	vr.NestedBlocks = append(vr.NestedBlocks, xpath)
}
