package fragment

import (
	"sort"
)

// VisualStructure represents the final visual structure of a page.
// This mirrors Java Crawljax's VisualStructureConstructor output.
type VisualStructure struct {
	// Root visual block
	Root *VisualBlock

	// All visual blocks (flattened)
	Blocks []*VisualBlock

	// Detected separators
	Separators []*Separator

	// Page dimensions
	PageWidth  int
	PageHeight int

	// Configuration
	PDoC int // Permitted Degree of Coherence
}

// VisualStructureConstructor constructs the final visual structure.
// This mirrors Java Crawljax's VisualStructureConstructor class.
type VisualStructureConstructor struct {
	pDoC       int // Permitted Degree of Coherence
	pageWidth  int
	pageHeight int

	// Visual blocks from parser
	vipsBlocks *VisualBlock

	// Detected separators
	separators []*Separator

	// Output structure
	structure *VisualStructure
}

// NewVisualStructureConstructor creates a new constructor.
func NewVisualStructureConstructor(pDoC int) *VisualStructureConstructor {
	return &VisualStructureConstructor{
		pDoC:       pDoC,
		separators: make([]*Separator, 0),
	}
}

// SetPageSize sets the page dimensions.
func (c *VisualStructureConstructor) SetPageSize(width, height int) {
	c.pageWidth = width
	c.pageHeight = height
}

// SetVipsBlocks sets the visual blocks from the parser.
func (c *VisualStructureConstructor) SetVipsBlocks(blocks *VisualBlock) {
	c.vipsBlocks = blocks
}

// UpdateVipsBlocks updates blocks after subsequent iterations.
func (c *VisualStructureConstructor) UpdateVipsBlocks(blocks *VisualBlock) {
	c.vipsBlocks = blocks
}

// SetSeparators sets the detected separators.
func (c *VisualStructureConstructor) SetSeparators(separators []*Separator) {
	c.separators = separators
}

// ConstructVisualStructure builds the final visual structure.
func (c *VisualStructureConstructor) ConstructVisualStructure() *VisualStructure {
	c.structure = &VisualStructure{
		Root:       c.vipsBlocks,
		PageWidth:  c.pageWidth,
		PageHeight: c.pageHeight,
		PDoC:       c.pDoC,
		Separators: c.separators,
	}

	// Collect all visual blocks
	c.structure.Blocks = c.collectVisualBlocks(c.vipsBlocks)

	// Build hierarchy based on containment
	c.buildHierarchy()

	// Assign IDs in order
	c.assignIDs()

	return c.structure
}

// collectVisualBlocks collects all visual blocks from the tree.
func (c *VisualStructureConstructor) collectVisualBlocks(root *VisualBlock) []*VisualBlock {
	var blocks []*VisualBlock

	var collect func(block *VisualBlock)
	collect = func(block *VisualBlock) {
		if block == nil {
			return
		}

		if block.IsVisualBlock {
			blocks = append(blocks, block)
		}

		for _, child := range block.Children {
			collect(child)
		}
	}

	collect(root)
	return blocks
}

// buildHierarchy builds parent-child relationships based on visual containment.
func (c *VisualStructureConstructor) buildHierarchy() {
	blocks := c.structure.Blocks

	// Sort blocks by area (largest first)
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].GetArea() > blocks[j].GetArea()
	})

	// Clear existing hierarchy
	for _, block := range blocks {
		block.Parent = nil
		block.ParentID = -1
	}

	// Build hierarchy based on containment
	for i := 0; i < len(blocks); i++ {
		child := blocks[i]

		// Find smallest container
		var smallestContainer *VisualBlock
		smallestArea := float64(c.pageWidth * c.pageHeight)

		for j := 0; j < len(blocks); j++ {
			if i == j {
				continue
			}

			parent := blocks[j]
			if parent.Contains(child) {
				parentArea := parent.GetArea()
				if parentArea < smallestArea {
					smallestArea = parentArea
					smallestContainer = parent
				}
			}
		}

		if smallestContainer != nil && smallestContainer != child {
			child.Parent = smallestContainer
			child.ParentID = smallestContainer.ID

			// Check if child is already in parent's children
			found := false
			for _, existingChild := range smallestContainer.Children {
				if existingChild == child {
					found = true
					break
				}
			}
			if !found {
				smallestContainer.Children = append(smallestContainer.Children, child)
			}
		}
	}

	// Find root (block with no parent)
	for _, block := range blocks {
		if block.Parent == nil {
			c.structure.Root = block
			break
		}
	}
}

// assignIDs assigns sequential IDs to all blocks.
func (c *VisualStructureConstructor) assignIDs() {
	id := 0

	var assign func(block *VisualBlock)
	assign = func(block *VisualBlock) {
		if block == nil {
			return
		}

		block.ID = id
		id++

		for _, child := range block.Children {
			child.ParentID = block.ID
			assign(child)
		}
	}

	assign(c.structure.Root)
}

// GetVisualBlocks returns all visual blocks.
func (c *VisualStructureConstructor) GetVisualBlocks() []*VisualBlock {
	if c.structure == nil {
		return nil
	}
	return c.structure.Blocks
}

// GetVisualStructure returns the constructed visual structure.
func (c *VisualStructureConstructor) GetVisualStructure() *VisualStructure {
	return c.structure
}

// ExportToRectangles converts visual blocks to VipsRectangles for output.
func (c *VisualStructureConstructor) ExportToRectangles() []*VipsRectangle {
	if c.structure == nil {
		return nil
	}

	rectangles := make([]*VipsRectangle, 0, len(c.structure.Blocks))

	for _, block := range c.structure.Blocks {
		rect := NewVipsRectangle(block.ID, block.ParentID, block.XPath, block.Rect)
		rect.DoC = block.DoC

		// Add nested block info
		var collectXPaths func(b *VisualBlock)
		collectXPaths = func(b *VisualBlock) {
			if b == nil {
				return
			}
			rect.AddNestedBlock(b.XPath)
			for _, child := range b.Children {
				collectXPaths(child)
			}
		}
		collectXPaths(block)

		rectangles = append(rectangles, rect)
	}

	return rectangles
}

// ExportToFragments converts visual blocks to Fragments.
func (c *VisualStructureConstructor) ExportToFragments() []*Fragment {
	if c.structure == nil {
		return nil
	}

	fragments := make([]*Fragment, 0, len(c.structure.Blocks))

	for _, block := range c.structure.Blocks {
		frag := block.ToFragment()
		fragments = append(fragments, frag)
	}

	return fragments
}

// NormalizeSeparators normalizes separator weights.
func (c *VisualStructureConstructor) NormalizeSeparators() {
	if len(c.separators) == 0 {
		return
	}

	// SoftMax normalization
	var sum float64
	for _, sep := range c.separators {
		sum += sep.Weight
	}

	if sum > 0 {
		for _, sep := range c.separators {
			sep.Weight = sep.Weight / sum
		}
	}

	// Min-Max normalization
	minW := c.separators[0].Weight
	maxW := c.separators[0].Weight

	for _, sep := range c.separators {
		if sep.Weight < minW {
			minW = sep.Weight
		}
		if sep.Weight > maxW {
			maxW = sep.Weight
		}
	}

	rangeW := maxW - minW
	if rangeW > 0 {
		for _, sep := range c.separators {
			sep.Weight = (sep.Weight - minW) / rangeW
		}
	}
}
