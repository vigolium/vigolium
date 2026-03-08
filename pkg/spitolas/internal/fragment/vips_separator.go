package fragment

// Separator represents a visual separator between blocks.
// This mirrors Java Crawljax's VipsSeparatorGraphicsDetector.
type Separator struct {
	// Position
	StartX float64
	StartY float64
	EndX   float64
	EndY   float64

	// Type
	IsHorizontal bool
	IsVertical   bool

	// Weight (used for visual structure construction)
	Weight float64

	// Blocks separated by this separator
	LeftBlock   *VisualBlock
	RightBlock  *VisualBlock
	TopBlock    *VisualBlock
	BottomBlock *VisualBlock
}

// NewHorizontalSeparator creates a horizontal separator.
func NewHorizontalSeparator(startX, y, endX float64) *Separator {
	return &Separator{
		StartX:       startX,
		StartY:       y,
		EndX:         endX,
		EndY:         y,
		IsHorizontal: true,
	}
}

// NewVerticalSeparator creates a vertical separator.
func NewVerticalSeparator(x, startY, endY float64) *Separator {
	return &Separator{
		StartX:     x,
		StartY:     startY,
		EndX:       x,
		EndY:       endY,
		IsVertical: true,
	}
}

// Length returns the length of the separator.
func (s *Separator) Length() float64 {
	if s.IsHorizontal {
		return s.EndX - s.StartX
	}
	return s.EndY - s.StartY
}

// VipsSeparatorDetector detects visual separators between blocks.
type VipsSeparatorDetector struct {
	pageWidth  int
	pageHeight int

	horizontalSeparators []*Separator
	verticalSeparators   []*Separator

	// Pool of potential separators
	separatorPool []*Separator

	// Minimum separator weight to keep
	cleanupThreshold float64
}

// NewVipsSeparatorDetector creates a new separator detector.
func NewVipsSeparatorDetector(pageWidth, pageHeight int) *VipsSeparatorDetector {
	return &VipsSeparatorDetector{
		pageWidth:            pageWidth,
		pageHeight:           pageHeight,
		horizontalSeparators: make([]*Separator, 0),
		verticalSeparators:   make([]*Separator, 0),
		separatorPool:        make([]*Separator, 0),
		cleanupThreshold:     0,
	}
}

// SetCleanupThreshold sets the minimum weight for separators.
func (d *VipsSeparatorDetector) SetCleanupThreshold(threshold float64) {
	d.cleanupThreshold = threshold
}

// DetectSeparators detects separators from visual blocks.
func (d *VipsSeparatorDetector) DetectSeparators(blocks []*VisualBlock) {
	d.fillPool(blocks)
	d.detectHorizontalSeparators(blocks)
	d.detectVerticalSeparators(blocks)
}

// fillPool creates initial separator pool from gaps between blocks.
func (d *VipsSeparatorDetector) fillPool(blocks []*VisualBlock) {
	d.separatorPool = make([]*Separator, 0)

	// Create separators from gaps between adjacent blocks
	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			b1 := blocks[i]
			b2 := blocks[j]

			// Check for horizontal gap (blocks stacked vertically)
			if d.hasHorizontalGap(b1, b2) {
				sep := d.createHorizontalSeparator(b1, b2)
				if sep != nil {
					d.separatorPool = append(d.separatorPool, sep)
				}
			}

			// Check for vertical gap (blocks side by side)
			if d.hasVerticalGap(b1, b2) {
				sep := d.createVerticalSeparator(b1, b2)
				if sep != nil {
					d.separatorPool = append(d.separatorPool, sep)
				}
			}
		}
	}
}

// hasHorizontalGap checks if there's a horizontal gap between two blocks.
func (d *VipsSeparatorDetector) hasHorizontalGap(b1, b2 *VisualBlock) bool {
	// Blocks must have horizontal overlap
	overlapX := min(b1.Rect.X+b1.Rect.Width, b2.Rect.X+b2.Rect.Width) - max(b1.Rect.X, b2.Rect.X)
	if overlapX <= 0 {
		return false
	}

	// There must be vertical space between them
	var top, bottom *VisualBlock
	if b1.Rect.Y < b2.Rect.Y {
		top = b1
		bottom = b2
	} else {
		top = b2
		bottom = b1
	}

	gap := bottom.Rect.Y - (top.Rect.Y + top.Rect.Height)
	return gap > 0
}

// hasVerticalGap checks if there's a vertical gap between two blocks.
func (d *VipsSeparatorDetector) hasVerticalGap(b1, b2 *VisualBlock) bool {
	// Blocks must have vertical overlap
	overlapY := min(b1.Rect.Y+b1.Rect.Height, b2.Rect.Y+b2.Rect.Height) - max(b1.Rect.Y, b2.Rect.Y)
	if overlapY <= 0 {
		return false
	}

	// There must be horizontal space between them
	var left, right *VisualBlock
	if b1.Rect.X < b2.Rect.X {
		left = b1
		right = b2
	} else {
		left = b2
		right = b1
	}

	gap := right.Rect.X - (left.Rect.X + left.Rect.Width)
	return gap > 0
}

// createHorizontalSeparator creates a horizontal separator between two blocks.
func (d *VipsSeparatorDetector) createHorizontalSeparator(b1, b2 *VisualBlock) *Separator {
	var top, bottom *VisualBlock
	if b1.Rect.Y < b2.Rect.Y {
		top = b1
		bottom = b2
	} else {
		top = b2
		bottom = b1
	}

	// Calculate separator position (middle of gap)
	y := (top.Rect.Y + top.Rect.Height + bottom.Rect.Y) / 2

	// Calculate horizontal extent
	startX := max(b1.Rect.X, b2.Rect.X)
	endX := min(b1.Rect.X+b1.Rect.Width, b2.Rect.X+b2.Rect.Width)

	sep := NewHorizontalSeparator(startX, y, endX)
	sep.TopBlock = top
	sep.BottomBlock = bottom

	// Calculate weight based on gap size
	gapSize := bottom.Rect.Y - (top.Rect.Y + top.Rect.Height)
	sep.Weight = gapSize / float64(d.pageHeight)

	return sep
}

// createVerticalSeparator creates a vertical separator between two blocks.
func (d *VipsSeparatorDetector) createVerticalSeparator(b1, b2 *VisualBlock) *Separator {
	var left, right *VisualBlock
	if b1.Rect.X < b2.Rect.X {
		left = b1
		right = b2
	} else {
		left = b2
		right = b1
	}

	// Calculate separator position (middle of gap)
	x := (left.Rect.X + left.Rect.Width + right.Rect.X) / 2

	// Calculate vertical extent
	startY := max(b1.Rect.Y, b2.Rect.Y)
	endY := min(b1.Rect.Y+b1.Rect.Height, b2.Rect.Y+b2.Rect.Height)

	sep := NewVerticalSeparator(x, startY, endY)
	sep.LeftBlock = left
	sep.RightBlock = right

	// Calculate weight based on gap size
	gapSize := right.Rect.X - (left.Rect.X + left.Rect.Width)
	sep.Weight = gapSize / float64(d.pageWidth)

	return sep
}

// detectHorizontalSeparators processes and cleans up horizontal separators.
func (d *VipsSeparatorDetector) detectHorizontalSeparators(blocks []*VisualBlock) {
	d.horizontalSeparators = make([]*Separator, 0)

	for _, sep := range d.separatorPool {
		if !sep.IsHorizontal {
			continue
		}

		// Check if separator crosses any block
		crosses := false
		for _, block := range blocks {
			if d.separatorCrossesBlock(sep, block) {
				crosses = true
				break
			}
		}

		if !crosses && sep.Weight >= d.cleanupThreshold {
			d.horizontalSeparators = append(d.horizontalSeparators, sep)
		}
	}
}

// detectVerticalSeparators processes and cleans up vertical separators.
func (d *VipsSeparatorDetector) detectVerticalSeparators(blocks []*VisualBlock) {
	d.verticalSeparators = make([]*Separator, 0)

	for _, sep := range d.separatorPool {
		if !sep.IsVertical {
			continue
		}

		// Check if separator crosses any block
		crosses := false
		for _, block := range blocks {
			if d.separatorCrossesBlock(sep, block) {
				crosses = true
				break
			}
		}

		if !crosses && sep.Weight >= d.cleanupThreshold {
			d.verticalSeparators = append(d.verticalSeparators, sep)
		}
	}
}

// separatorCrossesBlock checks if a separator crosses through a block.
func (d *VipsSeparatorDetector) separatorCrossesBlock(sep *Separator, block *VisualBlock) bool {
	if sep.IsHorizontal {
		// Horizontal separator crosses block if Y is within block and X overlaps
		if sep.StartY >= block.Rect.Y && sep.StartY <= block.Rect.Y+block.Rect.Height {
			// Check X overlap
			if sep.StartX < block.Rect.X+block.Rect.Width && sep.EndX > block.Rect.X {
				return true
			}
		}
	} else {
		// Vertical separator crosses block if X is within block and Y overlaps
		if sep.StartX >= block.Rect.X && sep.StartX <= block.Rect.X+block.Rect.Width {
			// Check Y overlap
			if sep.StartY < block.Rect.Y+block.Rect.Height && sep.EndY > block.Rect.Y {
				return true
			}
		}
	}
	return false
}

// GetHorizontalSeparators returns detected horizontal separators.
func (d *VipsSeparatorDetector) GetHorizontalSeparators() []*Separator {
	return d.horizontalSeparators
}

// GetVerticalSeparators returns detected vertical separators.
func (d *VipsSeparatorDetector) GetVerticalSeparators() []*Separator {
	return d.verticalSeparators
}

// GetAllSeparators returns all detected separators.
func (d *VipsSeparatorDetector) GetAllSeparators() []*Separator {
	all := make([]*Separator, 0, len(d.horizontalSeparators)+len(d.verticalSeparators))
	all = append(all, d.horizontalSeparators...)
	all = append(all, d.verticalSeparators...)
	return all
}

// NormalizeSeparatorWeights normalizes separator weights using min-max normalization.
func (d *VipsSeparatorDetector) NormalizeSeparatorWeights() {
	allSeps := d.GetAllSeparators()
	if len(allSeps) == 0 {
		return
	}

	// Find min and max weights
	minWeight := allSeps[0].Weight
	maxWeight := allSeps[0].Weight

	for _, sep := range allSeps {
		if sep.Weight < minWeight {
			minWeight = sep.Weight
		}
		if sep.Weight > maxWeight {
			maxWeight = sep.Weight
		}
	}

	// Normalize
	rangeWeight := maxWeight - minWeight
	if rangeWeight <= 0 {
		return
	}

	for _, sep := range allSeps {
		sep.Weight = (sep.Weight - minWeight) / rangeWeight
	}
}

// Helper functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
