package fragment

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// VIPS implements the Vision-based Page Segmentation algorithm.
//
// References:
//   - Cai, D., Yu, S., Wen, J. R., & Ma, W. Y. (2003). VIPS: a Vision-based Page
//     Segmentation Algorithm. Microsoft Technical Report.
type VIPS struct {
	// Configuration
	pDoC          int     // Permitted Degree of Coherence (1-11)
	numIterations int     // Number of segmentation iterations
	minWidth      float64 // Minimum block width
	minHeight     float64 // Minimum block height

	// Internal components
	parser      *VipsParser
	detector    *VipsSeparatorDetector
	constructor *VisualStructureConstructor

	// Page info
	pageWidth  int
	pageHeight int

	// Output
	visualStructure *VisualStructure
}

// NewVIPS creates a new VIPS extractor with default parameters.
func NewVIPS() *VIPS {
	return &VIPS{
		pDoC:          11, // Maximum coherence by default
		numIterations: 10,
		minWidth:      10, // Minimum block width
		minHeight:     10, // Minimum block height
	}
}

// WithPDoC sets the permitted degree of coherence (1-11).
// Higher values mean finer granularity.
func (v *VIPS) WithPDoC(pDoC int) *VIPS {
	if pDoC < 1 {
		pDoC = 1
	}
	if pDoC > 11 {
		pDoC = 11
	}
	v.pDoC = pDoC
	return v
}

// WithIterations sets the number of segmentation iterations.
// More iterations = finer segmentation with smaller thresholds.
func (v *VIPS) WithIterations(n int) *VIPS {
	if n < 1 {
		n = 1
	}
	if n > 20 {
		n = 20
	}
	v.numIterations = n
	return v
}

// WithMinSize sets minimum block dimensions.
func (v *VIPS) WithMinSize(width, height float64) *VIPS {
	v.minWidth = width
	v.minHeight = height
	return v
}

// Extract performs VIPS extraction on the page.
// This is the main entry point, mirroring VipsSelenium.startSegmentation().
func (v *VIPS) Extract(page *browser.Page) ([]*Fragment, error) {
	// Get page dimensions
	pageSize, err := v.getPageSize(page)
	if err != nil {
		return nil, fmt.Errorf("failed to get page size: %w", err)
	}
	v.pageWidth = pageSize.width
	v.pageHeight = pageSize.height

	// Perform multi-pass segmentation
	err = v.performSegmentation(page)
	if err != nil {
		return nil, fmt.Errorf("segmentation failed: %w", err)
	}

	// Convert to fragments
	return v.constructor.ExportToFragments(), nil
}

// ExtractRectangles performs VIPS extraction and returns VipsRectangles.
func (v *VIPS) ExtractRectangles(page *browser.Page) ([]*VipsRectangle, error) {
	// Get page dimensions
	pageSize, err := v.getPageSize(page)
	if err != nil {
		return nil, fmt.Errorf("failed to get page size: %w", err)
	}
	v.pageWidth = pageSize.width
	v.pageHeight = pageSize.height

	// Perform multi-pass segmentation
	err = v.performSegmentation(page)
	if err != nil {
		return nil, fmt.Errorf("segmentation failed: %w", err)
	}

	// Convert to rectangles
	return v.constructor.ExportToRectangles(), nil
}

// GetVisualStructure returns the constructed visual structure.
func (v *VIPS) GetVisualStructure() *VisualStructure {
	return v.visualStructure
}

// performSegmentation executes the multi-pass VIPS algorithm.
// This mirrors VipsSelenium.performSegmentation() with iterative refinement.
func (v *VIPS) performSegmentation(page *browser.Page) error {
	// Initialize components
	v.parser = NewVipsParser(page)
	v.parser.SetPageSize(v.pageWidth, v.pageHeight)

	v.detector = NewVipsSeparatorDetector(v.pageWidth, v.pageHeight)
	v.constructor = NewVisualStructureConstructor(v.pDoC)
	v.constructor.SetPageSize(v.pageWidth, v.pageHeight)

	// Get iteration thresholds
	thresholds := IterationThresholds(v.numIterations)

	var vipsBlocks *VisualBlock

	// Multi-pass segmentation with decreasing thresholds
	for iteration := 0; iteration < v.numIterations; iteration++ {
		threshold := thresholds[iteration]

		// Set thresholds for this iteration
		v.parser.SetThresholds(threshold.Width, threshold.Height)

		// Parse visual blocks
		var err error
		vipsBlocks, err = v.parser.Parse()
		if err != nil {
			return fmt.Errorf("iteration %d: %w", iteration+1, err)
		}

		if iteration == 0 {
			// First iteration - set initial blocks
			v.constructor.SetVipsBlocks(vipsBlocks)

			// Detect separators from initial blocks
			visualBlocks := v.parser.GetVisualBlocks(vipsBlocks)
			v.detector.DetectSeparators(visualBlocks)
		} else {
			// Subsequent iterations - update blocks
			v.constructor.UpdateVipsBlocks(vipsBlocks)
		}

		// Construct visual structure
		v.visualStructure = v.constructor.ConstructVisualStructure()
	}

	// Normalize separator weights
	v.constructor.NormalizeSeparators()
	v.detector.NormalizeSeparatorWeights()

	// Set final separators
	v.constructor.SetSeparators(v.detector.GetAllSeparators())

	// Final structure construction
	v.visualStructure = v.constructor.ConstructVisualStructure()

	return nil
}

// pageSize holds page dimensions.
type pageSize struct {
	width  int
	height int
}

// getPageSize retrieves page dimensions via JavaScript.
func (v *VIPS) getPageSize(page *browser.Page) (*pageSize, error) {
	script := `() => {
		return {
			width: Math.max(
				document.body.scrollWidth,
				document.documentElement.scrollWidth,
				document.body.offsetWidth,
				document.documentElement.offsetWidth,
				document.documentElement.clientWidth
			),
			height: Math.max(
				document.body.scrollHeight,
				document.documentElement.scrollHeight,
				document.body.offsetHeight,
				document.documentElement.offsetHeight,
				document.documentElement.clientHeight
			)
		};
	}`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return &pageSize{width: 1200, height: 800}, nil // Default fallback
	}

	width := 1200
	height := 800

	if w, ok := resultMap["width"].(float64); ok {
		width = int(w)
	}
	if h, ok := resultMap["height"].(float64); ok {
		height = int(h)
	}

	return &pageSize{width: width, height: height}, nil
}

// GetFragmentCount returns the number of detected fragments.
func (v *VIPS) GetFragmentCount() int {
	if v.visualStructure == nil {
		return 0
	}
	return len(v.visualStructure.Blocks)
}

// GetVisualBlocks returns the detected visual blocks.
func (v *VIPS) GetVisualBlocks() []*VisualBlock {
	if v.visualStructure == nil {
		return nil
	}
	return v.visualStructure.Blocks
}

// GetSeparators returns the detected separators.
func (v *VIPS) GetSeparators() []*Separator {
	if v.visualStructure == nil {
		return nil
	}
	return v.visualStructure.Separators
}

// GetRootBlock returns the root visual block.
func (v *VIPS) GetRootBlock() *VisualBlock {
	if v.visualStructure == nil {
		return nil
	}
	return v.visualStructure.Root
}

// VIPSConfig holds VIPS configuration options.
type VIPSConfig struct {
	PDoC          int     // Permitted Degree of Coherence (1-11)
	NumIterations int     // Number of iterations
	MinWidth      float64 // Minimum block width
	MinHeight     float64 // Minimum block height
}

// DefaultVIPSConfig returns the default VIPS configuration.
func DefaultVIPSConfig() VIPSConfig {
	return VIPSConfig{
		PDoC:          11,
		NumIterations: 10,
		MinWidth:      10,
		MinHeight:     10,
	}
}

// NewVIPSWithConfig creates a VIPS extractor with the given configuration.
func NewVIPSWithConfig(config VIPSConfig) *VIPS {
	return NewVIPS().
		WithPDoC(config.PDoC).
		WithIterations(config.NumIterations).
		WithMinSize(config.MinWidth, config.MinHeight)
}
