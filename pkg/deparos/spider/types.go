package spider

import (
	"net/url"
)

// LinkCallback is invoked for each discovered link during extraction.
type LinkCallback func(link *DiscoveredLink)

// DiscoveredLink represents an extracted URL with metadata about its source and type.
type DiscoveredLink struct {
	// SourceType indicates where the link was found (HTML, JavaScript, etc.)
	SourceType LinkSourceType

	// URL is the fully resolved and normalized URL
	URL *url.URL

	// RawURL is the original URL string as it appeared in the source
	RawURL string

	// ResourceType indicates the type of resource (HTML, Image, Script, etc.)
	ResourceType ResourceType

	// StartPos is the byte position in the response body where the link starts
	StartPos int

	// EndPos is the byte position in the response body where the link ends
	EndPos int

	// Element is the HTML tag name if the link was found in HTML (e.g., "a", "img")
	Element string

	// Attribute is the HTML attribute name if applicable (e.g., "href", "src")
	Attribute string
}

// LinkSourceType indicates where a link was discovered.
type LinkSourceType byte

const (
	SourceInlineURL LinkSourceType = iota
	SourceHTMLAttribute
	SourceJavaScript
	SourceComment
	SourceHTTPHeader
	SourceRobotsTxt
	SourceFlashSWF
	SourceMetaRefresh
	SourceEventHandler
	SourceScriptContent
)

// String returns the human-readable name of the link source type.
func (t LinkSourceType) String() string {
	switch t {
	case SourceInlineURL:
		return "InlineURL"
	case SourceHTMLAttribute:
		return "HTMLAttribute"
	case SourceJavaScript:
		return "JavaScript"
	case SourceComment:
		return "Comment"
	case SourceHTTPHeader:
		return "HTTPHeader"
	case SourceRobotsTxt:
		return "RobotsTxt"
	case SourceFlashSWF:
		return "FlashSWF"
	case SourceMetaRefresh:
		return "MetaRefresh"
	case SourceEventHandler:
		return "EventHandler"
	case SourceScriptContent:
		return "ScriptContent"
	default:
		return "Unknown"
	}
}

// ResourceType indicates the type of resource referenced by a URL.
type ResourceType uint16

const (
	ResourceUnknown ResourceType = 0
	ResourceHTML    ResourceType = 256
	ResourceScript  ResourceType = 259
	ResourceImage   ResourceType = 512
	ResourceJPEG    ResourceType = 513
	ResourceGIF     ResourceType = 514
	ResourcePNG     ResourceType = 515
	ResourceBMP     ResourceType = 516
	ResourceTIFF    ResourceType = 517
	ResourceAudio   ResourceType = 768
	ResourceVideo   ResourceType = 769
	ResourceBinary  ResourceType = 1025
)

// String returns the human-readable name of the resource type.
func (t ResourceType) String() string {
	switch t {
	case ResourceHTML:
		return "HTML"
	case ResourceScript:
		return "Script"
	case ResourceImage:
		return "Image"
	case ResourceJPEG:
		return "JPEG"
	case ResourceGIF:
		return "GIF"
	case ResourcePNG:
		return "PNG"
	case ResourceBMP:
		return "BMP"
	case ResourceTIFF:
		return "TIFF"
	case ResourceAudio:
		return "Audio"
	case ResourceVideo:
		return "Video"
	case ResourceBinary:
		return "Binary"
	default:
		return "Unknown"
	}
}
