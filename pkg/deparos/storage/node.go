package storage

import (
	"net/url"
	"time"
)

// DiscoveredNode represents a discovered URL with its request/response data.
// This is a flat data object - each URL is stored independently without tree structure.
type DiscoveredNode struct {
	// Database ID (0 if not persisted)
	id int64

	// URL data
	url *url.URL

	// Request/response data
	request  *RequestData
	response *ResponseData

	// Discovery metadata
	metadata *DiscoveryMetadata

	// Node properties
	nodeType NodeType

	// Cached tags (computed from request/response analysis)
	tags []string

	// Cached secret findings (secrets detected in response)
	secretFindings []SecretFinding
}

// ID returns the database ID of the node.
func (n *DiscoveredNode) ID() int64 {
	return n.id
}

// SetID sets the database ID of the node.
func (n *DiscoveredNode) SetID(id int64) {
	n.id = id
}

// RequestData stores HTTP request information
type RequestData struct {
	Method  string
	Headers map[string]string
	Body    []byte
}

// ResponseData stores HTTP response information
type ResponseData struct {
	StatusCode       int
	Headers          map[string]string
	Body             []byte
	ContentLength    int64 // Content-Length from response header
	MIMEType         string
	Location         string           // Location header value (for redirects)
	Title            string           // HTML page title
	FingerprintAttrs map[uint8]uint32 // Fingerprint attribute ID → hash value
	Words            int64            // Word count in response body
	Lines            int64            // Line count in response body
}

// DiscoveryMetadata tracks how and when the URL was found
type DiscoveryMetadata struct {
	FoundBy   string    // Task type that found it
	Depth     uint16    // Path depth
	Timestamp time.Time // When first discovered
}

// NewDiscoveredNode creates a new discovered node for a URL.
func NewDiscoveredNode(u *url.URL) *DiscoveredNode {
	return &DiscoveredNode{
		url:      u,
		nodeType: NodeTypeFile, // Default to file, will be set based on trailing slash
	}
}

// URL returns the node's URL
func (n *DiscoveredNode) URL() *url.URL {
	return n.url
}

// NodeType returns the node type
func (n *DiscoveredNode) NodeType() NodeType {
	return n.nodeType
}

// SetNodeType sets the node type
func (n *DiscoveredNode) SetNodeType(nt NodeType) {
	n.nodeType = nt
}

// Request returns the request data
func (n *DiscoveredNode) Request() *RequestData {
	return n.request
}

// Response returns the response data
func (n *DiscoveredNode) Response() *ResponseData {
	return n.response
}

// Metadata returns the discovery metadata
func (n *DiscoveredNode) Metadata() *DiscoveryMetadata {
	return n.metadata
}

// SetData sets the request, response, and metadata for the node.
func (n *DiscoveredNode) SetData(req *RequestData, resp *ResponseData, meta *DiscoveryMetadata) {
	n.request = req
	n.response = resp
	n.metadata = meta
}

// IsDirectory returns true if this is a directory node
func (n *DiscoveredNode) IsDirectory() bool {
	return n.nodeType == NodeTypeDirectory
}

// IsFile returns true if this is a file node
func (n *DiscoveredNode) IsFile() bool {
	return n.nodeType == NodeTypeFile
}

// Tags returns the cached tags for this node
func (n *DiscoveredNode) Tags() []string {
	return n.tags
}

// SetTags sets the cached tags for this node
func (n *DiscoveredNode) SetTags(tags []string) {
	n.tags = tags
}

// SecretFindings returns the cached secret findings for this node
func (n *DiscoveredNode) SecretFindings() []SecretFinding {
	return n.secretFindings
}

// SetSecretFindings sets the cached secret findings for this node
func (n *DiscoveredNode) SetSecretFindings(findings []SecretFinding) {
	n.secretFindings = findings
}
