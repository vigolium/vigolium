package extension

// Extension represents a Chrome extension that can be loaded
type Extension interface {
	Name() string
	Version() string
	ZipData() []byte
}

// registry holds all registered extensions
var registry []Extension

// Register adds an extension to the registry
func Register(ext Extension) {
	registry = append(registry, ext)
}

// GetAll returns all registered extensions
func GetAll() []Extension {
	return registry
}
