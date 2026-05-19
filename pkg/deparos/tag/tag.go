package tag

// Tag represents a discovered tag on a request/response pair.
type Tag string

const (
	TagVibeApp   Tag = "VibeApp"
	TagHasJWT    Tag = "Has-JWT"
	TagHasAPIKey Tag = "Has-API-Key"
	TagErrorPage Tag = "Error-Page"
	TagModernApp Tag = "Modern-App"
	TagJSONData  Tag = "JSON-Data"
)

// String returns the string representation of the tag.
func (t Tag) String() string {
	return string(t)
}

// AllTags returns all available tags.
func AllTags() []Tag {
	return []Tag{TagVibeApp, TagHasJWT, TagHasAPIKey, TagErrorPage, TagModernApp, TagJSONData}
}
