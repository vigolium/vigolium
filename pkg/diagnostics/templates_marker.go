package diagnostics

import "github.com/vigolium/vigolium/pkg/nucleitemplates"

// TemplatesMarkerFile is written into the nuclei templates directory by the
// archive install (nucleitemplates.Install): which release it is, its archive
// digest, and when it was installed, so doctor can say "stale" from a fact
// rather than a directory mtime.
const TemplatesMarkerFile = nucleitemplates.MarkerFile

// TemplatesMarker is the content of TemplatesMarkerFile.
type TemplatesMarker = nucleitemplates.Marker

// ReadTemplatesMarker reads dir's marker.
func ReadTemplatesMarker(dir string) (*TemplatesMarker, error) { return nucleitemplates.ReadMarker(dir) }
