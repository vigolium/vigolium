package knownissuescan

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Template targeting (ECON-12).
//
// With enrich_targets on, nuclei ran every template against the origin AND
// every discovered directory prefix. A template whose requests are anchored at
// {{RootURL}} (or that probes the host rather than a URL: dns, ssl) sends the
// same request for every prefix of a host, so N prefixes cost N identical
// sends per template. Only templates that build on {{BaseURL}} can find
// something different under /app/ than under /.
//
// RootOnlyTemplateIDs classifies a templates directory once per process so the
// prefix pass can exclude the origin-anchored templates by ID.

var rootOnlyCache sync.Map // dir -> []string

// RootOnlyTemplateIDs returns the IDs of templates under dir whose requests do
// not depend on the target's path: they reference {{RootURL}} and never
// {{BaseURL}}, or they are host-level protocols (dns/ssl) with no {{BaseURL}}.
// Unreadable files are skipped; the result is cached per dir.
func RootOnlyTemplateIDs(dir string) ([]string, error) {
	if v, ok := rootOnlyCache.Load(dir); ok {
		return v.([]string), nil
	}
	var ids []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if id, ok := classifyRootOnly(data); ok {
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rootOnlyCache.Store(dir, ids)
	return ids, nil
}

// classifyRootOnly reports a template's id when it is path-independent.
func classifyRootOnly(data []byte) (string, bool) {
	id := templateID(data)
	if id == "" {
		return "", false
	}
	if bytes.Contains(data, []byte("{{BaseURL}}")) {
		return "", false
	}
	if bytes.Contains(data, []byte("{{RootURL}}")) {
		return id, true
	}
	// Host-level protocols: the target's path never reaches the wire.
	for _, proto := range [][]byte{[]byte("\ndns:"), []byte("\nssl:")} {
		if bytes.Contains(data, proto) && !bytes.Contains(data, []byte("\nhttp:")) &&
			!bytes.Contains(data, []byte("\nrequests:")) && !bytes.Contains(data, []byte("\nheadless:")) {
			return id, true
		}
	}
	return "", false
}

// templateID reads the top-level `id:` of a nuclei template.
func templateID(data []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "id:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "id:")), `"'`)
		}
	}
	return ""
}
