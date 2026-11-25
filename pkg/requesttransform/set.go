package requesttransform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// KeyEnvPrefix prefixes the environment variable a key reference resolves
// from first: {"credential": "api-key"} reads VIGOLIUM_TRANSFORM_KEY_API_KEY.
const KeyEnvPrefix = "VIGOLIUM_TRANSFORM_KEY_"

// Set is the transforms one invocation applies, with the key store their
// references resolve against.
type Set struct {
	Transforms []*Transform
	keys       map[string]string
}

// KeyEnvName is the environment variable a credential name resolves from:
// the prefix plus the name uppercased, every non-alphanumeric byte as `_`.
func KeyEnvName(credential string) string {
	var b strings.Builder
	b.WriteString(KeyEnvPrefix)
	for _, r := range strings.ToUpper(credential) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Key resolves a credential reference: the environment first, then the
// keys file.
func (s *Set) Key(credential string) (string, bool) {
	if v, ok := os.LookupEnv(KeyEnvName(credential)); ok && v != "" {
		return v, true
	}
	v, ok := s.keys[credential]
	return v, ok
}

// For is the transform that applies to rawURL, or nil.
func (s *Set) For(rawURL string) *Transform {
	if s == nil {
		return nil
	}
	return For(s.Transforms, rawURL)
}

// Apply evaluates the transform that applies to req.URL with the real clock
// and crypto/rand. It answers req unchanged (and a nil transform) when none
// applies.
func (s *Set) Apply(req Request) (Request, *Transform, *Refusal) {
	t := s.For(req.URL)
	if t == nil {
		return req, nil, nil
	}
	out, _, r := Evaluate(t, req, Env{Now: func() int64 { return time.Now().UnixMilli() }, Key: s.Key})
	return out, t, r
}

// Parse decodes a transform file: one transform object or an array of them.
// keys is the parsed keys file (nil for none).
func Parse(data []byte, keys map[string]string) (*Set, error) {
	trimmed := bytes.TrimSpace(data)
	var docs []json.RawMessage
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &docs); err != nil {
			return nil, fmt.Errorf("the transform file is not a JSON transform or array of transforms: %w", err)
		}
	} else {
		docs = []json.RawMessage{trimmed}
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("the transform file holds no transform")
	}
	set := &Set{keys: keys}
	for i, doc := range docs {
		t, r := Decode(doc)
		if r != nil {
			return nil, fmt.Errorf("transform %d refused (%s): %s", i, r.Code, r.Detail)
		}
		set.Transforms = append(set.Transforms, t)
	}
	return set, nil
}

// Load reads a transform file and, when keysPath is set, its keys file - a
// JSON object of credential name to value, readable by its owner alone.
func Load(path, keysPath string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys map[string]string
	if keysPath != "" {
		info, err := os.Stat(keysPath)
		if err != nil {
			return nil, err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("the keys file %s is readable beyond its owner (mode %o) - chmod 600 it", keysPath, info.Mode().Perm())
		}
		raw, err := os.ReadFile(keysPath)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &keys); err != nil {
			return nil, fmt.Errorf("the keys file is not a JSON object of name to value: %w", err)
		}
	}
	return Parse(data, keys)
}

var active atomic.Pointer[Set]

// Activate installs the set every request this process sends is checked
// against (nil clears it).
func Activate(s *Set) { active.Store(s) }

// Active is the installed set, or nil.
func Active() *Set { return active.Load() }
