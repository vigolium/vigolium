// Package contract is the machine-readable description of vigolium's machine
// output: a JSON Schema (draft 2020-12) for every registered -j document, for
// each --events line type, for the error envelope, and for standalone
// documents such as the scan plan. `vigolium schema` prints them, `make
// schema` writes them to docs/schema, and the contracttest subpackage
// validates real command output against them in tests.
//
// The schemas are reflected from Go types, never hand-written: a command
// registers the type of one item and a struct naming its top-level extras, and
// the envelope spine comes from the public mirror in envelope.go. A field
// rename then changes the schema, which fails the golden test, which is the
// point.
//
// It is a leaf package: it imports only pkg/apicontract and the reflector, so
// any package that owns a machine shape (pkg/cli, pkg/scanevents) can register
// it without a cycle.
package contract

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Envelope kinds, as the `kind` field carries them.
const (
	KindRead     = "read"
	KindMutation = "mutation"
	KindScan     = "scan"
)

// ItemsKind says how a document's `items` array is filled.
const (
	// ItemsList: zero or more rows of Item.
	ItemsList = "list"
	// ItemsObject: exactly one object, wrapped as items:[obj].
	ItemsObject = "object"
)

// Command describes one command's -j document.
type Command struct {
	// Name is the `command` field the document carries: the cobra path without
	// the root ("finding", "scan status").
	Name string
	// Kind is the document's `kind` (KindRead, KindMutation, KindScan); empty
	// when the document carries none.
	Kind string
	// Description is a one-line summary, rendered as the schema's description.
	Description string
	// Item is a zero value of one item's Go type. Nil leaves items untyped.
	Item any
	// ItemsKind is ItemsList (the default) or ItemsObject.
	ItemsKind string
	// Variants are alternative item shapes a flag selects (traffic --curl).
	// The items schema is then anyOf the default and every variant.
	Variants []Variant
	// Extras is a zero value of a struct whose JSON fields are the command's
	// own top-level keys. omitempty fields are optional, the rest required.
	// They override a common envelope extra of the same name.
	Extras any
	// StreamFlag names the flag that turns stdout into a stream of these
	// documents, one per line (NDJSON); "" when there is none.
	StreamFlag string
}

// Variant is an alternative item shape selected by a flag.
type Variant struct {
	Flag string
	Item any
}

// Document is a standalone machine document that is not an envelope (the
// scan plan, for one).
type Document struct {
	Name        string
	Description string
	Value       any
}

var (
	mu        sync.RWMutex
	commands  = map[string]Command{}
	documents = map[string]Document{}
)

// RegisterCommand records a command's document shape. It panics on an empty
// or duplicate name or an unknown kind: both are programming errors caught by
// the first test that imports the registering package.
func RegisterCommand(c Command) {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		panic("contract: RegisterCommand with an empty name")
	}
	switch c.Kind {
	case "", KindRead, KindMutation, KindScan:
	default:
		panic(fmt.Sprintf("contract: command %q has unknown kind %q", c.Name, c.Kind))
	}
	switch c.ItemsKind {
	case "":
		c.ItemsKind = ItemsList
	case ItemsList, ItemsObject:
	default:
		panic(fmt.Sprintf("contract: command %q has unknown items kind %q", c.Name, c.ItemsKind))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := commands[c.Name]; dup {
		panic(fmt.Sprintf("contract: command %q registered twice", c.Name))
	}
	commands[c.Name] = c
}

// LookupCommand returns the registration for name.
func LookupCommand(name string) (Command, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := commands[name]
	return c, ok
}

// CommandNames lists the registered commands, sorted.
func CommandNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	return sortedKeys(commands)
}

// RegisterDocument records a standalone document's Go type under name.
func RegisterDocument(d Document) {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" || d.Value == nil {
		panic("contract: RegisterDocument needs a name and a value")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := documents[d.Name]; dup {
		panic(fmt.Sprintf("contract: document %q registered twice", d.Name))
	}
	documents[d.Name] = d
}

// LookupDocument returns the registration for name.
func LookupDocument(name string) (Document, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := documents[name]
	return d, ok
}

// DocumentNames lists the registered documents, sorted.
func DocumentNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	return sortedKeys(documents)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
