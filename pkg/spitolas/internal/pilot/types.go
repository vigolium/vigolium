// Package pilot provides an AI-powered crawl mode where an ACP agent
// fully controls the browser via tools, replacing the traditional
// crawler's automated exploration with intelligent, semantic navigation.
package pilot

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// PilotConfig configures the pilot-driven crawl mode.
type PilotConfig struct {
	Enabled       bool            `yaml:"enabled"`
	Auth          PilotAuthConfig `yaml:"auth"`
	Screenshot    bool            `yaml:"screenshot"`     // include page screenshot with every action result (costs more tokens)
	MaxRetries   int           `yaml:"max_retries"`    // max ACP prompt retries on stall
	StallTimeout time.Duration `yaml:"stall_timeout"` // no-tool-call timeout before retry (0 = 7m default)
}

// PilotAuthConfig configures authentication for pilot mode.
type PilotAuthConfig struct {
	Enabled      bool   `yaml:"enabled"`
	AutoRegister bool   `yaml:"auto_register"` // try to register if no credentials
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

// CreatedEntity tracks an entity created by the agent during crawling.
type CreatedEntity struct {
	ID         string `json:"id"`
	Type       string `json:"type"`       // "user", "post", "product", etc.
	Identifier string `json:"identifier"` // how to identify it (email, name, URL)
	StateID    string `json:"state_id"`   // state where it was created
	Deleted    bool   `json:"deleted"`
}

// EntityTracker manages entities created by the agent for create-then-delete testing.
type EntityTracker struct {
	mu       sync.RWMutex
	entities map[string]*CreatedEntity
	nextID   int
}

// NewEntityTracker creates a new EntityTracker.
func NewEntityTracker() *EntityTracker {
	return &EntityTracker{
		entities: make(map[string]*CreatedEntity),
	}
}

// Register records a new entity. Returns the assigned entity ID.
func (et *EntityTracker) Register(entityType, identifier, stateID string) string {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.nextID++
	id := "entity_" + strconv.Itoa(et.nextID)

	et.entities[id] = &CreatedEntity{
		ID:         id,
		Type:       entityType,
		Identifier: identifier,
		StateID:    stateID,
	}
	return id
}

// MarkDeleted marks an entity as deleted.
func (et *EntityTracker) MarkDeleted(entityID string) bool {
	et.mu.Lock()
	defer et.mu.Unlock()

	e, ok := et.entities[entityID]
	if !ok {
		return false
	}
	e.Deleted = true
	return true
}

// All returns all tracked entities.
func (et *EntityTracker) All() []*CreatedEntity {
	et.mu.RLock()
	defer et.mu.RUnlock()

	result := make([]*CreatedEntity, 0, len(et.entities))
	for _, e := range et.entities {
		result = append(result, e)
	}
	return result
}

// BlacklistEntry represents a blacklisted element that the agent must not click.
type BlacklistEntry struct {
	XPath  string `json:"xpath"`
	Reason string `json:"reason"`
	Auto   bool   `json:"auto"` // true if auto-detected, false if agent-added
}

// Blacklist manages elements that must not be clicked.
type Blacklist struct {
	mu      sync.RWMutex
	entries []BlacklistEntry
}

// NewBlacklist creates a new Blacklist.
func NewBlacklist() *Blacklist {
	return &Blacklist{
		entries: make([]BlacklistEntry, 0),
	}
}

// Add adds an entry to the blacklist.
func (bl *Blacklist) Add(xpath, reason string, auto bool) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.entries = append(bl.entries, BlacklistEntry{
		XPath:  xpath,
		Reason: reason,
		Auto:   auto,
	})
}

// IsBlacklisted checks if an XPath matches any blacklisted entry.
// Returns the reason if blacklisted, empty string otherwise.
func (bl *Blacklist) IsBlacklisted(xpath string) (string, bool) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	for _, entry := range bl.entries {
		if entry.XPath == xpath {
			return entry.Reason, true
		}
	}
	return "", false
}

// All returns all blacklist entries.
func (bl *Blacklist) All() []BlacklistEntry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	result := make([]BlacklistEntry, len(bl.entries))
	copy(result, bl.entries)
	return result
}

// Credentials stores authentication credentials for the session.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterFlow captures a replayable registration sequence.
type RegisterFlow struct {
	TargetURL   string        `json:"target_url"`
	Steps       []ActionEntry `json:"steps"`
	Credentials Credentials   `json:"credentials"`
	CreatedAt   time.Time     `json:"created_at"`
}

// LoginFlow captures a replayable login sequence.
type LoginFlow struct {
	TargetURL   string         `json:"target_url"`
	Steps       []ActionEntry  `json:"steps"`
	Credentials Credentials    `json:"credentials"`
	Cookies     []*http.Cookie `json:"cookies"`
	CreatedAt   time.Time      `json:"created_at"`
}

// StateSnapshot captures the state before/after an action for the action log.
type StateSnapshot struct {
	StateID string `json:"state_id"`
	URL     string `json:"url"`
	Title   string `json:"title"`
	IsNew   bool   `json:"is_new"`
}
