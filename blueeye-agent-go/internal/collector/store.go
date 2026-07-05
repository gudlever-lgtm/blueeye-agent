package collector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
)

// Source identifies where a definition arrived from. Definitions may only be
// INSTALLED from the authenticated WebSocket channel; every other path is
// rejected (milestone rule). Cache loading is a separate, non-install path used
// only to seed in-memory state at startup.
type Source int

const (
	// SourceWebSocket is the authenticated live channel — the only trusted path.
	SourceWebSocket Source = iota
	// SourceREST/other is rejected by Install.
	SourceREST
	// SourceOther is rejected by Install.
	SourceOther
)

// Outcome reports what Install did.
type Outcome string

const (
	// Installed means a new definition was added.
	Installed Outcome = "installed"
	// Replaced means an existing definition was upgraded (higher version).
	Replaced Outcome = "replaced"
	// SkippedOlder means the incoming version was not higher; kept existing.
	SkippedOlder Outcome = "skipped_older"
)

// ErrUntrustedSource is returned when Install is called with a non-WebSocket
// source — definitions must only arrive over the authenticated live channel.
var ErrUntrustedSource = errors.New("collector: definitions may only be installed from the WebSocket channel")

// Store holds the current collector definitions in memory and mirrors them to a
// disk cache so they survive restarts (and upgrades). It is concurrency-safe.
type Store struct {
	mu    sync.RWMutex
	defs  map[string]Definition
	dir   string
	audit *audit.Logger
}

// NewStore returns a store backed by the given cache directory. auditLog may be
// nil (a no-op logger is used).
func NewStore(dir string, auditLog *audit.Logger) *Store {
	if auditLog == nil {
		auditLog = audit.New("", nil)
	}
	return &Store{defs: map[string]Definition{}, dir: dir, audit: auditLog}
}

// LoadCache seeds in-memory state from the disk cache. Invalid cache files are
// skipped (not fatal). This is NOT an install path — cached definitions are the
// agent's own prior state; the server's live response later overrides them.
func (s *Store) LoadCache() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var d Definition
		if err := json.Unmarshal(data, &d); err != nil {
			continue
		}
		if err := d.Validate(); err != nil {
			continue // ignore a corrupt/invalid cached definition
		}
		s.putIfNewer(d)
	}
	return nil
}

// Seed installs the binary's bundled default definitions as the floor: an id is
// added only when absent or when the bundled version is newer. This gives the
// agent a working collector set even before the server pushes any definitions
// (and the server's live response still overrides by version). Invalid entries
// are skipped.
func (s *Store) Seed(defs []Definition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range defs {
		if d.Validate() != nil {
			continue
		}
		s.putIfNewer(d)
	}
}

// putIfNewer stores d when it is absent or strictly newer. Caller holds the lock.
func (s *Store) putIfNewer(d Definition) {
	if ex, ok := s.defs[d.ID]; ok && d.Version <= ex.Version {
		return
	}
	s.defs[d.ID] = d
}

// Install validates and applies a definition received from the live channel.
// Rules: source must be SourceWebSocket; the definition must be valid; and it
// replaces an existing one only when its version is strictly higher. Every
// install/replace writes a two-state audit record and updates the disk cache.
func (s *Store) Install(d Definition, source Source) (Outcome, error) {
	if source != SourceWebSocket {
		return "", ErrUntrustedSource
	}
	if err := d.Validate(); err != nil {
		return "", err
	}

	s.mu.Lock()
	existing, ok := s.defs[d.ID]
	if ok && d.Version <= existing.Version {
		s.mu.Unlock()
		return SkippedOlder, nil
	}
	outcome := Installed
	fromVersion := 0
	if ok {
		outcome = Replaced
		fromVersion = existing.Version
	}
	s.defs[d.ID] = d
	s.mu.Unlock()

	action := "collector.install"
	if outcome == Replaced {
		action = "collector.replace"
	}
	// Two-state audit around the disk-cache write (the durable side effect).
	_ = s.audit.Action(action, map[string]any{
		"id": d.ID, "from_version": fromVersion, "to_version": d.Version, "platform": d.Platform,
	}, func() error {
		return s.persist(d)
	})
	return outcome, nil
}

func (s *Store) persist(d Definition) error {
	if s.dir == "" {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp := filepath.Join(s.dir, d.ID+".json.tmp")
	final := filepath.Join(s.dir, d.ID+".json")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// Get returns a copy of the definition with the given id.
func (s *Store) Get(id string) (Definition, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.defs[id]
	return d, ok
}

// List returns all definitions, sorted by id.
func (s *Store) List() []Definition {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Definition, 0, len(s.defs))
	for _, d := range s.defs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListForHost returns the definitions that target the running OS.
func (s *Store) ListForHost() []Definition {
	out := []Definition{}
	for _, d := range s.List() {
		if d.AppliesHere() {
			out = append(out, d)
		}
	}
	return out
}
