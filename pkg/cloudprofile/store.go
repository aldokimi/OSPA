package cloudprofile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Source identifies where a profile's credentials come from.
type Source string

const (
	SourceLocal  Source = "local"  // clouds.yaml entry (opt-in connect)
	SourceRemote Source = "remote" // explicit credentials
)

// Profile is a saved cloud connection definition.
type Profile struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Source            Source    `json:"source"`
	LocalCloud        string    `json:"local_cloud,omitempty"`
	AuthURL           string    `json:"auth_url,omitempty"`
	Username          string    `json:"username,omitempty"`
	Password          string    `json:"password,omitempty"`
	ProjectName       string    `json:"project_name,omitempty"`
	ProjectID         string    `json:"project_id,omitempty"`
	UserDomainName    string    `json:"user_domain_name,omitempty"`
	ProjectDomainName string    `json:"project_domain_name,omitempty"`
	RegionName        string    `json:"region_name,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Public returns a copy safe for UI templates (password redacted).
func (p Profile) Public() Profile {
	cp := p
	if cp.Password != "" {
		cp.Password = "********"
	}
	return cp
}

// Store persists profiles and the active connection choice.
type Store struct {
	mu       sync.RWMutex
	path     string
	profiles map[string]Profile
	activeID string
}

type diskState struct {
	ActiveID string             `json:"active_id,omitempty"`
	Profiles map[string]Profile `json:"profiles"`
}

// Open loads or creates a profile store at path.
func Open(path string) (*Store, error) {
	s := &Store{
		path:     path,
		profiles: map[string]Profile{},
	}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var state diskState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("parse profiles: %w", err)
	}
	if state.Profiles != nil {
		s.profiles = state.Profiles
	}
	s.activeID = state.ActiveID
	return s, nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	state := diskState{ActiveID: s.activeID, Profiles: s.profiles}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// List returns profiles sorted by name (passwords redacted).
func (s *Store) List() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a full profile including password (for connecting).
func (s *Store) Get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

// ActiveID returns the last selected profile id (may not be live-connected).
func (s *Store) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID
}

// SetActive records which profile the user selected.
func (s *Store) SetActive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		if _, ok := s.profiles[id]; !ok {
			return fmt.Errorf("profile %q not found", id)
		}
	}
	s.activeID = id
	return s.saveLocked()
}

// Upsert creates or updates a profile.
func (s *Store) Upsert(p Profile) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if p.ID == "" {
		p.ID = newID()
		p.CreatedAt = now
	} else if existing, ok := s.profiles[p.ID]; ok {
		p.CreatedAt = existing.CreatedAt
		if p.Password == "" || p.Password == "********" {
			p.Password = existing.Password
		}
	} else {
		p.CreatedAt = now
	}
	if p.Name == "" {
		return Profile{}, fmt.Errorf("name is required")
	}
	if p.Source == SourceLocal && p.LocalCloud == "" {
		return Profile{}, fmt.Errorf("local_cloud is required for local profiles")
	}
	if p.Source == SourceRemote && p.AuthURL == "" {
		return Profile{}, fmt.Errorf("auth_url is required for remote profiles")
	}
	p.UpdatedAt = now
	s.profiles[p.ID] = p
	if err := s.saveLocked(); err != nil {
		return Profile{}, err
	}
	return p.Public(), nil
}

// Delete removes a profile.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[id]; !ok {
		return fmt.Errorf("profile %q not found", id)
	}
	delete(s.profiles, id)
	if s.activeID == id {
		s.activeID = ""
	}
	return s.saveLocked()
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// DefaultPath returns ~/.config/ospa/profiles.json
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "data/profiles.json"
	}
	return filepath.Join(home, ".config", "ospa", "profiles.json")
}
