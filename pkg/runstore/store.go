package runstore

import (
	"sync"
	"time"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/report"
)

// Status is the lifecycle state of a run.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Run is a persisted audit execution.
type Run struct {
	ID         string           `json:"id"`
	Cloud      string           `json:"cloud"`
	PolicyPath string           `json:"policy_path,omitempty"`
	Apply      bool             `json:"apply"`
	AllTenants bool             `json:"all_tenants"`
	Status     Status           `json:"status"`
	Error      string           `json:"error,omitempty"`
	Summary    report.Summary   `json:"summary"`
	Findings   []report.Finding `json:"findings"`
	CreatedAt  time.Time        `json:"created_at"`
	StartedAt  time.Time        `json:"started_at,omitempty"`
	FinishedAt time.Time        `json:"finished_at,omitempty"`
}

// Event is a live update for subscribers.
type Event struct {
	Kind    string // finding | status | summary
	Finding *report.Finding
	Status  Status
	Summary *report.Summary
	Error   string
}

// Store keeps runs in memory (v1).
type Store struct {
	mu   sync.RWMutex
	runs map[string]*Run
	subs map[string][]chan Event
}

// New creates an empty in-memory store.
func New() *Store {
	return &Store{
		runs: make(map[string]*Run),
		subs: make(map[string][]chan Event),
	}
}

// Create registers a new run in queued state.
func (s *Store) Create(id, cloud, policyPath string, apply, allTenants bool) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := &Run{
		ID:         id,
		Cloud:      cloud,
		PolicyPath: policyPath,
		Apply:      apply,
		AllTenants: allTenants,
		Status:     StatusQueued,
		Findings:   make([]report.Finding, 0),
		CreatedAt:  time.Now().UTC(),
	}
	s.runs[id] = run
	return cloneRun(run)
}

// Get returns a copy of a run.
func (s *Store) Get(id string) (*Run, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[id]
	if !ok {
		return nil, false
	}
	return cloneRun(run), true
}

// List returns runs newest-first.
func (s *Store) List() []*Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Run, 0, len(s.runs))
	for _, run := range s.runs {
		out = append(out, cloneRun(run))
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// SetStatus updates run status and notifies subscribers.
func (s *Store) SetStatus(id string, status Status, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return
	}
	run.Status = status
	run.Error = errMsg
	now := time.Now().UTC()
	switch status {
	case StatusRunning:
		run.StartedAt = now
	case StatusCompleted, StatusFailed, StatusCancelled:
		run.FinishedAt = now
	}
	s.broadcastLocked(id, Event{Kind: "status", Status: status, Error: errMsg})
}

// AppendFinding stores a finding and notifies subscribers.
func (s *Store) AppendFinding(id string, f report.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return
	}
	run.Findings = append(run.Findings, f)
	cp := f
	s.broadcastLocked(id, Event{Kind: "finding", Finding: &cp})
}

// SetSummary stores the final summary.
func (s *Store) SetSummary(id string, summary report.Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return
	}
	run.Summary = summary
	cp := summary
	s.broadcastLocked(id, Event{Kind: "summary", Summary: &cp})
}

// Subscribe receives live events. Caller must Unsubscribe.
func (s *Store) Subscribe(id string) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	s.mu.Lock()
	s.subs[id] = append(s.subs[id], ch)
	s.mu.Unlock()
	unsub := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		list := s.subs[id]
		for i, c := range list {
			if c == ch {
				s.subs[id] = append(list[:i], list[i+1:]...)
				break
			}
		}
		close(ch)
	}
	return ch, unsub
}

func (s *Store) broadcastLocked(id string, ev Event) {
	for _, ch := range s.subs[id] {
		select {
		case ch <- ev:
		default:
			// drop if subscriber is slow
		}
	}
}

func cloneRun(run *Run) *Run {
	cp := *run
	if run.Findings != nil {
		cp.Findings = append([]report.Finding(nil), run.Findings...)
	}
	return &cp
}
