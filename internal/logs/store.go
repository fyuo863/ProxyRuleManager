package logs

import (
	"sync"

	"proxy-rule-manager/internal/model"
)

type Store struct {
	mu      sync.RWMutex
	max     int
	entries []model.TrafficLog
}

func NewStore(maxEntries int) *Store {
	if maxEntries <= 0 {
		maxEntries = 500
	}
	return &Store{max: maxEntries, entries: make([]model.TrafficLog, 0, maxEntries)}
}

func (s *Store) SetMax(maxEntries int) {
	if maxEntries <= 0 {
		maxEntries = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.max = maxEntries
	if len(s.entries) > s.max {
		s.entries = s.entries[len(s.entries)-s.max:]
	}
}

func (s *Store) Add(entry model.TrafficLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	if len(s.entries) > s.max {
		s.entries = s.entries[len(s.entries)-s.max:]
	}
}

func (s *Store) Update(id string, mutator func(*model.TrafficLog)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.entries {
		if s.entries[idx].ID == id {
			mutator(&s.entries[idx])
			return
		}
	}
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([]model.TrafficLog, 0, s.max)
}

func (s *Store) List() []model.TrafficLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.TrafficLog, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *Store) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	active := 0
	for _, item := range s.entries {
		if item.Status == model.TrafficStatusActive {
			active++
		}
	}
	return active
}
