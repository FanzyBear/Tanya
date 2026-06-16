package state

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type State struct {
	mu   sync.RWMutex
	path string
	done map[string]bool
}

func New(path string) *State {
	s := &State{path: path, done: make(map[string]bool)}
	s.load()
	return s
}

func (s *State) IsDone(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.done[key]
}

func (s *State) MarkDone(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done[key] {
		return nil
	}
	s.done[key] = true
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, key)
	return err
}

func (s *State) DoneSet() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]bool, len(s.done))
	for k, v := range s.done {
		cp[k] = v
	}
	return cp
}

func (s *State) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = make(map[string]bool)
	s.load()
}

func (s *State) MarkUndone(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done[key] {
		return nil
	}
	delete(s.done, key)
	f, err := os.Create(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	for k := range s.done {
		fmt.Fprintln(f, k)
	}
	return nil
}

func (s *State) load() {
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k := strings.TrimSpace(sc.Text()); k != "" {
			s.done[k] = true
		}
	}
}
