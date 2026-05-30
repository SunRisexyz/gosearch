package scanner

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"gosearch/core/output"
)

type resumeCompleted struct {
	IsDir     bool `json:"is_dir"`
	Depth     int  `json:"depth"`
	HadResult bool `json:"had_result"`
}

type resumeEvent struct {
	Type   string         `json:"type"`
	URL    string         `json:"url"`
	IsDir  bool           `json:"is_dir"`
	Depth  int            `json:"depth"`
	Result *output.Result `json:"result,omitempty"`
}

type resumeStore struct {
	mu        sync.Mutex
	file      *os.File
	completed map[string]resumeCompleted
	results   []output.Result
	err       error
}

func openResumeStore(path string) (*resumeStore, error) {
	if path == "" {
		return nil, errors.New("resume-file is required when resume is enabled")
	}
	store := &resumeStore{
		completed: make(map[string]resumeCompleted),
	}
	if err := store.load(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	store.file = file
	return store, nil
}

func (s *resumeStore) load(path string) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	seenResults := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event resumeEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		if event.Type != "done" || event.URL == "" {
			continue
		}
		s.completed[event.URL] = resumeCompleted{
			IsDir:     event.IsDir,
			Depth:     event.Depth,
			HadResult: event.Result != nil,
		}
		if event.Result != nil {
			if _, ok := seenResults[event.URL]; ok {
				continue
			}
			seenResults[event.URL] = struct{}{}
			s.results = append(s.results, *event.Result)
		}
	}
	return scanner.Err()
}

func (s *resumeStore) completedInfo(url string) (resumeCompleted, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.completed[url]
	return info, ok
}

func (s *resumeStore) recordDone(t task, result *output.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	if _, ok := s.completed[t.url]; ok {
		return
	}
	event := resumeEvent{
		Type:   "done",
		URL:    t.url,
		IsDir:  t.isDir,
		Depth:  t.depth,
		Result: result,
	}
	data, err := json.Marshal(event)
	if err == nil {
		_, err = s.file.Write(append(data, '\n'))
	}
	if err != nil {
		s.err = err
		return
	}
	s.completed[t.url] = resumeCompleted{
		IsDir:     t.isDir,
		Depth:     t.depth,
		HadResult: result != nil,
	}
}

func (s *resumeStore) previousResults() []output.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]output.Result, len(s.results))
	copy(results, s.results)
	return results
}

func (s *resumeStore) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return s.err
	}
	if err := s.file.Close(); err != nil && s.err == nil {
		s.err = err
	}
	return s.err
}

func (s *resumeStore) recordErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
