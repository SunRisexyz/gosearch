package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gosearch/core/output"
)

func TestRunRecursiveDoesNotDeadlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	done := make(chan struct{})
	var stats Stats
	var runErr error
	go func() {
		defer close(done)
		_, stats, runErr = Run([]string{server.URL}, Options{
			Words:      []string{"a", "b", "c", "d", "e"},
			Threads:    2,
			Recursive:  true,
			MaxDepth:   3,
			Quiet:      true,
			TimeoutSec: 2,
			Method:     http.MethodGet,
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recursive scan timed out, likely blocked while enqueueing tasks")
	}
	if runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}
	if stats.Scanned == 0 || stats.Total < stats.Scanned {
		t.Fatalf("unexpected stats: total=%d scanned=%d", stats.Total, stats.Scanned)
	}
}

func TestShouldDisplayTracksHostsIndependently(t *testing.T) {
	seen := make(map[string]map[int]map[int]uint64)
	mu := &sync.Mutex{}

	if !shouldDisplay(mu, seen, "a.example", http.StatusOK, 123, 1) {
		t.Fatal("first result for host a should display")
	}
	if shouldDisplay(mu, seen, "a.example", http.StatusOK, 123, 2) {
		t.Fatal("duplicate result for host a should be hidden")
	}
	if !shouldDisplay(mu, seen, "b.example", http.StatusOK, 123, 3) {
		t.Fatal("same status and size on a different host should display")
	}
}

func TestRunResumeSkipsCompletedAndKeepsPreviousResults(t *testing.T) {
	requested := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested[r.URL.Path]++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new-result"))
	}))
	defer server.Close()

	doneURL := server.URL + "/done/"
	resumePath := filepath.Join(t.TempDir(), "resume.jsonl")
	event := resumeEvent{
		Type:  "done",
		URL:   doneURL,
		IsDir: true,
		Depth: 1,
		Result: &output.Result{
			URL:            doneURL,
			Host:           "127.0.0.1",
			StatusCode:     http.StatusOK,
			ResponseSize:   4,
			ScanTime:       time.Now(),
			ResponseTimeMs: 1,
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal resume event: %v", err)
	}
	if err := os.WriteFile(resumePath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write resume file: %v", err)
	}

	results, stats, err := Run([]string{server.URL}, Options{
		Words:      []string{"done", "new.txt"},
		Threads:    2,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodGet,
		Resume:     true,
		ResumePath: resumePath,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if requested["/done/"] != 0 {
		t.Fatalf("completed URL was requested again: %d", requested["/done/"])
	}
	if requested["/new.txt"] != 1 {
		t.Fatalf("new URL request count = %d, want 1", requested["/new.txt"])
	}
	if stats.Total != 2 || stats.Scanned != 2 {
		t.Fatalf("unexpected stats: total=%d scanned=%d", stats.Total, stats.Scanned)
	}
	if len(results) != 2 {
		t.Fatalf("results len = %d, want 2", len(results))
	}
}

func TestRunResumeContinuesRecursiveChildrenFromCompletedDir(t *testing.T) {
	requested := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested[r.URL.Path]++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("child-result"))
	}))
	defer server.Close()

	doneURL := server.URL + "/done/"
	resumePath := filepath.Join(t.TempDir(), "resume.jsonl")
	event := resumeEvent{
		Type:  "done",
		URL:   doneURL,
		IsDir: true,
		Depth: 1,
		Result: &output.Result{
			URL:            doneURL,
			Host:           "127.0.0.1",
			StatusCode:     http.StatusOK,
			ResponseSize:   4,
			ScanTime:       time.Now(),
			ResponseTimeMs: 1,
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal resume event: %v", err)
	}
	if err := os.WriteFile(resumePath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write resume file: %v", err)
	}

	_, _, err = Run([]string{server.URL}, Options{
		Words:      []string{"done", "leaf.txt"},
		Threads:    2,
		Recursive:  true,
		MaxDepth:   2,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodGet,
		Resume:     true,
		ResumePath: resumePath,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if requested["/done/"] != 0 {
		t.Fatalf("completed directory was requested again: %d", requested["/done/"])
	}
	if requested["/done/leaf.txt"] != 1 {
		t.Fatalf("recursive child request count = %d, want 1", requested["/done/leaf.txt"])
	}
}
