package scanner

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestRunAddsFingerprintsWhenEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>Swagger UI</title><body>wp-content swagger-ui</body></html>`))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:       []string{"wp-login.php"},
		Threads:     1,
		Quiet:       true,
		TimeoutSec:  2,
		Method:      http.MethodGet,
		Fingerprint: true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].Title != "Swagger UI" {
		t.Fatalf("title = %q, want %q", results[0].Title, "Swagger UI")
	}
	if len(results[0].Fingerprints) == 0 {
		t.Fatal("expected fingerprint findings")
	}
	if results[0].RiskLevel == "" {
		t.Fatal("expected risk level")
	}
}

func TestRunAdaptiveWordlistEnqueuesFingerprintPaths(t *testing.T) {
	requested := make(map[string]int)
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>WordPress</title><body>wp-content</body></html>`))
	}))
	defer server.Close()

	_, stats, err := Run([]string{server.URL}, Options{
		Words:            []string{"wp-login.php"},
		Threads:          2,
		Quiet:            true,
		TimeoutSec:       2,
		Method:           http.MethodGet,
		AdaptiveWordlist: true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	mu.Lock()
	wpJSONCount := requested["/wp-json/"]
	mu.Unlock()
	if wpJSONCount != 1 {
		t.Fatalf("adaptive wp-json request count = %d, want 1", wpJSONCount)
	}
	if stats.Total <= 1 {
		t.Fatalf("adaptive scan total = %d, want more than initial task", stats.Total)
	}
}

func TestRunSoft404FiltersBaselineLikeResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>Not Found</title><body>missing page</body></html>`))
	}))
	defer server.Close()

	results, stats, err := Run([]string{server.URL}, Options{
		Words:                []string{"admin"},
		Threads:              1,
		Quiet:                true,
		TimeoutSec:           2,
		Method:               http.MethodGet,
		Soft404:              true,
		Soft404Samples:       1,
		Soft404SizeTolerance: 0,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("results len = %d, want 0", len(results))
	}
	if stats.Total != 1 || stats.Scanned != 1 {
		t.Fatalf("unexpected stats: total=%d scanned=%d", stats.Total, stats.Scanned)
	}
}

func TestRunSoft404KeepsDifferentResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, ".gosearch-not-found-") {
			_, _ = w.Write([]byte(`<html><title>Not Found</title><body>missing page</body></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><title>Admin Panel</title><body>real admin panel content</body></html>`))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:                []string{"admin"},
		Threads:              1,
		Quiet:                true,
		TimeoutSec:           2,
		Method:               http.MethodGet,
		Soft404:              true,
		Soft404Samples:       1,
		Soft404SizeTolerance: 0,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].Title != "Admin Panel" {
		t.Fatalf("title = %q, want %q", results[0].Title, "Admin Panel")
	}
}

func TestRunRiskScoreMarksSensitivePaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("APP_KEY=secret"))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:      []string{".env"},
		Threads:    1,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodGet,
		RiskScore:  true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].RiskLevel != "critical" {
		t.Fatalf("risk level = %q, want critical", results[0].RiskLevel)
	}
	if results[0].RiskScore == 0 {
		t.Fatal("expected risk score")
	}
}

func TestRunMinRiskFiltersLowPriorityResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:      []string{"robots.txt", ".env"},
		Threads:    1,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodGet,
		RiskScore:  true,
		MinRisk:    "high",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if !strings.HasSuffix(results[0].URL, "/.env") {
		t.Fatalf("result URL = %s, want .env", results[0].URL)
	}
}

func TestRunSendsCustomHeadersCookieAndHost(t *testing.T) {
	var gotAuth string
	var gotCookie string
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:      []string{"admin"},
		Threads:    1,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodGet,
		Headers: http.Header{
			"Authorization": []string{"Bearer token"},
			"Host":          []string{"vhost.example"},
		},
		Cookie: "sid=abc",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer token")
	}
	if gotCookie != "sid=abc" {
		t.Fatalf("Cookie = %q, want %q", gotCookie, "sid=abc")
	}
	if gotHost != "vhost.example" {
		t.Fatalf("Host = %q, want %q", gotHost, "vhost.example")
	}
}

func TestRunSendsRequestBody(t *testing.T) {
	var gotMethod string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:      []string{"api"},
		Threads:    1,
		Quiet:      true,
		TimeoutSec: 2,
		Method:     http.MethodPost,
		Body:       []byte("payload"),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotBody != "payload" {
		t.Fatalf("body = %q, want payload", gotBody)
	}
}

func TestRunDiscoverImportsRobotsAndSitemapPaths(t *testing.T) {
	requested := make(map[string]int)
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Disallow: /from-robots/\nSitemap: /sitemap.xml\n"))
		case "/sitemap.xml":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<urlset><url><loc>` + "http://" + r.Host + `/from-sitemap</loc></url></urlset>`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer server.Close()

	_, stats, err := Run([]string{server.URL}, Options{
		Words:       []string{"base"},
		Threads:     1,
		Quiet:       true,
		TimeoutSec:  2,
		Method:      http.MethodGet,
		Discover:    true,
		DiscoverMax: 10,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	mu.Lock()
	fromRobots := requested["/from-robots/"]
	fromSitemap := requested["/from-sitemap"]
	mu.Unlock()
	if fromRobots != 1 {
		t.Fatalf("from-robots request count = %d, want 1", fromRobots)
	}
	if fromSitemap != 1 {
		t.Fatalf("from-sitemap request count = %d, want 1", fromSitemap)
	}
	if stats.Total != 3 {
		t.Fatalf("stats total = %d, want 3", stats.Total)
	}
}

func TestRunBackupVariantsEnqueuesBackupPathsWithoutCascade(t *testing.T) {
	requested := make(map[string]int)
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, stats, err := Run([]string{server.URL}, Options{
		Words:            []string{"config.php"},
		Threads:          2,
		Quiet:            true,
		TimeoutSec:       2,
		Method:           http.MethodGet,
		BackupVariants:   true,
		BackupVariantMax: 3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	mu.Lock()
	configBackup := requested["/config.php.bak"]
	cascade := requested["/config.php.bak.bak"]
	mu.Unlock()
	if configBackup != 1 {
		t.Fatalf("config.php.bak request count = %d, want 1", configBackup)
	}
	if cascade != 0 {
		t.Fatalf("cascaded backup request count = %d, want 0", cascade)
	}
	if stats.Total != 4 {
		t.Fatalf("stats total = %d, want 4", stats.Total)
	}
}

func TestRunMethodProbesAfterHit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET,HEAD,OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer server.Close()

	results, _, err := Run([]string{server.URL}, Options{
		Words:        []string{"admin"},
		Threads:      1,
		Quiet:        true,
		TimeoutSec:   2,
		Method:       http.MethodGet,
		ProbeMethods: []string{http.MethodHead, http.MethodOptions},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].Method != http.MethodGet {
		t.Fatalf("method = %q, want GET", results[0].Method)
	}
	if len(results[0].MethodProbes) != 2 {
		t.Fatalf("method probes len = %d, want 2", len(results[0].MethodProbes))
	}
	if results[0].MethodProbes[0].Method != http.MethodHead || results[0].MethodProbes[0].StatusCode != http.StatusOK {
		t.Fatalf("HEAD probe = %#v", results[0].MethodProbes[0])
	}
	if results[0].MethodProbes[1].Method != http.MethodOptions || results[0].MethodProbes[1].Allow != "GET,HEAD,OPTIONS" {
		t.Fatalf("OPTIONS probe = %#v", results[0].MethodProbes[1])
	}
}
