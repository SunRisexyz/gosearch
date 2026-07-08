package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	headers, err := ParseHeaders([]string{
		"Authorization: Bearer token",
		"# comment",
		"X-Test: one",
		"X-Test: two",
	})
	if err != nil {
		t.Fatalf("ParseHeaders returned error: %v", err)
	}
	if got := headers.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer token")
	}
	values := headers.Values("X-Test")
	if len(values) != 2 {
		t.Fatalf("X-Test values len = %d, want 2", len(values))
	}
}

func TestParseHeadersRejectsInvalidLine(t *testing.T) {
	if _, err := ParseHeaders([]string{"Authorization Bearer token"}); err == nil {
		t.Fatal("expected invalid header error")
	}
}

func TestLoadHeadersFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.txt")
	if err := os.WriteFile(path, []byte("X-From-File: yes\n"), 0o600); err != nil {
		t.Fatalf("write headers file: %v", err)
	}
	headers, err := LoadHeaders([]string{"X-From-CLI: yes"}, path)
	if err != nil {
		t.Fatalf("LoadHeaders returned error: %v", err)
	}
	if headers.Get("X-From-CLI") != "yes" || headers.Get("X-From-File") != "yes" {
		t.Fatalf("headers not loaded correctly: %#v", headers)
	}
}

func TestMergeHeadersOverridesBase(t *testing.T) {
	base, err := ParseHeaders([]string{"Authorization: Bearer raw", "X-Base: yes"})
	if err != nil {
		t.Fatalf("ParseHeaders base: %v", err)
	}
	override, err := ParseHeaders([]string{"Authorization: Bearer cli"})
	if err != nil {
		t.Fatalf("ParseHeaders override: %v", err)
	}
	merged := MergeHeaders(base, override)
	if got := merged.Get("Authorization"); got != "Bearer cli" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer cli")
	}
	if got := merged.Get("X-Base"); got != "yes" {
		t.Fatalf("X-Base = %q, want yes", got)
	}
}

func TestParseHTTPMethods(t *testing.T) {
	methods, err := ParseHTTPMethods("GET,HEAD,OPTIONS,head", "GET")
	if err != nil {
		t.Fatalf("ParseHTTPMethods returned error: %v", err)
	}
	if len(methods) != 2 || methods[0] != "HEAD" || methods[1] != "OPTIONS" {
		t.Fatalf("methods = %#v, want HEAD,OPTIONS", methods)
	}
}

func TestParseHTTPMethodsRejectsInvalidToken(t *testing.T) {
	if _, err := ParseHTTPMethods("BAD METHOD", "GET"); err == nil {
		t.Fatal("expected invalid method error")
	}
}
