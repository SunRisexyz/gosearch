package utils

import "testing"

func TestParseRawRequestRelativeURL(t *testing.T) {
	raw := "POST /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token\r\nCookie: sid=abc\r\nContent-Length: 7\r\n\r\npayload"
	req, err := ParseRawRequest(raw, "https")
	if err != nil {
		t.Fatalf("ParseRawRequest returned error: %v", err)
	}
	if req.Target != "https://example.com/" {
		t.Fatalf("target = %q, want %q", req.Target, "https://example.com/")
	}
	if req.Method != "POST" {
		t.Fatalf("method = %q, want POST", req.Method)
	}
	if req.Headers.Get("Authorization") != "Bearer token" {
		t.Fatalf("Authorization = %q", req.Headers.Get("Authorization"))
	}
	if req.Headers.Get("Cookie") != "sid=abc" {
		t.Fatalf("Cookie = %q", req.Headers.Get("Cookie"))
	}
	if string(req.Body) != "payload" {
		t.Fatalf("body = %q, want payload", string(req.Body))
	}
}

func TestParseRawRequestAbsoluteURL(t *testing.T) {
	raw := "GET https://example.com/admin HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
	req, err := ParseRawRequest(raw, "http")
	if err != nil {
		t.Fatalf("ParseRawRequest returned error: %v", err)
	}
	if req.Target != "https://example.com/" {
		t.Fatalf("target = %q, want %q", req.Target, "https://example.com/")
	}
}

func TestParseRawRequestRequiresHostForRelativeURL(t *testing.T) {
	raw := "GET /admin HTTP/1.1\r\n\r\n"
	if _, err := ParseRawRequest(raw, "http"); err == nil {
		t.Fatal("expected missing host error")
	}
}
