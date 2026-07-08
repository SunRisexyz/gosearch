package fingerprint

import (
	"net/http"
	"testing"
)

func TestExtractTitle(t *testing.T) {
	title := ExtractTitle([]byte("<html><title>  Hello&nbsp;World  </title></html>"))
	if title != "Hello World" {
		t.Fatalf("title = %q, want %q", title, "Hello World")
	}
}

func TestEngineMatchesHeaderBodyTitleAndPath(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Name:       "WordPress",
			Category:   "CMS",
			Risk:       RiskLow,
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "body", Contains: "wp-content"},
				{Type: "path", Contains: "wp-login.php"},
			},
		},
		{
			Name:       "Nginx",
			Category:   "Middleware",
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "nginx"},
			},
		},
		{
			Name:       "Swagger UI",
			Category:   "Sensitive Component",
			Risk:       RiskMedium,
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "title", Contains: "Swagger UI"},
			},
		},
	})

	headers := http.Header{}
	headers.Set("Server", "nginx/1.24")
	obs := BuildObservation("https://example.com/wp-login.php", headers, "Swagger UI", []byte("/wp-content/themes/a"), "")
	findings := engine.Match(obs)

	if len(findings) != 3 {
		t.Fatalf("findings len = %d, want 3", len(findings))
	}
	if HighestRisk(findings) != RiskMedium {
		t.Fatalf("highest risk = %q, want %q", HighestRisk(findings), RiskMedium)
	}
}
