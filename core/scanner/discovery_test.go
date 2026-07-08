package scanner

import "testing"

func TestParseRobots(t *testing.T) {
	body := []byte(`
User-agent: *
Disallow: /admin/
Allow: /public/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://other.example/sitemap.xml
`)
	paths, sitemaps := parseRobots(body, "https://example.com/")
	if len(paths) != 2 {
		t.Fatalf("paths len = %d, want 2: %#v", len(paths), paths)
	}
	if paths[0] != "admin/" || paths[1] != "public/" {
		t.Fatalf("paths = %#v", paths)
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://example.com/sitemap.xml" {
		t.Fatalf("sitemaps = %#v", sitemaps)
	}
}

func TestParseSitemapURLSet(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<urlset>
  <url><loc>https://example.com/from-sitemap</loc></url>
  <url><loc>https://other.example/ignored</loc></url>
</urlset>`)
	paths := parseSitemapURLSet(body, "https://example.com/")
	if len(paths) != 1 || paths[0] != "from-sitemap" {
		t.Fatalf("paths = %#v", paths)
	}
}
