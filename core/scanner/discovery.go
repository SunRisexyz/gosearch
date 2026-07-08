package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const discoveryBodyLimit = 2 * 1024 * 1024

type sitemapURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

type sitemapIndex struct {
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func discoverPaths(ctx context.Context, bases []string, client *http.Client, directClient *http.Client, opts Options) map[string][]string {
	maxPaths := opts.DiscoverMax
	if maxPaths < 1 {
		maxPaths = 200
	}
	discovered := make(map[string][]string, len(bases))
	for _, base := range bases {
		seen := make(map[string]struct{})
		paths := make([]string, 0)

		robotsURL := joinURL(base, "robots.txt", false)
		if body, ok := fetchDiscoveryBody(ctx, robotsURL, client, directClient, opts); ok {
			robotsPaths, sitemapURLs := parseRobots(body, base)
			paths = appendUniqueLimited(paths, robotsPaths, seen, maxPaths)
			for _, sitemapURL := range sitemapURLs {
				if len(paths) >= maxPaths {
					break
				}
				sitemapPaths := discoverSitemapPaths(ctx, sitemapURL, base, client, directClient, opts, 0)
				paths = appendUniqueLimited(paths, sitemapPaths, seen, maxPaths)
			}
		}

		if len(paths) < maxPaths {
			sitemapURL := joinURL(base, "sitemap.xml", false)
			if _, ok := seen["sitemap.xml"]; !ok {
				sitemapPaths := discoverSitemapPaths(ctx, sitemapURL, base, client, directClient, opts, 0)
				paths = appendUniqueLimited(paths, sitemapPaths, seen, maxPaths)
			}
		}
		discovered[base] = paths
	}
	return discovered
}

func discoverSitemapPaths(ctx context.Context, sitemapURL string, base string, client *http.Client, directClient *http.Client, opts Options, depth int) []string {
	if depth > 1 {
		return nil
	}
	body, ok := fetchDiscoveryBody(ctx, sitemapURL, client, directClient, opts)
	if !ok {
		return nil
	}

	paths := parseSitemapURLSet(body, base)
	if len(paths) > 0 {
		return paths
	}

	nested := parseSitemapIndex(body, base)
	out := make([]string, 0)
	for _, nestedURL := range nested {
		out = append(out, discoverSitemapPaths(ctx, nestedURL, base, client, directClient, opts, depth+1)...)
	}
	return out
}

func fetchDiscoveryBody(ctx context.Context, target string, client *http.Client, directClient *http.Client, opts Options) ([]byte, bool) {
	discoveryOpts := opts
	discoveryOpts.Method = http.MethodGet
	discoveryOpts.Body = nil
	req, err := newScanRequest(ctx, target, discoveryOpts)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil && directClient != nil && !opts.NoProxyFallback {
		directReq, reqErr := newScanRequest(ctx, target, discoveryOpts)
		if reqErr != nil {
			return nil, false
		}
		resp, err = directClient.Do(directReq)
	}
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryBodyLimit))
	if err != nil {
		return nil, false
	}
	return body, true
}

func parseRobots(body []byte, base string) ([]string, []string) {
	paths := make([]string, 0)
	sitemaps := make([]string, 0)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "allow", "disallow":
			if normalized := normalizeDiscoveredPath(value, base); normalized != "" {
				paths = append(paths, normalized)
			}
		case "sitemap":
			if sitemapURL := normalizeDiscoveredURL(value, base); sitemapURL != "" {
				sitemaps = append(sitemaps, sitemapURL)
			}
		}
	}
	return paths, sitemaps
}

func parseSitemapURLSet(body []byte, base string) []string {
	var payload sitemapURLSet
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&payload); err != nil {
		return nil
	}
	paths := make([]string, 0, len(payload.URLs))
	for _, item := range payload.URLs {
		if normalized := normalizeDiscoveredPath(item.Loc, base); normalized != "" {
			paths = append(paths, normalized)
		}
	}
	return paths
}

func parseSitemapIndex(body []byte, base string) []string {
	var payload sitemapIndex
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&payload); err != nil {
		return nil
	}
	urls := make([]string, 0, len(payload.Sitemaps))
	for _, item := range payload.Sitemaps {
		if normalized := normalizeDiscoveredURL(item.Loc, base); normalized != "" {
			urls = append(urls, normalized)
		}
	}
	return urls
}

func normalizeDiscoveredPath(value string, base string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" || strings.HasPrefix(value, "#") {
		return ""
	}
	parsedBase, err := url.Parse(base)
	if err != nil {
		return ""
	}
	parsed, err := parsedBase.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !sameHost(parsedBase, parsed) {
		return ""
	}
	path := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if path == "" {
		return ""
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func normalizeDiscoveredURL(value string, base string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsedBase, err := url.Parse(base)
	if err != nil {
		return ""
	}
	parsed, err := parsedBase.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !sameHost(parsedBase, parsed) {
		return ""
	}
	return parsed.String()
}

func sameHost(a *url.URL, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname())
}

func appendUniqueLimited(base []string, values []string, seen map[string]struct{}, limit int) []string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		base = append(base, value)
		if len(base) >= limit {
			return base
		}
	}
	return base
}
