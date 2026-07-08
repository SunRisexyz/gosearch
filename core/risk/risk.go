package risk

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"gosearch/core/fingerprint"
	"gosearch/core/output"
)

type Rule struct {
	Name       string
	Level      fingerprint.RiskLevel
	Tags       []string
	Contains   []string
	Suffixes   []string
	Regex      *regexp.Regexp
	Require2xx bool
}

var pathRules = []Rule{
	{Name: "environment file exposure", Level: fingerprint.RiskCritical, Tags: []string{"secret", "config-leak"}, Contains: []string{"/.env"}, Require2xx: true},
	{Name: "git config exposure", Level: fingerprint.RiskCritical, Tags: []string{"source-leak", "secret"}, Contains: []string{"/.git/config"}, Require2xx: true},
	{Name: "private key exposure", Level: fingerprint.RiskCritical, Tags: []string{"secret", "key-leak"}, Suffixes: []string{"id_rsa", ".pem", ".key"}, Require2xx: true},
	{Name: "git metadata path", Level: fingerprint.RiskHigh, Tags: []string{"source-leak"}, Contains: []string{"/.git/"}},
	{Name: "svn metadata path", Level: fingerprint.RiskHigh, Tags: []string{"source-leak"}, Contains: []string{"/.svn/"}},
	{Name: "database dump path", Level: fingerprint.RiskHigh, Tags: []string{"database", "backup"}, Suffixes: []string{".sql", ".sqlite", ".db"}},
	{Name: "backup archive path", Level: fingerprint.RiskHigh, Tags: []string{"backup"}, Suffixes: []string{".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar", ".bak"}},
	{Name: "phpinfo exposure", Level: fingerprint.RiskHigh, Tags: []string{"php", "info-leak"}, Contains: []string{"phpinfo.php"}},
	{Name: "spring actuator sensitive endpoint", Level: fingerprint.RiskHigh, Tags: []string{"java", "actuator"}, Contains: []string{"/actuator/env", "/actuator/heapdump", "/actuator/logfile"}},
	{Name: "swagger api docs", Level: fingerprint.RiskMedium, Tags: []string{"api-docs"}, Contains: []string{"swagger", "api-docs", "openapi.json"}},
	{Name: "admin surface", Level: fingerprint.RiskMedium, Tags: []string{"admin-surface"}, Contains: []string{"/admin", "/manager", "/login", "/console"}},
	{Name: "server status endpoint", Level: fingerprint.RiskMedium, Tags: []string{"status", "info-leak"}, Contains: []string{"server-status", "nginx_status", "status.php"}},
	{Name: "robots or sitemap", Level: fingerprint.RiskInfo, Tags: []string{"discovery"}, Suffixes: []string{"robots.txt", "sitemap.xml"}},
}

func Apply(res *output.Result) {
	if res == nil {
		return
	}
	for _, rule := range pathRules {
		if !matchesRule(*res, rule) {
			continue
		}
		merge(res, rule.Level, rule.Tags, rule.Name)
	}
	if len(res.Fingerprints) > 0 {
		for _, finding := range res.Fingerprints {
			merge(res, finding.Risk, finding.Tags, "fingerprint: "+finding.Name)
		}
	}
	if res.RiskLevel != "" {
		res.RiskScore = score(res.RiskLevel, res.StatusCode)
	}
}

func MeetsMin(level fingerprint.RiskLevel, min fingerprint.RiskLevel) bool {
	if min == "" {
		return true
	}
	return Rank(level) >= Rank(min)
}

func ParseLevel(raw string) (fingerprint.RiskLevel, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "", nil
	}
	switch raw {
	case string(fingerprint.RiskInfo), string(fingerprint.RiskLow), string(fingerprint.RiskMedium), string(fingerprint.RiskHigh), string(fingerprint.RiskCritical):
		return fingerprint.RiskLevel(raw), nil
	default:
		return "", errors.New("min-risk must be one of: info,low,medium,high,critical")
	}
}

func Rank(level fingerprint.RiskLevel) int {
	switch strings.ToLower(string(level)) {
	case string(fingerprint.RiskCritical):
		return 5
	case string(fingerprint.RiskHigh):
		return 4
	case string(fingerprint.RiskMedium):
		return 3
	case string(fingerprint.RiskLow):
		return 2
	case string(fingerprint.RiskInfo):
		return 1
	default:
		return 0
	}
}

func Summary(results []output.Result) map[string]int {
	summary := map[string]int{
		string(fingerprint.RiskCritical): 0,
		string(fingerprint.RiskHigh):     0,
		string(fingerprint.RiskMedium):   0,
		string(fingerprint.RiskLow):      0,
		string(fingerprint.RiskInfo):     0,
	}
	for _, res := range results {
		if res.RiskLevel == "" {
			continue
		}
		summary[string(res.RiskLevel)]++
	}
	return summary
}

func TopFindings(results []output.Result, limit int) []output.Result {
	if limit <= 0 {
		return nil
	}
	copied := make([]output.Result, len(results))
	copy(copied, results)
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].RiskScore != copied[j].RiskScore {
			return copied[i].RiskScore > copied[j].RiskScore
		}
		return copied[i].URL < copied[j].URL
	})
	if len(copied) > limit {
		copied = copied[:limit]
	}
	return copied
}

func matchesRule(res output.Result, rule Rule) bool {
	if rule.Require2xx && (res.StatusCode < 200 || res.StatusCode >= 300) {
		return false
	}
	normalized := normalizedPath(res.URL)
	if normalized == "" {
		return false
	}
	if rule.Regex != nil && rule.Regex.MatchString(normalized) {
		return true
	}
	for _, term := range rule.Contains {
		if strings.Contains(normalized, strings.ToLower(term)) {
			return true
		}
	}
	for _, suffix := range rule.Suffixes {
		if strings.HasSuffix(normalized, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func normalizedPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	value := parsed.EscapedPath()
	if parsed.RawQuery != "" {
		value += "?" + parsed.RawQuery
	}
	return strings.ToLower(path.Clean("/" + strings.TrimPrefix(value, "/")))
}

func merge(res *output.Result, level fingerprint.RiskLevel, tags []string, reason string) {
	if level == "" {
		level = fingerprint.RiskInfo
	}
	if Rank(level) > Rank(res.RiskLevel) {
		res.RiskLevel = level
	}
	res.Tags = mergeStrings(res.Tags, tags)
	if reason != "" {
		res.RiskReasons = mergeStrings(res.RiskReasons, []string{reason})
	}
}

func mergeStrings(base []string, values []string) []string {
	seen := make(map[string]struct{}, len(base)+len(values))
	out := make([]string, 0, len(base)+len(values))
	for _, value := range append(base, values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func score(level fingerprint.RiskLevel, statusCode int) int {
	base := map[fingerprint.RiskLevel]int{
		fingerprint.RiskCritical: 90,
		fingerprint.RiskHigh:     70,
		fingerprint.RiskMedium:   50,
		fingerprint.RiskLow:      30,
		fingerprint.RiskInfo:     10,
	}[level]
	switch {
	case statusCode >= 200 && statusCode < 300:
		base += 8
	case statusCode == http.StatusForbidden:
		base += 4
	case statusCode >= 300 && statusCode < 400:
		base += 2
	}
	return base
}
