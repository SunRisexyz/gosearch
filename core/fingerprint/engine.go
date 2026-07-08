package fingerprint

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	copied := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.Name) == "" || len(rule.Matchers) == 0 {
			continue
		}
		if rule.Confidence <= 0 {
			rule.Confidence = 80
		}
		if rule.Risk == "" {
			rule.Risk = RiskInfo
		}
		copied = append(copied, rule)
	}
	return &Engine{rules: copied}
}

func (e *Engine) Match(obs Observation) []Finding {
	if e == nil || len(e.rules) == 0 {
		return nil
	}
	findings := make([]Finding, 0, 4)
	for _, rule := range e.rules {
		evidence, ok := matchRule(rule, obs)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Name:       rule.Name,
			Category:   rule.Category,
			Confidence: rule.Confidence,
			Risk:       rule.Risk,
			Tags:       uniqueStrings(rule.Tags),
			Evidence:   evidence,
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if riskRank(findings[i].Risk) != riskRank(findings[j].Risk) {
			return riskRank(findings[i].Risk) > riskRank(findings[j].Risk)
		}
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		return findings[i].Name < findings[j].Name
	})
	return findings
}

func BuildObservation(rawURL string, headers http.Header, title string, body []byte, faviconHash string) Observation {
	pathValue := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		pathValue = parsed.EscapedPath()
	}
	headerCopy := make(map[string][]string, len(headers))
	for key, values := range headers {
		copied := make([]string, len(values))
		copy(copied, values)
		headerCopy[http.CanonicalHeaderKey(key)] = copied
	}
	return Observation{
		URL:         rawURL,
		Path:        pathValue,
		Headers:     headerCopy,
		Title:       title,
		Body:        string(body),
		FaviconHash: faviconHash,
	}
}

func HighestRisk(findings []Finding) RiskLevel {
	highest := RiskInfo
	for _, finding := range findings {
		if riskRank(finding.Risk) > riskRank(highest) {
			highest = finding.Risk
		}
	}
	return highest
}

func Tags(findings []Finding) []string {
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	for _, finding := range findings {
		if finding.Category != "" {
			key := strings.ToLower(finding.Category)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				tags = append(tags, finding.Category)
			}
		}
		for _, tag := range finding.Tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			key := strings.ToLower(tag)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return tags
}

func matchRule(rule Rule, obs Observation) ([]string, bool) {
	mode := strings.ToLower(strings.TrimSpace(rule.MatchMode))
	if mode == "" {
		mode = "any"
	}

	evidence := make([]string, 0, len(rule.Matchers))
	matched := 0
	for _, matcher := range rule.Matchers {
		item, ok := matchOne(matcher, obs)
		if !ok {
			if mode == "all" {
				return nil, false
			}
			continue
		}
		matched++
		evidence = append(evidence, item)
	}
	if mode == "all" {
		return evidence, matched == len(rule.Matchers)
	}
	return evidence, matched > 0
}

func matchOne(m Matcher, obs Observation) (string, bool) {
	matcherType := strings.ToLower(strings.TrimSpace(m.Type))
	switch matcherType {
	case "header":
		return matchHeader(m, obs)
	case "title":
		return matchText("title", obs.Title, m)
	case "body":
		return matchText("body", obs.Body, m)
	case "path":
		return matchText("path", obs.Path, m)
	case "url":
		return matchText("url", obs.URL, m)
	case "favicon":
		return matchText("favicon", obs.FaviconHash, m)
	default:
		return "", false
	}
}

func matchHeader(m Matcher, obs Observation) (string, bool) {
	key := http.CanonicalHeaderKey(strings.TrimSpace(m.Key))
	if key == "" {
		return "", false
	}
	values := obs.Headers[key]
	if len(values) == 0 {
		return "", false
	}
	joined := strings.Join(values, " ")
	if matched(joined, m) {
		return fmt.Sprintf("header %s matched", key), true
	}
	return "", false
}

func matchText(source string, value string, m Matcher) (string, bool) {
	if value == "" {
		return "", false
	}
	if !matched(value, m) {
		return "", false
	}
	if m.Equals != "" {
		return fmt.Sprintf("%s equals %q", source, m.Equals), true
	}
	if m.Contains != "" {
		return fmt.Sprintf("%s contains %q", source, m.Contains), true
	}
	return fmt.Sprintf("%s matched", source), true
}

func matched(value string, m Matcher) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if m.Equals != "" {
		return strings.EqualFold(value, strings.TrimSpace(m.Equals))
	}
	if m.Contains != "" {
		return strings.Contains(strings.ToLower(value), strings.ToLower(strings.TrimSpace(m.Contains)))
	}
	return false
}

func riskRank(risk RiskLevel) int {
	switch strings.ToLower(string(risk)) {
	case string(RiskCritical):
		return 5
	case string(RiskHigh):
		return 4
	case string(RiskMedium):
		return 3
	case string(RiskLow):
		return 2
	default:
		return 1
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
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
		out = append(out, value)
	}
	return out
}

func IsFaviconPath(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(path.Base(parsed.Path), "favicon.ico")
}
