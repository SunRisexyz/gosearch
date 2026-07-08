package output

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gosearch/core/fingerprint"
	"gosearch/core/utils"
)

func WriteResults(path string, results []Result, meta ReportMeta) error {
	results = FilterByStatusSize(results)
	SortByRisk(results)
	meta.Hits = len(results)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		base := strings.ToLower(path)
		switch base {
		case "json", "csv", "md", "markdown", "txt":
			ext = "." + base
			path = fmt.Sprintf("report%s", ext)
		}
	}
	switch ext {
	case ".json":
		return writeJSON(path, results, meta)
	case ".csv":
		return writeCSV(path, results, meta)
	case ".md", ".markdown":
		return writeMarkdown(path, results, meta)
	case ".txt":
		return writeText(path, results, meta)
	default:
		return errors.New("unsupported output format")
	}
}

func writeJSON(path string, results []Result, meta ReportMeta) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	formatted := make([]string, 0, len(results))
	for _, r := range results {
		formatted = append(formatted, fmt.Sprintf("[%s] %3d - %6s - %s", r.ScanTime.Format("15:04:05"), r.StatusCode, formatSizeShort(r.ResponseSize), displayPath(r.URL)))
	}
	payload := struct {
		Meta        ReportMeta     `json:"meta"`
		RiskSummary map[string]int `json:"risk_summary"`
		TopFindings []Result       `json:"top_findings"`
		Results     []Result       `json:"results"`
		Formatted   []string       `json:"formatted"`
		GeneratedAt string         `json:"generated_at"`
	}{
		Meta:        meta,
		RiskSummary: RiskSummary(results),
		TopFindings: TopFindings(results, 10),
		Results:     results,
		Formatted:   formatted,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}
	return encoder.Encode(payload)
}

func writeCSV(path string, results []Result, meta ReportMeta) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"time", "method", "status_code", "size_human", "size_bytes", "response_time_ms", "host", "path", "url", "redirect_url", "method_probes", "title", "risk_level", "risk_score", "risk_reasons", "tags", "fingerprints"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, res := range results {
		pathStr := displayPath(res.URL)
		sizeHuman := formatSizeShort(res.ResponseSize)
		row := []string{
			res.ScanTime.Format("15:04:05"),
			res.Method,
			fmt.Sprintf("%d", res.StatusCode),
			sizeHuman,
			fmt.Sprintf("%d", res.ResponseSize),
			fmt.Sprintf("%d", res.ResponseTimeMs),
			res.Host,
			pathStr,
			res.URL,
			res.RedirectURL,
			methodProbeSummary(res),
			res.Title,
			string(res.RiskLevel),
			fmt.Sprintf("%d", res.RiskScore),
			strings.Join(res.RiskReasons, ";"),
			strings.Join(res.Tags, ";"),
			fingerprintSummary(res),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeMarkdown(path string, results []Result, meta ReportMeta) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()

	header := fmt.Sprintf("# Gosearch Report\n- Target: %s\n- Scan Time: %s\n- Total: %d\n- Hits: %d\n- Duration: %s\n\n",
		meta.Target,
		meta.ScanTime.Format("2006-01-02 15:04:05"),
		meta.Total,
		meta.Hits,
		meta.Duration.String(),
	)
	if _, err := file.WriteString(header); err != nil {
		return err
	}
	if _, err := file.WriteString(markdownRiskSummary(results)); err != nil {
		return err
	}
	_, err = file.WriteString("| URL | Method | Status | Size | Time(ms) | Probes | Risk | Score | Reasons | Fingerprints | Title | Redirect | Time |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	if err != nil {
		return err
	}

	for _, res := range results {
		line := fmt.Sprintf("| %s | %s | %d | %d | %d | %s | %s | %d | %s | %s | %s | %s | %s |\n", res.URL, res.Method, res.StatusCode, res.ResponseSize, res.ResponseTimeMs, escapeMarkdownCell(methodProbeSummary(res)), res.RiskLevel, res.RiskScore, escapeMarkdownCell(strings.Join(res.RiskReasons, ";")), fingerprintSummary(res), escapeMarkdownCell(res.Title), res.RedirectURL, res.ScanTime.Format(time.RFC3339))
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	return nil
}

func writeText(path string, results []Result, meta ReportMeta) error {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()

	header := fmt.Sprintf("Gosearch started %s as: %s\n\n",
		meta.ScanTime.Format("Mon Jan 02 15:04:05 2006"),
		meta.Command,
	)
	if _, err := file.WriteString(header); err != nil {
		return err
	}
	for _, res := range results {
		sizeText := formatSize(res.ResponseSize)
		extra := ""
		if len(res.Fingerprints) > 0 {
			extra += fmt.Sprintf(" fp=%s", fingerprintSummary(res))
		}
		if len(res.MethodProbes) > 0 {
			extra += fmt.Sprintf(" probes=%q", methodProbeSummary(res))
		}
		if res.RiskLevel != "" {
			extra += fmt.Sprintf(" risk=%s", res.RiskLevel)
		}
		if res.RiskScore > 0 {
			extra += fmt.Sprintf(" score=%d", res.RiskScore)
		}
		if len(res.RiskReasons) > 0 {
			extra += fmt.Sprintf(" reasons=%q", strings.Join(res.RiskReasons, ";"))
		}
		if res.Title != "" {
			extra += fmt.Sprintf(" title=%q", res.Title)
		}
		line := fmt.Sprintf("%d %s %s%s\n", res.StatusCode, sizeText, res.URL, extra)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	return nil
}

func fingerprintSummary(res Result) string {
	if len(res.Fingerprints) == 0 {
		return ""
	}
	names := make([]string, 0, len(res.Fingerprints))
	seen := make(map[string]struct{}, len(res.Fingerprints))
	for _, fp := range res.Fingerprints {
		if fp.Name == "" {
			continue
		}
		if _, ok := seen[fp.Name]; ok {
			continue
		}
		seen[fp.Name] = struct{}{}
		names = append(names, fp.Name)
	}
	return strings.Join(names, ";")
}

func methodProbeSummary(res Result) string {
	if len(res.MethodProbes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(res.MethodProbes))
	for _, probe := range res.MethodProbes {
		if probe.Error != "" {
			parts = append(parts, fmt.Sprintf("%s=error:%s", probe.Method, probe.Error))
			continue
		}
		item := fmt.Sprintf("%s=%d", probe.Method, probe.StatusCode)
		if probe.Allow != "" {
			item += fmt.Sprintf("(Allow:%s)", probe.Allow)
		}
		parts = append(parts, item)
	}
	return strings.Join(parts, ";")
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "|", "\\|")
}

func FilterByStatusSize(results []Result) []Result {
	seen := make(map[string]map[int]map[int]struct{})
	filtered := make([]Result, 0, len(results))
	for _, r := range results {
		host := r.Host
		if host == "" {
			host = "_"
		}
		if seen[host] == nil {
			seen[host] = make(map[int]map[int]struct{})
		}
		if seen[host][r.StatusCode] == nil {
			seen[host][r.StatusCode] = make(map[int]struct{})
		}
		if _, ok := seen[host][r.StatusCode][r.ResponseSize]; ok {
			continue
		}
		seen[host][r.StatusCode][r.ResponseSize] = struct{}{}
		filtered = append(filtered, r)
	}
	return filtered
}

func SortByRisk(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		leftRank := riskRank(results[i].RiskLevel)
		rightRank := riskRank(results[j].RiskLevel)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if results[i].RiskScore != results[j].RiskScore {
			return results[i].RiskScore > results[j].RiskScore
		}
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		if results[i].ResponseSize != results[j].ResponseSize {
			return results[i].ResponseSize > results[j].ResponseSize
		}
		return results[i].URL < results[j].URL
	})
}

func RiskSummary(results []Result) map[string]int {
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

func TopFindings(results []Result, limit int) []Result {
	if limit <= 0 || len(results) == 0 {
		return nil
	}
	copied := make([]Result, len(results))
	copy(copied, results)
	SortByRisk(copied)
	if len(copied) > limit {
		copied = copied[:limit]
	}
	return copied
}

func markdownRiskSummary(results []Result) string {
	summary := RiskSummary(results)
	if summary[string(fingerprint.RiskCritical)] == 0 &&
		summary[string(fingerprint.RiskHigh)] == 0 &&
		summary[string(fingerprint.RiskMedium)] == 0 &&
		summary[string(fingerprint.RiskLow)] == 0 &&
		summary[string(fingerprint.RiskInfo)] == 0 {
		return ""
	}
	return fmt.Sprintf("## Risk Summary\n- Critical: %d\n- High: %d\n- Medium: %d\n- Low: %d\n- Info: %d\n\n",
		summary[string(fingerprint.RiskCritical)],
		summary[string(fingerprint.RiskHigh)],
		summary[string(fingerprint.RiskMedium)],
		summary[string(fingerprint.RiskLow)],
		summary[string(fingerprint.RiskInfo)],
	)
}

func riskRank(level fingerprint.RiskLevel) int {
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

func formatSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	kb := float64(size) / 1024.0
	if kb < 1024.0 {
		return fmt.Sprintf("%.0fKB", kb)
	}
	mb := kb / 1024.0
	return fmt.Sprintf("%.1fMB", mb)
}

func BuildReportPath(reportDir string, target string, start time.Time, suffix string) (string, error) {
	if suffix == "" {
		suffix = "txt"
	}
	if !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}
	host, err := utils.HostFromURL(target)
	if err != nil {
		return "", err
	}
	safeHost := "_" + utils.SafeFilename(host)
	filename := fmt.Sprintf("_%s%s", start.Format("06-01-02_15-04-05"), suffix)
	if reportDir == "" {
		reportDir = "."
	}
	if err := os.MkdirAll(filepath.Join(reportDir, safeHost), 0o755); err != nil {
		return "", err
	}
	return filepath.Join(reportDir, safeHost, filename), nil
}

func WriteReportsByTarget(reportDir string, suffix string, targets []string, results []Result, start time.Time, total int, duration time.Duration, command string) ([]string, error) {
	if suffix == "" {
		suffix = "txt"
	}
	if !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}
	var paths []string
	seenTarget := make(map[string]struct{})
	seenPath := make(map[string]struct{})
	for _, target := range targets {
		if _, ok := seenTarget[target]; ok {
			continue
		}
		seenTarget[target] = struct{}{}
		base, err := utils.NormalizeBaseURL(target)
		if err != nil {
			return nil, err
		}
		targetResults := make([]Result, 0, 16)
		for _, res := range results {
			if strings.HasPrefix(res.URL, base) {
				targetResults = append(targetResults, res)
			}
		}
		targetResults = FilterByStatusSize(targetResults)
		path, err := BuildReportPath(reportDir, target, start, suffix)
		if err != nil {
			return nil, err
		}
		if _, ok := seenPath[path]; ok {
			continue
		}
		seenPath[path] = struct{}{}
		if err := WriteResults(path, targetResults, ReportMeta{
			Target:   target,
			ScanTime: start,
			Total:    total,
			Hits:     len(targetResults),
			Duration: duration,
			Command:  command,
		}); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
