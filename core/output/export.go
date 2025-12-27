package output

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gosearch/core/utils"
)

func WriteResults(path string, results []Result, meta ReportMeta) error {
	results = FilterByStatusSize(results)
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
		Meta        ReportMeta `json:"meta"`
		Results     []Result   `json:"results"`
		Formatted   []string   `json:"formatted"`
		GeneratedAt string     `json:"generated_at"`
	}{
		Meta:        meta,
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

	header := []string{"time", "status_code", "size_human", "size_bytes", "response_time_ms", "host", "path", "url", "redirect_url"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, res := range results {
		pathStr := displayPath(res.URL)
		sizeHuman := formatSizeShort(res.ResponseSize)
		row := []string{
			res.ScanTime.Format("15:04:05"),
			fmt.Sprintf("%d", res.StatusCode),
			sizeHuman,
			fmt.Sprintf("%d", res.ResponseSize),
			fmt.Sprintf("%d", res.ResponseTimeMs),
			res.Host,
			pathStr,
			res.URL,
			res.RedirectURL,
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
	_, err = file.WriteString("| URL | Status | Size | Time(ms) | Redirect | Time |\n| --- | --- | --- | --- | --- | --- |\n")
	if err != nil {
		return err
	}

	for _, res := range results {
		line := fmt.Sprintf("| %s | %d | %d | %d | %s | %s |\n", res.URL, res.StatusCode, res.ResponseSize, res.ResponseTimeMs, res.RedirectURL, res.ScanTime.Format(time.RFC3339))
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
		line := fmt.Sprintf("%d %s %s\n", res.StatusCode, sizeText, res.URL)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	return nil
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
