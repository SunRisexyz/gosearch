package output

import (
	"fmt"
	// "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	orange = color.New(color.FgHiYellow)
	red    = color.New(color.FgRed)
	cyan   = color.New(color.FgCyan)
	gray   = color.New(color.FgHiBlack)
)

func init() {
	color.NoColor = false
}

const clearLine = "\r\033[2K"
const maxProgressLen = 180

var printMu sync.Mutex
var statusSizeSeen = make(map[string]map[int]map[int]struct{})
var lastHost string
var lastHostSet bool

func PrintResult(res Result) {
	printMu.Lock()
	defer printMu.Unlock()

	hostKey := res.Host
	if hostKey == "" {
		hostKey = "_"
	}
	if statusSizeSeen[hostKey] == nil {
		statusSizeSeen[hostKey] = make(map[int]map[int]struct{})
	}
	if statusSizeSeen[hostKey][res.StatusCode] == nil {
		statusSizeSeen[hostKey][res.StatusCode] = make(map[int]struct{})
	}
	if _, ok := statusSizeSeen[hostKey][res.StatusCode][res.ResponseSize]; ok {
		return
	}
	statusSizeSeen[hostKey][res.StatusCode][res.ResponseSize] = struct{}{}

	if !lastHostSet || lastHost != hostKey {
		fmt.Println()
		cyan.Printf("[%s]\n", hostKey)
		lastHost = hostKey
		lastHostSet = true
	}

	fmt.Fprint(os.Stdout, clearLine)
	status := fmt.Sprintf("%d", res.StatusCode)
	line := fmt.Sprintf("[%s] %3s - %6s - %s", time.Now().Format("15:04:05"), status, formatSizeShort(res.ResponseSize), displayPath(res.URL))
	switch res.StatusCode {
	case 200:
		green.Println(line)
	case 301, 302, 307, 308:
		yellow.Println(line)
	case 403:
		orange.Println(line)
	default:
		red.Println(line)
	}
}

func PrintProgress(scanned *uint64, total *uint64, hits *uint64, threads int, currentPath *atomic.Value, done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	lastLen := 0
	for {
		select {
		case <-done:
			if lastLen > 0 {
				fmt.Print(clearLine)
			}
			return
		case <-ticker.C:
			s := atomic.LoadUint64(scanned)
			t := atomic.LoadUint64(total)
			// h := atomic.LoadUint64(hits)
			percent := 0
			if t > 0 {
				percent = int(float64(s) / float64(t) * 100)
			}
			current := ""
			if currentPath != nil {
				if v := currentPath.Load(); v != nil {
					current, _ = v.(string)
				}
			}
			current = truncateMiddle(current, 60)
			line := fmt.Sprintf("[Progress] %d/%d (%d%%) %s", s, t, percent, current)
			limit := progressWidth()
			if len(line) > limit {
				line = truncateMiddle(line, limit)
			}
			if len(line) < lastLen {
				line = line + strings.Repeat(" ", lastLen-len(line))
			}
			lastLen = len(line)
			printMu.Lock()
			fmt.Fprint(os.Stdout, clearLine)
			fmt.Fprintf(color.Output, "%s", line)
			_ = os.Stdout.Sync()
			printMu.Unlock()
		}
	}
}

func truncateMiddle(s string, max int) string {
	if max <= 3 || len(s) <= max {
		return s
	}
	keep := max - 3
	left := keep / 2
	right := keep - left
	return s[:left] + "..." + s[len(s)-right:]
}

func progressWidth() int {
	limit := maxProgressLen
	if colsStr := os.Getenv("COLUMNS"); colsStr != "" {
		if cols, err := strconv.Atoi(colsStr); err == nil && cols > 10 {
			limit = cols - 1
		}
	}
	if limit < 20 {
		limit = 20
	}
	if limit > maxProgressLen {
		limit = maxProgressLen
	}
	return limit
}

func PrintWelcome(art string, version string) {
	if strings.TrimSpace(art) == "" {
		art = "GOSEARCH"
		fmt.Printf(`
   █████████                                                         █████     
  ███░░░░░███                                                       ░░███       %s
 ███     ░░░   ██████   █████   ██████   ██████   ████████   ██████  ░███████  
░███          ███░░███ ███░░   ███░░███ ░░░░░███ ░░███░░███ ███░░███ ░███░░███ 
░███    █████░███ ░███░░█████ ░███████   ███████  ░███ ░░░ ░███ ░░░  ░███ ░███ 
░░███  ░░███ ░███ ░███ ░░░░███░███░░░   ███░░███  ░███     ░███  ███ ░███ ░███ 
 ░░█████████ ░░██████  ██████ ░░██████ ░░████████ █████    ░░██████  ████ █████
  ░░░░░░░░░   ░░░░░░  ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░░      ░░░░░░  ░░░░ ░░░░░                                                                      
	`, version)
		fmt.Print("\n")
	}
}

func PrintInfo(msg string) {
	cyan.Printf("[INFO] %s\n", msg)
}

func PrintScanHeader(version, exts, method string, threads int, wordCount int, outputPath string, target string, start time.Time) {
	fmt.Printf(`
   █████████                                                         █████     
  ███░░░░░███                                                       ░░███       %s
 ███     ░░░   ██████   █████   ██████   ██████   ████████   ██████  ░███████  
░███          ███░░███ ███░░   ███░░███ ░░░░░███ ░░███░░███ ███░░███ ░███░░███ 
░███    █████░███ ░███░░█████ ░███████   ███████  ░███ ░░░ ░███ ░░░  ░███ ░███ 
░░███  ░░███ ░███ ░███ ░░░░███░███░░░   ███░░███  ░███     ░███  ███ ░███ ░███ 
 ░░█████████ ░░██████  ██████ ░░██████ ░░████████ █████    ░░██████  ████ █████
  ░░░░░░░░░   ░░░░░░  ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░░      ░░░░░░  ░░░░ ░░░░░                                                                      
	`, version)
	fmt.Printf("\nExtensions: %s | HTTP method: %s | Threads: %d | Wordlist size: %d\n", exts, method, threads, wordCount)
	if outputPath != "" {
		abs, err := filepath.Abs(outputPath)
		if err == nil {
			outputPath = abs
		}
		fmt.Printf("Output File: %s\n", outputPath)
	}
	fmt.Printf("Target: %s\n\n", target)
	fmt.Printf("[%s] Starting:\n", start.Format("15:04:05"))
}

func PrintSummary(scanned uint64, total uint64, hits uint64) {
	gray.Printf("\nDone. scanned=%d total=%d hits=%d\n", scanned, total, hits)
}

func PrintDebug(prefix string, msg string) {
	printMu.Lock()
	defer printMu.Unlock()
	gray.Printf("[DEBUG] %s: %s\n", prefix, msg)
}

func ResetFilters() {
	printMu.Lock()
	defer printMu.Unlock()
	statusSizeSeen = make(map[string]map[int]map[int]struct{})
	lastHost = ""
	lastHostSet = false
}

func displayPath(raw string) string {
	// Preserve everything after the first path slash (including query/fragment) to avoid losing "#" parts.
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	// Find first "/" after scheme://host
	start := strings.Index(raw, "://")
	if start >= 0 {
		start = strings.Index(raw[start+3:], "/")
		if start >= 0 {
			start = start + 3 + strings.Index(raw, "://")
			return raw[start:]
		}
		return "/"
	}
	// No scheme, attempt simple URL parse but keep fragment if present
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) == 2 {
		return "/" + parts[1]
	}
	return "/" + raw
}

func formatSizeShort(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	kb := float64(size) / 1024.0
	if kb < 1024 {
		return fmt.Sprintf("%dKB", int(kb+0.5))
	}
	mb := kb / 1024.0
	return fmt.Sprintf("%.1fMB", mb)
}
