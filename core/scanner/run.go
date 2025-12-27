package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosearch/core/output"
	"gosearch/core/utils"

	"golang.org/x/sync/errgroup"
)

type task struct {
	url     string
	isDir   bool
	baseURL string
	depth   int
	seq     uint64
}

func Run(targets []string, opts Options) ([]output.Result, Stats, error) {
	if opts.MaxProcs > 0 {
		runtime.GOMAXPROCS(opts.MaxProcs)
	}

	output.ResetFilters()

	client, err := buildClient(opts)
	if err != nil {
		return nil, Stats{}, err
	}
	directOpts := opts
	directOpts.Proxy = ""
	directOpts.Socks5 = ""
	directOpts.ProxyAuth = ""
	directClient, err := buildClient(directOpts)
	if err != nil {
		return nil, Stats{}, err
	}

	paths := buildPaths(opts.Words, opts.Extensions, opts.FuzzEnabled, opts.FuzzWords)

	workCh := make(chan task, opts.Threads*2)
	var taskWG sync.WaitGroup

	var total uint64 = uint64(len(paths) * len(targets))
	var scanned uint64
	var hits uint64

	results := make([]output.Result, 0, 128)
	var resultsMu sync.Mutex
	var seqCounter uint64
	statusSizeMu := &sync.Mutex{}
	statusSizeFirst := make(map[int]map[int]uint64)
	var resultCh chan output.Result
	var resultWG sync.WaitGroup
	if !opts.Quiet {
		resultCh = make(chan output.Result, opts.Threads*2)
		resultWG.Add(1)
		go func() {
			defer resultWG.Done()
			for res := range resultCh {
				output.PrintResult(res)
			}
		}()
	}

	visited := make(map[string]struct{})
	var visitedMu sync.Mutex

	ctx := context.Background()
	group, ctx := errgroup.WithContext(ctx)

	currentPath := &atomic.Value{}
	currentPath.Store("")

	for i := 0; i < opts.Threads; i++ {
		group.Go(func() error {
			for t := range workCh {
				atomic.AddUint64(&scanned, 1)
				currentPath.Store(t.url)
				res, ok := doRequest(ctx, client, directClient, t.url, opts)
				if ok {
					if !isExcluded(res, opts) {
						if !shouldDisplay(statusSizeMu, statusSizeFirst, res.StatusCode, res.ResponseSize, t.seq) {
							taskWG.Done()
							continue
						}
						resultsMu.Lock()
						results = append(results, res)
						resultsMu.Unlock()
						atomic.AddUint64(&hits, 1)
						if resultCh != nil {
							select {
							case resultCh <- res:
							default:
								// avoid blocking workers if logger is slower
								go func(r output.Result) { resultCh <- r }(res)
							}
						}
						if opts.Recursive && t.isDir && t.depth < opts.MaxDepth {
							enqueueBase(t.url, paths, t.depth+1, opts, &taskWG, workCh, visited, &visitedMu, &seqCounter)
						}
					}
				}
				taskWG.Done()
			}
			return nil
		})
	}

	progressDone := make(chan struct{})
	if !opts.Quiet {
		go output.PrintProgress(&scanned, &total, &hits, opts.Threads, currentPath, progressDone)
	}

	for _, target := range targets {
		base, err := normalizeBase(target)
		if err != nil {
			return nil, Stats{}, err
		}
		enqueueBase(base, paths, 1, opts, &taskWG, workCh, visited, &visitedMu, &seqCounter)
	}

	go func() {
		taskWG.Wait()
		close(workCh)
		if resultCh != nil {
			close(resultCh)
		}
	}()

	if err := group.Wait(); err != nil {
		return nil, Stats{}, err
	}
	if resultCh != nil {
		resultWG.Wait()
	}

	close(progressDone)

	if !opts.Quiet {
		output.PrintSummary(scanned, total, hits)
	}

	return results, Stats{
		Total:   total,
		Scanned: scanned,
		Hits:    hits,
	}, nil
}

func enqueueBase(base string, paths []string, depth int, opts Options, wg *sync.WaitGroup, ch chan<- task, visited map[string]struct{}, visitedMu *sync.Mutex, seqCounter *uint64) {
	visitedMu.Lock()
	if _, ok := visited[base]; ok {
		visitedMu.Unlock()
		return
	}
	visited[base] = struct{}{}
	visitedMu.Unlock()

	for _, p := range paths {
		isDir := !strings.Contains(p, ".") && !strings.HasSuffix(p, "/")
		pathURL := joinURL(base, p, isDir)
		wg.Add(1)
		seq := atomic.AddUint64(seqCounter, 1)
		ch <- task{url: pathURL, isDir: isDir, baseURL: base, depth: depth, seq: seq}
	}
}

func shouldDisplay(mu *sync.Mutex, seen map[int]map[int]uint64, status int, size int, seq uint64) bool {
	mu.Lock()
	defer mu.Unlock()
	if seen[status] == nil {
		seen[status] = make(map[int]uint64)
	}
	if old, ok := seen[status][size]; ok {
		// already have a smaller sequence
		if old <= seq {
			return false
		}
	}
	seen[status][size] = seq
	return true
}

func doRequest(ctx context.Context, client *http.Client, directClient *http.Client, target string, opts Options) (output.Result, bool) {
	retries := opts.Retry
	if retries < 0 {
		retries = 0
	}
	for attempt := 0; attempt <= retries; attempt++ {
		if opts.RandomDelay {
			delay := rand.Intn(151) + 50
			time.Sleep(time.Duration(delay) * time.Millisecond)
		} else if opts.DelayMs > 0 {
			time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
		}

		req, err := http.NewRequestWithContext(ctx, opts.Method, target, nil)
		if err != nil {
			return output.Result{}, false
		}
		ua := opts.UserAgent
		if ua == "" {
			ua = utils.RandomUserAgent()
		}
		req.Header.Set("User-Agent", ua)

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if (opts.Proxy != "" || opts.Socks5 != "") && directClient != nil {
				if opts.Debug {
					output.PrintDebug("PROXY", "proxy failed, fallback to direct")
				}
				resp, err = directClient.Do(req)
			}
		}
		if err != nil {
			if opts.Debug {
				output.PrintDebug("ERROR", fmt.Sprintf("%s %s: %v", opts.Method, target, err))
			}
			if attempt < retries {
				continue
			}
			return output.Result{}, false
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		redirectURL := ""
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirectURL = resp.Header.Get("Location")
		}

		host := ""
		if parsed, err := url.Parse(target); err == nil {
			host = parsed.Hostname()
		}
		res := output.Result{
			URL:            target,
			Host:           host,
			StatusCode:     resp.StatusCode,
			ResponseSize:   len(bodyBytes),
			RedirectURL:    redirectURL,
			ScanTime:       time.Now(),
			ResponseTimeMs: int(time.Since(start).Milliseconds()),
		}

		if opts.Debug {
			output.PrintDebug("RESPONSE", fmt.Sprintf("%s %s -> %d %d bytes", opts.Method, target, res.StatusCode, res.ResponseSize))
		}

		if len(opts.ExcludeContent) > 0 && containsAny(string(bodyBytes), opts.ExcludeContent) {
			return res, false
		}

		return res, true
	}
	return output.Result{}, false
}

func isExcluded(res output.Result, opts Options) bool {
	if len(opts.StatusFilter) > 0 {
		if _, ok := opts.StatusFilter[res.StatusCode]; !ok {
			return true
		}
	}
	if _, ok := opts.ExcludeStatus[res.StatusCode]; ok {
		return true
	}
	if _, ok := opts.ExcludeSizes[res.ResponseSize]; ok {
		return true
	}
	return false
}

func buildPaths(words []string, extensions string, fuzz bool, fuzzWords []string) []string {
	base := []string{}
	for _, w := range words {
		if fuzz && strings.Contains(w, "{dir}") {
			for _, f := range fuzzWords {
				base = append(base, strings.ReplaceAll(w, "{dir}", f))
			}
			continue
		}
		base = append(base, w)
	}

	extList := parseExtensions(extensions)
	if len(extList) == 0 {
		return base
	}

	out := []string{}
	for _, w := range base {
		if strings.Contains(w, ".") {
			out = append(out, w)
			continue
		}
		for _, ext := range extList {
			out = append(out, fmt.Sprintf("%s.%s", w, ext))
		}
	}
	return out
}

func parseExtensions(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	exts := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, ".")
		if p == "" {
			continue
		}
		exts = append(exts, p)
	}
	return exts
}

func normalizeBase(target string) (string, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("invalid target URL")
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed.String(), nil
}

func joinURL(base string, path string, isDir bool) string {
	baseURL := strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	combined := baseURL + "/" + path
	if isDir && !strings.HasSuffix(combined, "/") {
		combined += "/"
	}
	return combined
}

func containsAny(body string, terms []string) bool {
	for _, t := range terms {
		if t == "" {
			continue
		}
		if strings.Contains(body, t) {
			return true
		}
	}
	return false
}

func buildClient(opts Options) (*http.Client, error) {
	timeout := 15 * time.Second
	if opts.TimeoutSec > 0 {
		timeout = time.Duration(opts.TimeoutSec) * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure},
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		if opts.ProxyAuth != "" {
			transport.ProxyConnectHeader = http.Header{}
			transport.ProxyConnectHeader.Add("Proxy-Authorization", "Basic "+basicAuth(opts.ProxyAuth))
		}
	}

	if opts.Socks5 != "" {
		dialer := &socks5Dialer{address: opts.Socks5, auth: opts.ProxyAuth}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			return conn, nil
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	if opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

func basicAuth(raw string) string {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	token := parts[0] + ":" + parts[1]
	return base64.StdEncoding.EncodeToString([]byte(token))
}
