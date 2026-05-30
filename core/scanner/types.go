package scanner

import "time"

type Options struct {
	Target string
	Words  []string

	UseDefaultWordlist bool

	Extensions string
	Threads    int
	Recursive  bool
	MaxDepth   int

	FuzzEnabled  bool
	FuzzDictPath string
	FuzzWords    []string

	Proxy     string
	Socks5    string
	ProxyAuth string

	FollowRedirects bool
	MaxRedirects    int

	Insecure bool
	Retry    int

	ExcludeStatusRaw  string
	ExcludeSizeRaw    string
	ExcludeContentRaw string

	ExcludeStatus   map[int]struct{}
	ExcludeSizes    map[int]struct{}
	ExcludeContent  []string
	StatusFilterRaw string
	StatusFilter    map[int]struct{}

	Quiet      bool
	OutputPath string

	DelayMs     int
	RandomDelay bool

	UserAgent  string
	Debug      bool
	MaxProcs   int
	Method     string
	TimeoutSec int

	ConnectTimeoutSec        int
	ResponseHeaderTimeoutSec int
	MaxBodyBytes             int
	NoProxyFallback          bool
	Resume                   bool
	ResumePath               string
}

type Stats struct {
	Total   uint64
	Scanned uint64
	Hits    uint64
}
type Result struct {
	URL          string    `json:"url"`
	StatusCode   int       `json:"status_code"`
	ResponseSize int       `json:"response_size"`
	RedirectURL  string    `json:"redirect_url"`
	ScanTime     time.Time `json:"scan_time"`
}

type job struct {
	baseURL string
	depth   int
}
