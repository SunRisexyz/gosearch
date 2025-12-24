package output

import "time"

type Result struct {
	URL            string    `json:"url"`
	Host           string    `json:"host"`
	StatusCode     int       `json:"status_code"`
	ResponseSize   int       `json:"response_size"`
	RedirectURL    string    `json:"redirect_url"`
	ScanTime       time.Time `json:"scan_time"`
	ResponseTimeMs int       `json:"response_time_ms"`
}

type ReportMeta struct {
	Target   string
	ScanTime time.Time
	Total    int
	Hits     int
	Duration time.Duration
	Command  string
}
