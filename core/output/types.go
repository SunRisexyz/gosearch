package output

import (
	"time"

	"gosearch/core/fingerprint"
)

type Result struct {
	URL            string                `json:"url"`
	Host           string                `json:"host"`
	Method         string                `json:"method,omitempty"`
	StatusCode     int                   `json:"status_code"`
	ResponseSize   int                   `json:"response_size"`
	RedirectURL    string                `json:"redirect_url"`
	ScanTime       time.Time             `json:"scan_time"`
	ResponseTimeMs int                   `json:"response_time_ms"`
	MethodProbes   []MethodProbe         `json:"method_probes,omitempty"`
	Title          string                `json:"title,omitempty"`
	Fingerprints   []fingerprint.Finding `json:"fingerprints,omitempty"`
	RiskLevel      fingerprint.RiskLevel `json:"risk_level,omitempty"`
	RiskScore      int                   `json:"risk_score,omitempty"`
	RiskReasons    []string              `json:"risk_reasons,omitempty"`
	Tags           []string              `json:"tags,omitempty"`
}

type MethodProbe struct {
	Method         string `json:"method"`
	StatusCode     int    `json:"status_code"`
	ResponseSize   int    `json:"response_size"`
	ResponseTimeMs int    `json:"response_time_ms"`
	Allow          string `json:"allow,omitempty"`
	RedirectURL    string `json:"redirect_url,omitempty"`
	Error          string `json:"error,omitempty"`
}

type ReportMeta struct {
	Target   string
	ScanTime time.Time
	Total    int
	Hits     int
	Duration time.Duration
	Command  string
}
