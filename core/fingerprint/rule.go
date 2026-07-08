package fingerprint

type RiskLevel string

const (
	RiskInfo     RiskLevel = "info"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Matcher struct {
	Type     string `json:"type" yaml:"type"`
	Key      string `json:"key,omitempty" yaml:"key,omitempty"`
	Contains string `json:"contains,omitempty" yaml:"contains,omitempty"`
	Equals   string `json:"equals,omitempty" yaml:"equals,omitempty"`
}

type Rule struct {
	Name       string    `json:"name" yaml:"name"`
	Category   string    `json:"category" yaml:"category"`
	Risk       RiskLevel `json:"risk,omitempty" yaml:"risk,omitempty"`
	Tags       []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	Confidence int       `json:"confidence" yaml:"confidence"`
	MatchMode  string    `json:"match_mode,omitempty" yaml:"match_mode,omitempty"`
	Matchers   []Matcher `json:"matchers" yaml:"matchers"`
}

type Finding struct {
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Confidence int       `json:"confidence"`
	Risk       RiskLevel `json:"risk,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Evidence   []string  `json:"evidence,omitempty"`
}

type Observation struct {
	URL         string
	Path        string
	Headers     map[string][]string
	Title       string
	Body        string
	FaviconHash string
}
