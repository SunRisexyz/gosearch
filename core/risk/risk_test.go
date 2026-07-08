package risk

import (
	"net/http"
	"testing"

	"gosearch/core/fingerprint"
	"gosearch/core/output"
)

func TestApplyMarksSensitivePath(t *testing.T) {
	res := output.Result{
		URL:        "https://example.com/.env",
		StatusCode: http.StatusOK,
	}
	Apply(&res)
	if res.RiskLevel != fingerprint.RiskCritical {
		t.Fatalf("risk level = %q, want %q", res.RiskLevel, fingerprint.RiskCritical)
	}
	if res.RiskScore == 0 {
		t.Fatal("expected risk score")
	}
	if len(res.RiskReasons) == 0 {
		t.Fatal("expected risk reasons")
	}
}

func TestApplyKeepsHighestFingerprintRisk(t *testing.T) {
	res := output.Result{
		URL:        "https://example.com/swagger-ui/",
		StatusCode: http.StatusOK,
		Fingerprints: []fingerprint.Finding{
			{Name: "Jenkins", Risk: fingerprint.RiskHigh, Tags: []string{"ci"}},
		},
	}
	Apply(&res)
	if res.RiskLevel != fingerprint.RiskHigh {
		t.Fatalf("risk level = %q, want %q", res.RiskLevel, fingerprint.RiskHigh)
	}
}

func TestParseLevelRejectsInvalidValue(t *testing.T) {
	if _, err := ParseLevel("urgent"); err == nil {
		t.Fatal("expected invalid min-risk error")
	}
}
