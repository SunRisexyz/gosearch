package scanner

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"gosearch/core/fingerprint"
	"gosearch/core/output"
)

type soft404Baseline struct {
	entries map[string][]soft404Signature
}

type soft404Signature struct {
	StatusCode   int
	ResponseSize int
	Title        string
}

func buildSoft404Baseline(ctx context.Context, bases []string, client *http.Client, directClient *http.Client, opts Options) *soft404Baseline {
	sampleCount := opts.Soft404Samples
	if sampleCount < 1 {
		sampleCount = 2
	}
	baseline := &soft404Baseline{entries: make(map[string][]soft404Signature, len(bases))}
	for _, base := range bases {
		for i := 0; i < sampleCount; i++ {
			probePath := fmt.Sprintf(".gosearch-not-found-%d-%d", time.Now().UnixNano(), i)
			probeURL := joinURL(base, probePath, false)
			res, ok := doRequest(ctx, client, directClient, probeURL, opts, nil, nil)
			if !ok {
				continue
			}
			baseline.entries[base] = append(baseline.entries[base], soft404Signature{
				StatusCode:   res.StatusCode,
				ResponseSize: res.ResponseSize,
				Title:        res.Title,
			})
		}
	}
	return baseline
}

func (b *soft404Baseline) matches(base string, res output.Result, opts Options) bool {
	if b == nil {
		return false
	}
	signatures := b.entries[base]
	if len(signatures) == 0 {
		return false
	}
	for _, signature := range signatures {
		if signature.StatusCode != res.StatusCode {
			continue
		}
		if !similarSize(signature.ResponseSize, res.ResponseSize, opts.Soft404SizeTolerance) {
			continue
		}
		if signature.Title != "" || res.Title != "" {
			if !strings.EqualFold(strings.TrimSpace(signature.Title), strings.TrimSpace(res.Title)) {
				continue
			}
		}
		return true
	}
	return false
}

func similarSize(a int, b int, tolerance int) bool {
	diff := int(math.Abs(float64(a - b)))
	if tolerance > 0 {
		return diff <= tolerance
	}
	defaultTolerance := a / 20
	if defaultTolerance < 64 {
		defaultTolerance = 64
	}
	return diff <= defaultTolerance
}

func shouldExtractTitle(opts Options, fingerprintEngine *fingerprint.Engine) bool {
	return opts.Soft404 || fingerprintEngine != nil
}
