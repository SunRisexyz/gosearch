package scanner

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gosearch/core/output"
)

func runMethodProbes(ctx context.Context, client *http.Client, directClient *http.Client, target string, opts Options, throttle *adaptiveThrottle) []output.MethodProbe {
	if len(opts.ProbeMethods) == 0 {
		return nil
	}
	probes := make([]output.MethodProbe, 0, len(opts.ProbeMethods))
	for _, method := range opts.ProbeMethods {
		probes = append(probes, doMethodProbe(ctx, client, directClient, target, opts, method, throttle))
	}
	return probes
}

func doMethodProbe(ctx context.Context, client *http.Client, directClient *http.Client, target string, opts Options, method string, throttle *adaptiveThrottle) output.MethodProbe {
	probe := output.MethodProbe{Method: method}
	probeOpts := opts
	probeOpts.Method = method
	if method == http.MethodHead || method == http.MethodOptions {
		probeOpts.Body = nil
	}

	retries := probeOpts.Retry
	if retries < 0 {
		retries = 0
	}
	for attempt := 0; attempt <= retries; attempt++ {
		if throttle != nil {
			throttle.wait()
		}
		req, err := newScanRequest(ctx, target, probeOpts)
		if err != nil {
			probe.Error = err.Error()
			return probe
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil && directClient != nil && !opts.NoProxyFallback {
			directReq, reqErr := newScanRequest(ctx, target, probeOpts)
			if reqErr != nil {
				probe.Error = reqErr.Error()
				return probe
			}
			resp, err = directClient.Do(directReq)
		}
		if err != nil {
			if throttle != nil {
				throttle.recordFailure()
			}
			if attempt < retries {
				continue
			}
			probe.Error = err.Error()
			return probe
		}

		_, responseSize := readBody(resp, opts.MaxBodyBytes)
		resp.Body.Close()
		probe.StatusCode = resp.StatusCode
		probe.ResponseSize = responseSize
		probe.ResponseTimeMs = int(time.Since(start).Milliseconds())
		probe.Allow = resp.Header.Get("Allow")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			probe.RedirectURL = resp.Header.Get("Location")
		}
		if throttle != nil {
			throttle.recordStatus(resp.StatusCode)
		}
		return probe
	}
	probe.Error = fmt.Sprintf("%s probe failed", method)
	return probe
}
