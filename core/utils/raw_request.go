package utils

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type RawRequest struct {
	Method  string
	Target  string
	Headers http.Header
	Body    []byte
}

func LoadRawRequest(path string, scheme string) (RawRequest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return RawRequest{}, err
	}
	return ParseRawRequest(string(data), scheme)
}

func ParseRawRequest(raw string, scheme string) (RawRequest, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return RawRequest{}, err
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return RawRequest{}, err
	}

	headers := http.Header{}
	for key, values := range req.Header {
		copied := make([]string, len(values))
		copy(copied, values)
		headers[http.CanonicalHeaderKey(key)] = copied
	}
	if req.Host != "" {
		headers.Set("Host", req.Host)
	}

	target, err := rawRequestTarget(req, scheme)
	if err != nil {
		return RawRequest{}, err
	}
	return RawRequest{
		Method:  req.Method,
		Target:  target,
		Headers: headers,
		Body:    body,
	}, nil
}

func rawRequestTarget(req *http.Request, scheme string) (string, error) {
	if req.URL != nil && req.URL.IsAbs() {
		base := *req.URL
		if base.Host == "" {
			return "", errors.New("raw request absolute URL is missing host")
		}
		base.Path = "/"
		base.RawQuery = ""
		base.Fragment = ""
		return base.String(), nil
	}
	if scheme == "" {
		scheme = "http"
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "http" && scheme != "https" {
		return "", errors.New("raw-scheme must be http or https")
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return "", errors.New("raw request Host header is required when URL is relative")
	}
	u := url.URL{Scheme: scheme, Host: host, Path: "/"}
	return u.String(), nil
}
