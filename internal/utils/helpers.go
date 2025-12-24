package utils

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func ParseStatusSet(raw string) (map[int]struct{}, error) {
	set := map[int]struct{}{}
	if raw == "" {
		return set, nil
	}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, errors.New("invalid status code: " + part)
		}
		if val < 100 || val > 599 {
			return nil, errors.New("invalid status code: " + part)
		}
		set[val] = struct{}{}
	}
	return set, nil
}

func IntsToCSV(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func EnsureDirs(reportDir string, dictDir string) error {
	if reportDir != "" {
		if err := os.MkdirAll(filepath.Clean(reportDir), 0o755); err != nil {
			return err
		}
	}
	if dictDir != "" && dictDir != "." {
		if err := os.MkdirAll(filepath.Clean(dictDir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func EnsureDictFile(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		return true, err
	}
	return true, nil
}

func NormalizeBaseURL(target string) (string, error) {
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

func HostFromURL(target string) (string, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", errors.New("invalid target URL")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", errors.New("invalid target host")
	}
	return host, nil
}

func SafeFilename(input string) string {
	out := make([]rune, 0, len(input))
	for _, r := range input {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

func ValidateTarget(raw string) error {
	if raw == "" {
		return errors.New("target is empty")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("invalid target host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if !isValidHostname(host) {
		return errors.New("invalid host: " + host)
	}
	return nil
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 {
			return false
		}
		if p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
