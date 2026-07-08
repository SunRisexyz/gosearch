package utils

import (
	"bufio"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func LoadHeaders(raw []string, filePath string) (http.Header, error) {
	lines := make([]string, 0, len(raw))
	lines = append(lines, raw...)
	if filePath != "" {
		fileLines, err := readHeaderLines(filePath)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fileLines...)
	}
	return ParseHeaders(lines)
}

func MergeHeaders(base http.Header, override http.Header) http.Header {
	merged := http.Header{}
	for key, values := range base {
		copied := make([]string, len(values))
		copy(copied, values)
		merged[http.CanonicalHeaderKey(key)] = copied
	}
	for key, values := range override {
		copied := make([]string, len(values))
		copy(copied, values)
		merged[http.CanonicalHeaderKey(key)] = copied
	}
	return merged
}

func ParseHeaders(lines []string) (http.Header, error) {
	headers := http.Header{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("invalid header, expected 'Name: value': " + line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, errors.New("invalid header name")
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid header contains newline")
		}
		headers.Add(http.CanonicalHeaderKey(name), value)
	}
	return headers, nil
}

func readHeaderLines(path string) ([]string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
