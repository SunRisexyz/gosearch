package scanner

import (
	"net/url"
	"path"
	"strings"
)

var fileBackupSuffixes = []string{
	".bak",
	".backup",
	".old",
	".orig",
	".save",
	".tmp",
	".swp",
	"~",
}

var archiveSuffixes = []string{
	".zip",
	".tar.gz",
	".tgz",
	".7z",
	".rar",
}

func backupVariants(rawURL string, max int) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	escapedPath := strings.Trim(parsed.EscapedPath(), "/")
	if escapedPath == "" {
		return nil
	}
	isDir := strings.HasSuffix(parsed.EscapedPath(), "/")
	escapedPath = strings.TrimSuffix(escapedPath, "/")
	if escapedPath == "" {
		return nil
	}

	var candidates []string
	if isDir || !strings.Contains(path.Base(escapedPath), ".") {
		candidates = directoryBackupVariants(escapedPath)
	} else {
		candidates = fileBackupVariants(escapedPath)
	}
	return uniqueLimited(candidates, max)
}

func fileBackupVariants(relativePath string) []string {
	out := make([]string, 0, len(fileBackupSuffixes)+4)
	for _, suffix := range fileBackupSuffixes {
		out = append(out, relativePath+suffix)
	}
	ext := path.Ext(relativePath)
	if ext != "" {
		withoutExt := strings.TrimSuffix(relativePath, ext)
		out = append(out, withoutExt+ext+".bak")
		out = append(out, withoutExt+".bak"+ext)
		out = append(out, withoutExt+".old"+ext)
	}
	return out
}

func directoryBackupVariants(relativePath string) []string {
	base := strings.TrimSuffix(relativePath, "/")
	out := make([]string, 0, len(archiveSuffixes)+4)
	for _, suffix := range archiveSuffixes {
		out = append(out, base+suffix)
	}
	out = append(out, base+".bak", base+".old", base+"~")
	return out
}

func uniqueLimited(values []string, max int) []string {
	if max < 1 {
		max = 12
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
		if len(out) >= max {
			return out
		}
	}
	return out
}
