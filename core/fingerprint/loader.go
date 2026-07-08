package fingerprint

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
