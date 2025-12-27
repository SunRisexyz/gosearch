package utils

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Welcome struct {
		AsciiArt string `yaml:"ascii_art"`
		Version  string `yaml:"version"`
	} `yaml:"welcome"`
	Scan struct {
		DictPath    string `yaml:"dict_path"`
		ThreadNum   int    `yaml:"thread_num"`
		FilterCodes []int  `yaml:"filter_codes"`
		Timeout     int    `yaml:"timeout"`
	} `yaml:"scan"`
	Output struct {
		ReportDir  string `yaml:"report_dir"`
		FileSuffix string `yaml:"file_suffix"`
	} `yaml:"output"`
}

func LoadConfig(path string) (Config, bool, error) {
	cfg := defaultConfig()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, false, nil
		}
		return cfg, false, err
	}
	if info.IsDir() {
		return cfg, false, nil
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return cfg, false, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, false, err
	}

	return cfg, true, nil
}

func defaultConfig() Config {
	cfg := Config{}
	cfg.Welcome.Version = "v1.0"
	cfg.Scan.DictPath = "dict/dict.txt"
	cfg.Scan.ThreadNum = 10
	cfg.Scan.FilterCodes = []int{404, 500, 503}
	cfg.Scan.Timeout = 5
	cfg.Output.ReportDir = "report"
	cfg.Output.FileSuffix = "txt"
	return cfg
}
