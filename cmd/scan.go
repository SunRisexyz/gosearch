package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gosearch/core/output"
	"gosearch/core/scanner"
	"gosearch/core/utils"

	"github.com/spf13/cobra"
)

var scanOpts scanner.Options
var wordlistPath string
var targetsPath string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan directories and files",
	RunE: func(cmd *cobra.Command, args []string) error {
		startTime := time.Now()
		cfg, _, err := utils.LoadConfig("config.yml")
		if err != nil {
			return err
		}

		if err := utils.EnsureDirs(cfg.Output.ReportDir, filepath.Dir(cfg.Scan.DictPath)); err != nil {
			return err
		}
		if created, err := utils.EnsureDictFile(cfg.Scan.DictPath); err != nil {
			return err
		} else if created {
			output.PrintInfo(fmt.Sprintf("created default wordlist: %s", cfg.Scan.DictPath))
		}

		if scanOpts.Target == "" && targetsPath == "" {
			return errors.New("target is required: -u or -l")
		}

		if !cmd.Flags().Changed("threads") && cfg.Scan.ThreadNum > 0 {
			scanOpts.Threads = cfg.Scan.ThreadNum
		}
		if !cmd.Flags().Changed("wordlist") && wordlistPath == "" && cfg.Scan.DictPath != "" {
			wordlistPath = cfg.Scan.DictPath
			output.PrintInfo(fmt.Sprintf("using default wordlist: %s", wordlistPath))
		}
		if !cmd.Flags().Changed("filter") && scanOpts.ExcludeStatusRaw == "" && len(cfg.Scan.FilterCodes) > 0 {
			scanOpts.ExcludeStatusRaw = utils.IntsToCSV(cfg.Scan.FilterCodes)
		}
		if !cmd.Flags().Changed("timeout") && scanOpts.TimeoutSec == 0 && cfg.Scan.Timeout > 0 {
			scanOpts.TimeoutSec = cfg.Scan.Timeout
		}
		if scanOpts.Threads < 1 || scanOpts.Threads > 200 {
			return errors.New("threads must be between 1 and 200")
		}
		if scanOpts.TimeoutSec < 0 {
			return errors.New("timeout must be >= 0")
		}
		if scanOpts.MaxDepth < 1 {
			scanOpts.MaxDepth = 3
		}
		targets, err := utils.LoadTargets(scanOpts.Target, targetsPath)
		if err != nil {
			return err
		}
		for _, t := range targets {
			if err := utils.ValidateTarget(t); err != nil {
				return err
			}
		}

		words, err := utils.LoadWordlist(wordlistPath, scanOpts.UseDefaultWordlist)
		if err != nil {
			return err
		}
		scanOpts.Words = words

		if scanOpts.FuzzEnabled {
			fuzzWords, err := utils.LoadFuzzDict(scanOpts.FuzzDictPath)
			if err != nil {
				return err
			}
			scanOpts.FuzzWords = fuzzWords
		}

		if scanOpts.DelayMs < 0 {
			scanOpts.DelayMs = 0
		}

		if scanOpts.RandomDelay {
			scanOpts.DelayMs = 0
		}

		scanOpts.ExcludeStatus, err = utils.ParseStatusSet(scanOpts.ExcludeStatusRaw)
		if err != nil {
			return err
		}
		scanOpts.ExcludeSizes = utils.ParseIntSet(scanOpts.ExcludeSizeRaw)
		scanOpts.ExcludeContent = utils.ParseCSVStrings(scanOpts.ExcludeContentRaw)
		scanOpts.StatusFilter, err = utils.ParseStatusSet(scanOpts.StatusFilterRaw)
		if err != nil {
			return err
		}

		outputPathPreview := scanOpts.OutputPath
		if outputPathPreview == "" && len(targets) > 0 {
			p, err := output.BuildReportPath(cfg.Output.ReportDir, targets[0], startTime, cfg.Output.FileSuffix)
			if err == nil {
				outputPathPreview = p
			}
		}
		if outputPathPreview == "" && scanOpts.OutputPath != "" {
			if abs, err := filepath.Abs(scanOpts.OutputPath); err == nil {
				outputPathPreview = abs
			}
		}

		output.PrintScanHeader(cfg.Welcome.Version, scanOpts.Extensions, scanOpts.Method, scanOpts.Threads, len(scanOpts.Words), outputPathPreview, strings.Join(targets, ","), startTime)

		results, stats, err := scanner.Run(targets, scanOpts)
		if err != nil {
			return err
		}

		commandLine := strings.Join(os.Args, " ")
		if scanOpts.OutputPath != "" {
			if err := output.WriteResults(scanOpts.OutputPath, results, output.ReportMeta{
				Target:   strings.Join(targets, ","),
				ScanTime: startTime,
				Total:    int(stats.Total),
				Hits:     len(output.FilterByStatusSize(results)),
				Duration: time.Since(startTime),
				Command:  commandLine,
			}); err != nil {
				return err
			}
			output.PrintInfo(fmt.Sprintf("report saved to: %s", scanOpts.OutputPath))
		} else {
			paths, err := output.WriteReportsByTarget(cfg.Output.ReportDir, cfg.Output.FileSuffix, targets, results, startTime, int(stats.Total), time.Since(startTime), commandLine)
			if err != nil {
				return err
			}
			if len(paths) > 0 {
				output.PrintInfo(fmt.Sprintf("report saved to: %s", strings.Join(paths, ",")))
			} else {
				output.PrintInfo(fmt.Sprintf("report saved to: %s", cfg.Output.ReportDir))
			}
		}

		output.PrintInfo(fmt.Sprintf("scan finished in %s", time.Since(startTime)))

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanOpts.Target, "url", "u", "", "Target URL")
	scanCmd.Flags().StringVarP(&targetsPath, "list", "l", "", "Targets list file")
	scanCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Wordlist file")
	scanCmd.Flags().BoolVar(&scanOpts.UseDefaultWordlist, "default-wordlist", false, "Use built-in wordlist")
	scanCmd.Flags().StringVarP(&scanOpts.Extensions, "extensions", "e", "", "Extensions, comma-separated")

	scanCmd.Flags().IntVarP(&scanOpts.Threads, "threads", "t", 30, "Concurrent threads (1-200)")
	scanCmd.Flags().BoolVarP(&scanOpts.Recursive, "recursive", "r", false, "Enable recursive scan")
	scanCmd.Flags().IntVar(&scanOpts.MaxDepth, "max-depth", 3, "Max recursion depth")

	scanCmd.Flags().BoolVarP(&scanOpts.FuzzEnabled, "fuzz", "F", false, "Enable fuzzing with {dir} placeholder")
	scanCmd.Flags().StringVarP(&scanOpts.FuzzDictPath, "fuzz-dict", "G", "", "Custom fuzz dict file")

	scanCmd.Flags().StringVarP(&scanOpts.Proxy, "proxy", "p", "", "HTTP proxy URL (http://ip:port)")
	scanCmd.Flags().StringVarP(&scanOpts.Socks5, "socks5", "5", "", "SOCKS5 proxy (ip:port)")
	scanCmd.Flags().StringVarP(&scanOpts.ProxyAuth, "proxy-auth", "a", "", "Proxy auth user:pass")

	scanCmd.Flags().BoolVarP(&scanOpts.FollowRedirects, "follow-redirects", "R", false, "Follow redirects")
	scanCmd.Flags().IntVarP(&scanOpts.MaxRedirects, "max-redirects", "M", 5, "Max redirects")

	scanCmd.Flags().BoolVarP(&scanOpts.Insecure, "insecure", "k", false, "Skip TLS verification")
	scanCmd.Flags().IntVarP(&scanOpts.Retry, "retry", "y", 1, "Retry attempts")

	scanCmd.Flags().StringVarP(&scanOpts.ExcludeStatusRaw, "exclude-status", "E", "", "Exclude status codes, e.g. 404,500")
	scanCmd.Flags().StringVarP(&scanOpts.ExcludeSizeRaw, "exclude-size", "S", "", "Exclude sizes, e.g. 0,1024")
	scanCmd.Flags().StringVarP(&scanOpts.ExcludeContentRaw, "exclude-content", "C", "", "Exclude content keywords, comma-separated")
	scanCmd.Flags().StringVar(&scanOpts.StatusFilterRaw, "status-codes", "", "Only show these status codes (comma-separated); empty means show all")
	scanCmd.Flags().StringVarP(&scanOpts.ExcludeStatusRaw, "filter", "f", "", "Filter (exclude) status codes, comma-separated")

	scanCmd.Flags().BoolVarP(&scanOpts.Quiet, "quiet", "q", false, "Quiet mode")
	scanCmd.Flags().StringVarP(&scanOpts.OutputPath, "output", "o", "", "Output file (json/csv/md/txt)")

	scanCmd.Flags().IntVarP(&scanOpts.DelayMs, "delay", "d", 0, "Delay per request in ms")
	scanCmd.Flags().BoolVarP(&scanOpts.RandomDelay, "random-delay", "Z", false, "Random delay 50-200ms")

	scanCmd.Flags().StringVarP(&scanOpts.UserAgent, "user-agent", "A", "", "Custom User-Agent")
	scanCmd.Flags().BoolVarP(&scanOpts.Debug, "debug", "D", false, "Enable debug logging")
	scanCmd.Flags().IntVarP(&scanOpts.MaxProcs, "max-procs", "P", 0, "Limit CPU cores (0 = all)")

	scanCmd.Flags().StringVarP(&scanOpts.Method, "method", "X", "GET", "HTTP method")
	scanCmd.Flags().IntVarP(&scanOpts.TimeoutSec, "timeout", "T", 0, "Request timeout in seconds")

	scanCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println(strings.TrimSpace(cmd.UsageString()))
	})
}
