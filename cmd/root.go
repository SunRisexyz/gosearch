package cmd

import (
	"fmt"
	"os"
	"strings"

	"gosearch/internal/output"
	"gosearch/internal/utils"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gosearch",
	Short: "gosearch is a fast directory scanner",
	Long:  "gosearch is a dirsearch-like directory and file scanner built in Go.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		cfg, _, err := utils.LoadConfig("config.yml")
		if err == nil {
			output.PrintWelcome(cfg.Welcome.AsciiArt, cfg.Welcome.Version)
		}
		fmt.Println(strings.TrimSpace(cmd.UsageString()))
	})
}
