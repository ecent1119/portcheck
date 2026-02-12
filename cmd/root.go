package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "portcheck",
	Short: "Local Port Collision Detector",
	Long: `portcheck detects port conflicts in Docker Compose configurations.

It identifies:
  - Multiple services binding to the same host port
  - Same port reused across different compose files
  - Privileged ports (< 1024) that may need sudo
  - Potential conflicts with system services

Fast, actionable, no guessing.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("portcheck %s\n", version)
	},
}
