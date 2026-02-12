package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stackgen-cli/portcheck/internal/profiles"
	"github.com/stackgen-cli/portcheck/internal/reporter"
	"github.com/stackgen-cli/portcheck/internal/runtime"
	"github.com/stackgen-cli/portcheck/internal/scanner"
)

var (
	strictMode      bool
	outputFormat    string
	runtimeScan     bool
	suggestPorts    bool
	activeProfiles  []string
	showHostIP      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan for port collisions",
	Long: `Scan Docker Compose files for port conflicts.

By default, scans the current directory. Use --strict to fail 
on any conflicts (useful in CI).

Features:
  • Static compose file scanning
  • Runtime container port detection (--runtime)
  • Port suggestions for conflicts (--suggest)
  • Profile-aware scanning (--profile)
  • Host IP binding analysis (--show-host-ip)

Examples:
  portcheck scan
  portcheck scan ./myproject
  portcheck scan --strict
  portcheck scan --runtime
  portcheck scan --suggest
  portcheck scan --profile dev --profile tools
  portcheck scan --show-host-ip`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&strictMode, "strict", false, "Exit with error code on any issues found")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, markdown")
	scanCmd.Flags().BoolVar(&runtimeScan, "runtime", false, "Also scan running containers for port usage")
	scanCmd.Flags().BoolVar(&suggestPorts, "suggest", false, "Suggest alternative ports for conflicts")
	scanCmd.Flags().StringSliceVar(&activeProfiles, "profile", nil, "Compose profile(s) to consider")
	scanCmd.Flags().BoolVar(&showHostIP, "show-host-ip", false, "Show host IP binding details")
}

func runScan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Standard compose file scan
	result, err := scanner.Scan(path)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Profile-aware scanning
	if len(activeProfiles) > 0 {
		profileConfig, err := profiles.LoadProfiles(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load profiles: %v\n", err)
		} else {
			conflicts := profileConfig.DetectPortConflicts(activeProfiles)
			for _, c := range conflicts {
				result.Issues = append(result.Issues, scanner.Issue{
					Severity:    "error",
					Type:        "profile_collision",
					Description: fmt.Sprintf("Profile conflict on port %s: multiple services", c.Port),
				})
			}
		}
	}

	// Runtime scan
	var runtimeResult *runtime.RuntimeResult
	if runtimeScan {
		runtimeResult, err = runtime.ScanRuntime()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: runtime scan failed: %v\n", err)
		} else if runtimeResult.DockerRunning {
			// Check for conflicts between compose and runtime
			for port, containers := range runtimeResult.UsedPorts {
				if bindings, exists := result.PortMap[port]; exists {
					for _, b := range bindings {
						for _, c := range containers {
							// Check if it's the same service (might be running from this compose)
							if !isLikelyFromCompose(c, b.Service) {
								runtimeResult.Conflicts = append(runtimeResult.Conflicts, runtime.RuntimeConflict{
									Port:           port,
									ComposeService: b.Service,
									RuntimeInfo:    c.Name,
									Type:           "already_in_use",
									Message:        fmt.Sprintf("Port %d (for %s) is already used by container %s", port, b.Service, c.Name),
								})
							}
						}
					}
				}
			}
		}
	}

	// Suggest alternative ports
	var suggestions map[int]int
	if suggestPorts && len(result.Issues) > 0 {
		var conflictPorts []int
		seen := make(map[int]bool)
		for _, issue := range result.Issues {
			if issue.Type == "collision" && !seen[issue.Port] {
				conflictPorts = append(conflictPorts, issue.Port)
				seen[issue.Port] = true
			}
		}
		if len(conflictPorts) > 0 {
			suggestions = runtime.SuggestFreePorts(conflictPorts)
		}
	}

	// Generate output
	switch outputFormat {
	case "json":
		output := map[string]interface{}{
			"result": result,
		}
		if runtimeResult != nil {
			output["runtime"] = runtimeResult
		}
		if suggestions != nil {
			output["suggestions"] = suggestions
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)

	case "markdown":
		output, err := reporter.FormatMarkdown(result)
		if err != nil {
			return err
		}
		fmt.Println(output)
		if runtimeResult != nil && runtimeResult.DockerRunning {
			fmt.Println(runtime.FormatRuntimeResult(runtimeResult))
		}
		if suggestions != nil && len(suggestions) > 0 {
			fmt.Println("\n## Port Suggestions")
			for old, new := range suggestions {
				fmt.Printf("- Port %d → %d\n", old, new)
			}
		}

	default:
		output, err := reporter.FormatText(result)
		if err != nil {
			return err
		}
		fmt.Println(output)

		// Show host IP details if requested
		if showHostIP {
			fmt.Println("\n=== Host IP Bindings ===")
			for _, b := range result.PortBindings {
				hostIP := b.HostIP
				if hostIP == "" {
					hostIP = "0.0.0.0 (all interfaces)"
				}
				fmt.Printf("  %s: %s -> %d:%d\n", b.Service, hostIP, b.HostPort, b.ContainerPort)
			}
		}

		if runtimeResult != nil && runtimeResult.DockerRunning {
			fmt.Println("\n=== Runtime Status ===")
			fmt.Printf("Running containers: %d\n", len(runtimeResult.Containers))
			if len(runtimeResult.Conflicts) > 0 {
				fmt.Println("Conflicts:")
				for _, c := range runtimeResult.Conflicts {
					fmt.Printf("  ⚠️  %s\n", c.Message)
				}
			}
		}

		if suggestions != nil && len(suggestions) > 0 {
			fmt.Println("\n=== Suggested Alternatives ===")
			for old, new := range suggestions {
				fmt.Printf("  Port %d → %d\n", old, new)
			}
		}
	}

	// Exit with error if strict mode and issues found
	hasIssues := result.HasIssues()
	if runtimeResult != nil && len(runtimeResult.Conflicts) > 0 {
		hasIssues = true
	}

	if strictMode && hasIssues {
		os.Exit(1)
	}

	return nil
}

// isLikelyFromCompose checks if a running container might be from the compose service
func isLikelyFromCompose(container runtime.Container, serviceName string) bool {
	// Check container name contains service name
	if strings.Contains(strings.ToLower(container.Name), strings.ToLower(serviceName)) {
		return true
	}
	// Check com.docker.compose.service label
	if label, ok := container.Labels["com.docker.compose.service"]; ok {
		if strings.ToLower(label) == strings.ToLower(serviceName) {
			return true
		}
	}
	return false
}
