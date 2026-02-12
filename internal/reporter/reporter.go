// Package reporter provides output formatting for port scan results
package reporter

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/stackgen-cli/portcheck/internal/scanner"
)

// FormatText generates colored text output
func FormatText(r *scanner.Result) (string, error) {
	var sb strings.Builder

	sb.WriteString(color.CyanString("Port Check Report\n"))
	sb.WriteString(color.CyanString("=================\n\n"))

	sb.WriteString(fmt.Sprintf("Scanned: %s\n", r.Path))
	sb.WriteString(fmt.Sprintf("Compose files: %d\n", len(r.ComposeFiles)))
	sb.WriteString(fmt.Sprintf("Port bindings: %d\n", len(r.PortBindings)))
	sb.WriteString(fmt.Sprintf("Issues found: %d\n\n", len(r.Issues)))

	if len(r.Issues) == 0 {
		sb.WriteString(color.GreenString("✅ No port conflicts detected!\n"))
		return sb.String(), nil
	}

	// Group issues by severity
	errors := []scanner.Issue{}
	warnings := []scanner.Issue{}
	info := []scanner.Issue{}

	for _, issue := range r.Issues {
		switch issue.Severity {
		case "error":
			errors = append(errors, issue)
		case "warning":
			warnings = append(warnings, issue)
		default:
			info = append(info, issue)
		}
	}

	if len(errors) > 0 {
		sb.WriteString(color.RedString("❌ ERRORS\n"))
		sb.WriteString(color.RedString("---------\n"))
		for _, issue := range errors {
			formatIssue(&sb, issue)
		}
		sb.WriteString("\n")
	}

	if len(warnings) > 0 {
		sb.WriteString(color.YellowString("⚠️  WARNINGS\n"))
		sb.WriteString(color.YellowString("-----------\n"))
		for _, issue := range warnings {
			formatIssue(&sb, issue)
		}
		sb.WriteString("\n")
	}

	if len(info) > 0 {
		sb.WriteString(color.HiBlackString("ℹ️  INFO\n"))
		sb.WriteString(color.HiBlackString("-------\n"))
		for _, issue := range info {
			formatIssue(&sb, issue)
		}
	}

	return sb.String(), nil
}

func formatIssue(sb *strings.Builder, issue scanner.Issue) {
	sb.WriteString(fmt.Sprintf("\nPort %d: %s\n", issue.Port, issue.Description))

	for _, b := range issue.Bindings {
		rel, _ := filepath.Rel(".", b.File)
		if rel == "" {
			rel = b.File
		}
		sb.WriteString(fmt.Sprintf("  → %s in %s (%s)\n", b.String(), rel, b.Service))
	}
}

// FormatJSON generates JSON output
func FormatJSON(r *scanner.Result) (string, error) {
	type jsonBinding struct {
		Port      int    `json:"host_port"`
		Container int    `json:"container_port"`
		Protocol  string `json:"protocol"`
		HostIP    string `json:"host_ip,omitempty"`
		Service   string `json:"service"`
		File      string `json:"file"`
	}

	type jsonIssue struct {
		Severity    string        `json:"severity"`
		Type        string        `json:"type"`
		Port        int           `json:"port"`
		Description string        `json:"description"`
		Bindings    []jsonBinding `json:"bindings,omitempty"`
	}

	type jsonOutput struct {
		Path         string        `json:"path"`
		ComposeFiles []string      `json:"compose_files"`
		TotalPorts   int           `json:"total_ports"`
		Issues       []jsonIssue   `json:"issues"`
		Bindings     []jsonBinding `json:"bindings"`
	}

	out := jsonOutput{
		Path:         r.Path,
		ComposeFiles: r.ComposeFiles,
		TotalPorts:   len(r.PortBindings),
	}

	for _, issue := range r.Issues {
		ji := jsonIssue{
			Severity:    issue.Severity,
			Type:        issue.Type,
			Port:        issue.Port,
			Description: issue.Description,
		}
		for _, b := range issue.Bindings {
			ji.Bindings = append(ji.Bindings, jsonBinding{
				Port:      b.HostPort,
				Container: b.ContainerPort,
				Protocol:  b.Protocol,
				HostIP:    b.HostIP,
				Service:   b.Service,
				File:      b.File,
			})
		}
		out.Issues = append(out.Issues, ji)
	}

	for _, b := range r.PortBindings {
		out.Bindings = append(out.Bindings, jsonBinding{
			Port:      b.HostPort,
			Container: b.ContainerPort,
			Protocol:  b.Protocol,
			HostIP:    b.HostIP,
			Service:   b.Service,
			File:      b.File,
		})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatMarkdown generates markdown output
func FormatMarkdown(r *scanner.Result) (string, error) {
	var sb strings.Builder

	sb.WriteString("# Port Check Report\n\n")
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n\n", r.Path))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Compose files scanned | %d |\n", len(r.ComposeFiles)))
	sb.WriteString(fmt.Sprintf("| Total port bindings | %d |\n", len(r.PortBindings)))
	sb.WriteString(fmt.Sprintf("| Issues found | %d |\n", len(r.Issues)))
	sb.WriteString("\n")

	if len(r.Issues) == 0 {
		sb.WriteString("✅ **No port conflicts detected!**\n\n")
	} else {
		sb.WriteString("## Issues\n\n")
		sb.WriteString("| Severity | Port | Type | Description |\n")
		sb.WriteString("|----------|------|------|-------------|\n")

		for _, issue := range r.Issues {
			sevIcon := ""
			switch issue.Severity {
			case "error":
				sevIcon = "🔴"
			case "warning":
				sevIcon = "🟡"
			default:
				sevIcon = "🔵"
			}
			sb.WriteString(fmt.Sprintf("| %s %s | %d | %s | %s |\n",
				sevIcon, issue.Severity, issue.Port, issue.Type, issue.Description))
		}
		sb.WriteString("\n")
	}

	// All bindings
	if len(r.PortBindings) > 0 {
		sb.WriteString("## All Port Bindings\n\n")
		sb.WriteString("| Host Port | Container Port | Service | File |\n")
		sb.WriteString("|-----------|----------------|---------|------|\n")

		for _, b := range r.PortBindings {
			rel, _ := filepath.Rel(".", b.File)
			if rel == "" {
				rel = b.File
			}
			sb.WriteString(fmt.Sprintf("| %d | %d | %s | `%s` |\n",
				b.HostPort, b.ContainerPort, b.Service, rel))
		}
	}

	return sb.String(), nil
}
