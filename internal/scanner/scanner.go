// Package scanner implements port collision detection for Docker Compose
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// PortBinding represents a single port binding
type PortBinding struct {
	HostPort      int
	ContainerPort int
	Protocol      string // tcp, udp
	HostIP        string // binding address
	Service       string
	File          string
	Original      string // original string from compose file
}

// Issue represents a detected port problem
type Issue struct {
	Severity    string // error, warning
	Type        string // collision, privileged, shadowed
	Port        int
	Description string
	Bindings    []PortBinding
}

// Result contains the scan results
type Result struct {
	Path         string
	ComposeFiles []string
	PortBindings []PortBinding
	PortMap      map[int][]PortBinding // grouped by host port
	Issues       []Issue
}

// HasIssues returns true if there are any issues
func (r *Result) HasIssues() bool {
	return len(r.Issues) > 0
}

// Scan scans compose files for port collisions
func Scan(basePath string) (*Result, error) {
	r := &Result{
		Path:    basePath,
		PortMap: make(map[int][]PortBinding),
	}

	// Find compose files
	patterns := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
		"docker-compose.*.yml",
		"docker-compose.*.yaml",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(basePath, pattern))
		r.ComposeFiles = append(r.ComposeFiles, matches...)
	}

	// Also check subdirectories
	entries, _ := os.ReadDir(basePath)
	for _, entry := range entries {
		if entry.IsDir() {
			for _, pattern := range patterns[:4] { // Only standard names in subdirs
				subPath := filepath.Join(basePath, entry.Name(), pattern)
				if _, err := os.Stat(subPath); err == nil {
					r.ComposeFiles = append(r.ComposeFiles, subPath)
				}
			}
		}
	}

	// Parse each compose file
	for _, file := range r.ComposeFiles {
		if err := r.parseComposeFile(file); err != nil {
			// Add as warning but continue
			r.Issues = append(r.Issues, Issue{
				Severity:    "warning",
				Type:        "parse_error",
				Description: fmt.Sprintf("Failed to parse %s: %v", file, err),
			})
		}
	}

	// Analyze for issues
	r.analyze()

	return r, nil
}

type composeFile struct {
	Services map[string]struct {
		Ports []interface{} `yaml:"ports"`
	} `yaml:"services"`
}

func (r *Result) parseComposeFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var compose composeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return err
	}

	for serviceName, svc := range compose.Services {
		for _, port := range svc.Ports {
			binding := parsePort(port, serviceName, path)
			if binding != nil {
				r.PortBindings = append(r.PortBindings, *binding)
				r.PortMap[binding.HostPort] = append(r.PortMap[binding.HostPort], *binding)
			}
		}
	}

	return nil
}

// parsePort parses various port formats:
// - "3000"
// - "3000:3000"
// - "8080:80"
// - "127.0.0.1:8080:80"
// - "8080:80/tcp"
// - {target: 80, published: 8080}
var portRegex = regexp.MustCompile(`^(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):)?(\d+)(?::(\d+))?(?:/(tcp|udp))?$`)

func parsePort(port interface{}, service, file string) *PortBinding {
	binding := &PortBinding{
		Service:  service,
		File:     file,
		Protocol: "tcp",
	}

	switch v := port.(type) {
	case string:
		binding.Original = v
		match := portRegex.FindStringSubmatch(v)
		if match == nil {
			return nil
		}

		binding.HostIP = match[1]

		portStr := match[2]
		containerStr := match[3]

		hostPort, _ := strconv.Atoi(portStr)

		if containerStr != "" {
			containerPort, _ := strconv.Atoi(containerStr)
			binding.HostPort = hostPort
			binding.ContainerPort = containerPort
		} else {
			// Single port: same for host and container
			binding.HostPort = hostPort
			binding.ContainerPort = hostPort
		}

		if match[4] != "" {
			binding.Protocol = match[4]
		}

	case int:
		binding.Original = fmt.Sprintf("%d", v)
		binding.HostPort = v
		binding.ContainerPort = v

	case map[string]interface{}:
		// Long syntax
		if target, ok := v["target"].(int); ok {
			binding.ContainerPort = target
		}
		if published, ok := v["published"].(int); ok {
			binding.HostPort = published
		} else if published, ok := v["published"].(string); ok {
			binding.HostPort, _ = strconv.Atoi(published)
		}
		if protocol, ok := v["protocol"].(string); ok {
			binding.Protocol = protocol
		}
		if hostIP, ok := v["host_ip"].(string); ok {
			binding.HostIP = hostIP
		}
		binding.Original = fmt.Sprintf("%d:%d", binding.HostPort, binding.ContainerPort)

	default:
		return nil
	}

	if binding.HostPort == 0 {
		return nil
	}

	return binding
}

func (r *Result) analyze() {
	// Check for collisions (same port bound multiple times)
	for port, bindings := range r.PortMap {
		if len(bindings) > 1 {
			// Group by binding specificity
			directCollisions := []PortBinding{}
			potentialCollisions := []PortBinding{}

			for _, b := range bindings {
				if b.HostIP == "" || b.HostIP == "0.0.0.0" {
					directCollisions = append(directCollisions, b)
				} else {
					potentialCollisions = append(potentialCollisions, b)
				}
			}

			// Direct collision (any wildcard + any other binding)
			if len(directCollisions) > 1 ||
				(len(directCollisions) > 0 && len(potentialCollisions) > 0) {
				r.Issues = append(r.Issues, Issue{
					Severity:    "error",
					Type:        "collision",
					Port:        port,
					Description: fmt.Sprintf("Port %d bound by multiple services", port),
					Bindings:    bindings,
				})
			} else if len(potentialCollisions) > 1 {
				// Multiple specific bindings - might be intentional
				r.Issues = append(r.Issues, Issue{
					Severity:    "warning",
					Type:        "potential_collision",
					Port:        port,
					Description: fmt.Sprintf("Port %d bound multiple times with specific IPs", port),
					Bindings:    bindings,
				})
			}
		}
	}

	// Check for privileged ports
	for _, binding := range r.PortBindings {
		if binding.HostPort > 0 && binding.HostPort < 1024 {
			r.Issues = append(r.Issues, Issue{
				Severity:    "warning",
				Type:        "privileged",
				Port:        binding.HostPort,
				Description: fmt.Sprintf("Port %d is privileged (requires root/sudo)", binding.HostPort),
				Bindings:    []PortBinding{binding},
			})
		}
	}

	// Check for common system port conflicts
	commonPorts := map[int]string{
		22:   "SSH",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		443:  "HTTPS",
		3306: "MySQL",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP Alternate",
		27017: "MongoDB",
	}

	for _, binding := range r.PortBindings {
		if svc, ok := commonPorts[binding.HostPort]; ok {
			// Only warn if binding to all interfaces
			if binding.HostIP == "" || binding.HostIP == "0.0.0.0" {
				alreadyWarned := false
				for _, issue := range r.Issues {
					if issue.Port == binding.HostPort && issue.Type == "collision" {
						alreadyWarned = true
						break
					}
				}
				if !alreadyWarned {
					r.Issues = append(r.Issues, Issue{
						Severity:    "info",
						Type:        "common_port",
						Port:        binding.HostPort,
						Description: fmt.Sprintf("Port %d is commonly used by %s", binding.HostPort, svc),
						Bindings:    []PortBinding{binding},
					})
				}
			}
		}
	}

	// Sort issues by severity then port
	severityOrder := map[string]int{"error": 0, "warning": 1, "info": 2}
	sort.Slice(r.Issues, func(i, j int) bool {
		if severityOrder[r.Issues[i].Severity] != severityOrder[r.Issues[j].Severity] {
			return severityOrder[r.Issues[i].Severity] < severityOrder[r.Issues[j].Severity]
		}
		return r.Issues[i].Port < r.Issues[j].Port
	})
}

// GroupedByFile returns bindings grouped by compose file
func (r *Result) GroupedByFile() map[string][]PortBinding {
	grouped := make(map[string][]PortBinding)
	for _, b := range r.PortBindings {
		grouped[b.File] = append(grouped[b.File], b)
	}
	return grouped
}

// String returns a summary string
func (b PortBinding) String() string {
	var parts []string
	if b.HostIP != "" {
		parts = append(parts, b.HostIP)
	}
	parts = append(parts, fmt.Sprintf("%d:%d", b.HostPort, b.ContainerPort))
	str := strings.Join(parts, ":")
	if b.Protocol != "tcp" {
		str += "/" + b.Protocol
	}
	return str
}
