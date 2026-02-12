// Package runtime provides real-time port scanning of running containers
package runtime

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Container represents a running Docker container
type Container struct {
	ID        string
	Name      string
	Image     string
	State     string
	Ports     []ContainerPort
	Labels    map[string]string
	CreatedAt time.Time
}

// ContainerPort represents a port exposed by a running container
type ContainerPort struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Protocol      string
	Type          string // tcp, udp
}

// RuntimeResult contains runtime scan results
type RuntimeResult struct {
	Containers    []Container
	UsedPorts     map[int][]Container     // port -> containers using it
	Conflicts     []RuntimeConflict
	ScanTime      time.Time
	DockerRunning bool
}

// RuntimeConflict describes a conflict between compose definition and runtime
type RuntimeConflict struct {
	Port           int
	ComposeService string
	RuntimeInfo    string
	Type           string // "already_in_use", "not_running", "mismatch"
	Message        string
}

// dockerContainer is the JSON structure from docker ps
type dockerContainer struct {
	ID      string `json:"Id"`
	Names   string `json:"Names"`
	Image   string `json:"Image"`
	State   string `json:"State"`
	Ports   string `json:"Ports"`
	Labels  string `json:"Labels"`
	Created string `json:"CreatedAt"`
}

// ScanRuntime scans for currently running containers
func ScanRuntime() (*RuntimeResult, error) {
	result := &RuntimeResult{
		UsedPorts: make(map[int][]Container),
		ScanTime:  time.Now(),
	}

	// Check if Docker is available
	if err := exec.Command("docker", "version").Run(); err != nil {
		result.DockerRunning = false
		return result, nil
	}
	result.DockerRunning = true

	// Get running containers
	cmd := exec.Command("docker", "ps", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Parse JSON lines
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var dc dockerContainer
		if err := json.Unmarshal([]byte(line), &dc); err != nil {
			continue
		}

		container := Container{
			ID:     dc.ID[:12],
			Name:   strings.TrimPrefix(dc.Names, "/"),
			Image:  dc.Image,
			State:  dc.State,
			Ports:  parsePorts(dc.Ports),
			Labels: parseLabels(dc.Labels),
		}

		result.Containers = append(result.Containers, container)

		// Track used ports
		for _, p := range container.Ports {
			if p.HostPort > 0 {
				result.UsedPorts[p.HostPort] = append(result.UsedPorts[p.HostPort], container)
			}
		}
	}

	return result, nil
}

// parsePorts parses the Ports field from Docker ps
// Format: "0.0.0.0:8080->80/tcp, :::8080->80/tcp"
func parsePorts(portsStr string) []ContainerPort {
	var ports []ContainerPort

	if portsStr == "" {
		return ports
	}

	parts := strings.Split(portsStr, ", ")
	for _, part := range parts {
		p := parsePortMapping(part)
		if p != nil {
			ports = append(ports, *p)
		}
	}

	return ports
}

func parsePortMapping(s string) *ContainerPort {
	// Format: "0.0.0.0:8080->80/tcp" or ":::8080->80/tcp"
	p := &ContainerPort{Protocol: "tcp"}

	// Split by ->
	arrowParts := strings.Split(s, "->")
	if len(arrowParts) != 2 {
		return nil
	}

	hostPart := arrowParts[0]
	containerPart := arrowParts[1]

	// Parse container port and protocol
	slashParts := strings.Split(containerPart, "/")
	if len(slashParts) >= 1 {
		fmt.Sscanf(slashParts[0], "%d", &p.ContainerPort)
	}
	if len(slashParts) >= 2 {
		p.Protocol = slashParts[1]
	}

	// Parse host IP and port
	colonIdx := strings.LastIndex(hostPart, ":")
	if colonIdx >= 0 {
		p.HostIP = hostPart[:colonIdx]
		fmt.Sscanf(hostPart[colonIdx+1:], "%d", &p.HostPort)
	}

	return p
}

func parseLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)
	if labelsStr == "" {
		return labels
	}

	parts := strings.Split(labelsStr, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
	return labels
}

// CheckPortsInUse checks if specific ports are already in use on the host
func CheckPortsInUse(ports []int) map[int]bool {
	result := make(map[int]bool)

	for _, port := range ports {
		// Try to bind to the port
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			result[port] = true // Port is in use
		} else {
			listener.Close()
			result[port] = false // Port is free
		}
	}

	return result
}

// FindFreePort finds a free port near the suggested one
func FindFreePort(suggested int, maxAttempts int) int {
	for i := 0; i < maxAttempts; i++ {
		port := suggested + i
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			listener.Close()
			return port
		}
	}
	return 0
}

// SuggestFreePorts suggests alternative free ports for a list of conflicting ports
func SuggestFreePorts(conflictPorts []int) map[int]int {
	suggestions := make(map[int]int)

	for _, port := range conflictPorts {
		// Try common alternatives based on port type
		alternatives := getPortAlternatives(port)

		for _, alt := range alternatives {
			addr := fmt.Sprintf(":%d", alt)
			listener, err := net.Listen("tcp", addr)
			if err == nil {
				listener.Close()
				suggestions[port] = alt
				break
			}
		}

		// If no alternative found in common alternatives, search nearby
		if _, found := suggestions[port]; !found {
			free := FindFreePort(port+1, 100)
			if free > 0 {
				suggestions[port] = free
			}
		}
	}

	return suggestions
}

// getPortAlternatives returns common alternative ports
func getPortAlternatives(port int) []int {
	alternatives := []int{}

	// Common port alternatives
	portAlternatives := map[int][]int{
		80:    {8080, 8000, 8081, 9080},
		443:   {8443, 4443, 9443},
		3000:  {3001, 3002, 3003},
		3306:  {3307, 3308, 33060},
		5432:  {5433, 5434, 54320},
		5000:  {5001, 5002, 5003},
		6379:  {6380, 6381, 6382},
		8080:  {8081, 8082, 8090, 9080},
		27017: {27018, 27019, 27020},
	}

	if alts, ok := portAlternatives[port]; ok {
		alternatives = append(alternatives, alts...)
	}

	// Also try port + 1000, port + 10000
	alternatives = append(alternatives, port+1000, port+10000)

	return alternatives
}

// FormatRuntimeResult formats runtime scan results
func FormatRuntimeResult(result *RuntimeResult) string {
	var sb strings.Builder

	sb.WriteString("# Runtime Port Scan\n\n")

	if !result.DockerRunning {
		sb.WriteString("⚠️ Docker daemon is not running\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("**Containers Found:** %d\n", len(result.Containers)))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n\n", result.ScanTime.Format(time.RFC3339)))

	if len(result.Containers) > 0 {
		sb.WriteString("## Running Containers\n\n")
		sb.WriteString("| Container | Image | Ports |\n")
		sb.WriteString("|-----------|-------|-------|\n")

		for _, c := range result.Containers {
			var ports []string
			for _, p := range c.Ports {
				if p.HostPort > 0 {
					ports = append(ports, fmt.Sprintf("%d:%d/%s", p.HostPort, p.ContainerPort, p.Protocol))
				}
			}
			portsStr := strings.Join(ports, ", ")
			if portsStr == "" {
				portsStr = "-"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.Name, c.Image, portsStr))
		}
		sb.WriteString("\n")
	}

	if len(result.Conflicts) > 0 {
		sb.WriteString("## Conflicts\n\n")
		for _, c := range result.Conflicts {
			sb.WriteString(fmt.Sprintf("- **Port %d**: %s\n", c.Port, c.Message))
		}
	}

	return sb.String()
}
