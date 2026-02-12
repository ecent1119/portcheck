// Package profiles implements compose profile-aware port scanning
package profiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProfilesConfig represents all profiles found in compose files
type ProfilesConfig struct {
	Profiles map[string]*Profile
	Files    []string
}

// Profile represents a compose profile and its services
type Profile struct {
	Name     string
	Services []ProfileService
}

// ProfileService represents a service in a profile
type ProfileService struct {
	Name     string
	Ports    []string
	EnvFiles []string
	File     string
}

// composeWithProfiles is for parsing compose files with profiles
type composeWithProfiles struct {
	Services map[string]struct {
		Ports    []interface{} `yaml:"ports"`
		Profiles []string      `yaml:"profiles"`
		EnvFile  interface{}   `yaml:"env_file"`
	} `yaml:"services"`
}

// LoadProfiles loads all profile information from compose files
func LoadProfiles(basePath string) (*ProfilesConfig, error) {
	config := &ProfilesConfig{
		Profiles: make(map[string]*Profile),
	}

	// Always have a "default" profile for services without profiles
	config.Profiles["default"] = &Profile{Name: "default"}

	// Find compose files
	patterns := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}

	for _, pattern := range patterns {
		path := filepath.Join(basePath, pattern)
		if _, err := os.Stat(path); err == nil {
			config.Files = append(config.Files, path)
			if err := parseComposeProfiles(path, config); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", path, err)
			}
		}
	}

	return config, nil
}

func parseComposeProfiles(path string, config *ProfilesConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var compose composeWithProfiles
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return err
	}

	for serviceName, svc := range compose.Services {
		// Collect ports as strings
		var ports []string
		for _, p := range svc.Ports {
			switch v := p.(type) {
			case string:
				ports = append(ports, v)
			case int:
				ports = append(ports, fmt.Sprintf("%d", v))
			case map[string]interface{}:
				if pub, ok := v["published"]; ok {
					if cont, ok := v["target"]; ok {
						ports = append(ports, fmt.Sprintf("%v:%v", pub, cont))
					}
				}
			}
		}

		// Collect env files
		var envFiles []string
		switch ef := svc.EnvFile.(type) {
		case string:
			envFiles = append(envFiles, ef)
		case []interface{}:
			for _, f := range ef {
				if s, ok := f.(string); ok {
					envFiles = append(envFiles, s)
				}
			}
		}

		ps := ProfileService{
			Name:     serviceName,
			Ports:    ports,
			EnvFiles: envFiles,
			File:     path,
		}

		// Add to appropriate profiles
		if len(svc.Profiles) == 0 {
			// No profiles = default profile
			config.Profiles["default"].Services = append(config.Profiles["default"].Services, ps)
		} else {
			for _, profileName := range svc.Profiles {
				if _, exists := config.Profiles[profileName]; !exists {
					config.Profiles[profileName] = &Profile{Name: profileName}
				}
				config.Profiles[profileName].Services = append(config.Profiles[profileName].Services, ps)
			}
		}
	}

	return nil
}

// GetActivePorts returns all ports that would be active for given profiles
func (c *ProfilesConfig) GetActivePorts(activeProfiles []string) []string {
	var ports []string
	seen := make(map[string]bool)

	// Always include default profile
	profiles := append([]string{"default"}, activeProfiles...)

	for _, profileName := range profiles {
		if profile, exists := c.Profiles[profileName]; exists {
			for _, svc := range profile.Services {
				for _, port := range svc.Ports {
					if !seen[port] {
						seen[port] = true
						ports = append(ports, port)
					}
				}
			}
		}
	}

	return ports
}

// DetectPortConflicts detects port conflicts within active profiles
func (c *ProfilesConfig) DetectPortConflicts(activeProfiles []string) []PortConflict {
	var conflicts []PortConflict

	// Track port -> services mapping
	portServices := make(map[string][]ServiceInfo)

	profiles := append([]string{"default"}, activeProfiles...)

	for _, profileName := range profiles {
		if profile, exists := c.Profiles[profileName]; exists {
			for _, svc := range profile.Services {
				for _, port := range svc.Ports {
					// Extract host port
					hostPort := extractHostPort(port)
					if hostPort != "" {
						portServices[hostPort] = append(portServices[hostPort], ServiceInfo{
							Service: svc.Name,
							Profile: profileName,
							Port:    port,
						})
					}
				}
			}
		}
	}

	// Find conflicts
	for port, services := range portServices {
		if len(services) > 1 {
			conflicts = append(conflicts, PortConflict{
				Port:     port,
				Services: services,
			})
		}
	}

	return conflicts
}

// ServiceInfo holds info about a service using a port
type ServiceInfo struct {
	Service string
	Profile string
	Port    string
}

// PortConflict represents a port conflict between services
type PortConflict struct {
	Port     string
	Services []ServiceInfo
}

func extractHostPort(portSpec string) string {
	// Handle formats like "8080:80", "127.0.0.1:8080:80", "8080"
	parts := strings.Split(portSpec, ":")
	switch len(parts) {
	case 1:
		return strings.Split(parts[0], "/")[0] // Remove /tcp, /udp
	case 2:
		return strings.Split(parts[0], "/")[0]
	case 3:
		return strings.Split(parts[1], "/")[0]
	}
	return portSpec
}

// ListProfiles returns all available profile names
func (c *ProfilesConfig) ListProfiles() []string {
	var names []string
	for name := range c.Profiles {
		names = append(names, name)
	}
	return names
}

// FormatProfiles formats profile information as text
func FormatProfiles(config *ProfilesConfig) string {
	var sb strings.Builder

	sb.WriteString("# Compose Profiles\n\n")

	for name, profile := range config.Profiles {
		sb.WriteString(fmt.Sprintf("## Profile: %s\n", name))
		if len(profile.Services) == 0 {
			sb.WriteString("  (no services)\n")
		} else {
			for _, svc := range profile.Services {
				sb.WriteString(fmt.Sprintf("  - **%s**", svc.Name))
				if len(svc.Ports) > 0 {
					sb.WriteString(fmt.Sprintf(" [ports: %s]", strings.Join(svc.Ports, ", ")))
				}
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
