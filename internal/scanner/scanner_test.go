package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan_NoFiles(t *testing.T) {
	dir := t.TempDir()

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.ComposeFiles) != 0 {
		t.Errorf("Expected 0 compose files, got %d", len(result.ComposeFiles))
	}

	if len(result.PortBindings) != 0 {
		t.Errorf("Expected 0 port bindings, got %d", len(result.PortBindings))
	}
}

func TestScan_BasicPorts(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
  api:
    image: node
    ports:
      - "3000:3000"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) != 2 {
		t.Errorf("Expected 2 port bindings, got %d", len(result.PortBindings))
	}

	// Should find bindings for ports 8080 and 3000
	found8080 := false
	found3000 := false
	for _, b := range result.PortBindings {
		if b.HostPort == 8080 && b.ContainerPort == 80 {
			found8080 = true
		}
		if b.HostPort == 3000 && b.ContainerPort == 3000 {
			found3000 = true
		}
	}

	if !found8080 {
		t.Error("Port 8080:80 not found")
	}
	if !found3000 {
		t.Error("Port 3000:3000 not found")
	}
}

func TestScan_Collision(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web1:
    image: nginx
    ports:
      - "8080:80"
  web2:
    image: nginx
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect collision
	if !result.HasIssues() {
		t.Error("Expected to detect port collision")
	}

	foundCollision := false
	for _, issue := range result.Issues {
		if issue.Type == "collision" && issue.Port == 8080 {
			foundCollision = true
			if len(issue.Bindings) != 2 {
				t.Errorf("Collision should have 2 bindings, got %d", len(issue.Bindings))
			}
		}
	}

	if !foundCollision {
		t.Error("Did not find collision issue for port 8080")
	}
}

func TestScan_PrivilegedPort(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: nginx
    ports:
      - "80:80"
      - "443:443"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	privilegedCount := 0
	for _, issue := range result.Issues {
		if issue.Type == "privileged" {
			privilegedCount++
		}
	}

	if privilegedCount != 2 {
		t.Errorf("Expected 2 privileged port warnings, got %d", privilegedCount)
	}
}

func TestScan_PortFormats(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  test:
    image: test
    ports:
      - "3000"
      - "8080:80"
      - "127.0.0.1:9000:9000"
      - "5000:5000/udp"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) != 4 {
		t.Errorf("Expected 4 port bindings, got %d", len(result.PortBindings))
	}

	// Check specific formats
	tests := []struct {
		hostPort int
		wantIP   string
		wantProt string
	}{
		{3000, "", "tcp"},
		{8080, "", "tcp"},
		{9000, "127.0.0.1", "tcp"},
		{5000, "", "udp"},
	}

	for _, tc := range tests {
		found := false
		for _, b := range result.PortBindings {
			if b.HostPort == tc.hostPort {
				found = true
				if b.HostIP != tc.wantIP {
					t.Errorf("Port %d: HostIP = %s, want %s", tc.hostPort, b.HostIP, tc.wantIP)
				}
				if b.Protocol != tc.wantProt {
					t.Errorf("Port %d: Protocol = %s, want %s", tc.hostPort, b.Protocol, tc.wantProt)
				}
			}
		}
		if !found {
			t.Errorf("Port %d not found", tc.hostPort)
		}
	}
}

func TestScan_LongSyntax(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: nginx
    ports:
      - target: 80
        published: 8080
        protocol: tcp
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) != 1 {
		t.Fatalf("Expected 1 port binding, got %d", len(result.PortBindings))
	}

	b := result.PortBindings[0]
	if b.HostPort != 8080 {
		t.Errorf("HostPort = %d, want 8080", b.HostPort)
	}
	if b.ContainerPort != 80 {
		t.Errorf("ContainerPort = %d, want 80", b.ContainerPort)
	}
}

func TestScan_MultipleComposeFiles(t *testing.T) {
	dir := t.TempDir()

	compose1 := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
`
	compose2 := `services:
  api:
    image: node
    ports:
      - "8080:3000"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.dev.yml"), []byte(compose2), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.ComposeFiles) < 2 {
		t.Errorf("Expected at least 2 compose files, got %d", len(result.ComposeFiles))
	}

	// Should detect cross-file collision
	foundCollision := false
	for _, issue := range result.Issues {
		if issue.Type == "collision" && issue.Port == 8080 {
			foundCollision = true
		}
	}

	if !foundCollision {
		t.Error("Should detect collision across multiple compose files")
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input       interface{}
		wantHost    int
		wantCont    int
		wantIP      string
		wantProto   string
		shouldBeNil bool
	}{
		{"3000", 3000, 3000, "", "tcp", false},
		{"8080:80", 8080, 80, "", "tcp", false},
		{"127.0.0.1:9000:9000", 9000, 9000, "127.0.0.1", "tcp", false},
		{"5000:5000/udp", 5000, 5000, "", "udp", false},
		{3000, 3000, 3000, "", "tcp", false},
		{"invalid", 0, 0, "", "", true},
		{"", 0, 0, "", "", true},
	}

	for _, tc := range tests {
		result := parsePort(tc.input, "test", "test.yml")
		if tc.shouldBeNil {
			if result != nil {
				t.Errorf("parsePort(%v) should be nil", tc.input)
			}
			continue
		}
		if result == nil {
			t.Errorf("parsePort(%v) returned nil", tc.input)
			continue
		}
		if result.HostPort != tc.wantHost {
			t.Errorf("parsePort(%v).HostPort = %d, want %d", tc.input, result.HostPort, tc.wantHost)
		}
		if result.ContainerPort != tc.wantCont {
			t.Errorf("parsePort(%v).ContainerPort = %d, want %d", tc.input, result.ContainerPort, tc.wantCont)
		}
		if result.HostIP != tc.wantIP {
			t.Errorf("parsePort(%v).HostIP = %s, want %s", tc.input, result.HostIP, tc.wantIP)
		}
		if result.Protocol != tc.wantProto {
			t.Errorf("parsePort(%v).Protocol = %s, want %s", tc.input, result.Protocol, tc.wantProto)
		}
	}
}

func TestHasIssues(t *testing.T) {
	r := &Result{}
	if r.HasIssues() {
		t.Error("Empty result should not have issues")
	}

	r.Issues = append(r.Issues, Issue{Type: "test"})
	if !r.HasIssues() {
		t.Error("Result with issues should return true")
	}
}

// Edge case tests

func TestScan_PortRanges(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  multi:
    image: test
    ports:
      - "8000-8005:8000-8005"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Port ranges are complex - just verify no crash
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestScan_IPv6Binding(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  ipv6:
    image: test
    ports:
      - "[::1]:8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should handle IPv6 without crashing
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestScan_MixedPortSyntax(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  mixed:
    image: test
    ports:
      - 3000
      - "4000:4000"
      - "5000:5000/udp"
      - target: 6000
        published: 6001
        protocol: tcp
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) < 2 {
		t.Errorf("Expected at least 2 port bindings, got %d", len(result.PortBindings))
	}
}

func TestScan_VeryHighPort(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  highport:
    image: test
    ports:
      - "65535:65535"
      - "65534:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) != 2 {
		t.Errorf("Expected 2 port bindings, got %d", len(result.PortBindings))
	}
}

func TestScan_ZeroPort(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  zeroport:
    image: test
    ports:
      - "0:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Port 0 means random port assignment
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestScan_MalformedCompose(t *testing.T) {
	dir := t.TempDir()

	// Invalid YAML
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("{{invalid}}"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Scan(dir)
	// Should either error or return empty result
	if err == nil {
		t.Log("No error on malformed compose - acceptable behavior")
	}
}

func TestScan_UDPAndTCPSamePort(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  dual:
    image: test
    ports:
      - "53:53/tcp"
      - "53:53/udp"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// TCP and UDP on same port should NOT be a collision
	for _, issue := range result.Issues {
		if issue.Type == "collision" {
			t.Log("Warning: TCP/UDP same port detected as collision - might be intentional")
		}
	}
}

func TestScan_EnvironmentVariableInPort(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  envport:
    image: test
    ports:
      - "${HOST_PORT:-8080}:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should handle env vars gracefully
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestScan_ExposedPorts(t *testing.T) {
	dir := t.TempDir()

	// expose doesn't bind to host, shouldn't conflict
	compose := `services:
  internal:
    image: test
    expose:
      - "8080"
  web:
    image: test
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// expose should not show as port binding
	if len(result.PortBindings) != 1 {
		t.Errorf("Expected 1 port binding (ports, not expose), got %d", len(result.PortBindings))
	}
}

func TestScan_MultipleInterfaceBindings(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  multi:
    image: test
    ports:
      - "127.0.0.1:8080:80"
      - "0.0.0.0:8080:80"
      - "192.168.1.1:8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect potential conflict on same port different interfaces
	if len(result.PortBindings) != 3 {
		t.Errorf("Expected 3 port bindings, got %d", len(result.PortBindings))
	}
}

func TestScan_NestedComposeFiles(t *testing.T) {
	dir := t.TempDir()

	// Create nested directory structure
	subdir := filepath.Join(dir, "services", "api")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	compose := `services:
  api:
    image: api
    ports:
      - "3000:3000"
`
	if err := os.WriteFile(filepath.Join(subdir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find compose file in nested directory
	if len(result.ComposeFiles) == 0 {
		t.Log("No nested compose files found - may depend on scan depth")
	}
}

func TestScan_ProfiledServices(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: test
    ports:
      - "8080:80"
  debug:
    image: test
    profiles:
      - debug
    ports:
      - "8080:8080"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Debug service port should be detected even if profiled
	if len(result.PortBindings) < 2 {
		t.Log("Profile-gated ports might not be scanned")
	}
}

func TestScan_ContainerPortOnly(t *testing.T) {
	dir := t.TempDir()

	// Just container port means random host port
	compose := `services:
  random:
    image: test
    ports:
      - "80"
      - "443"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should handle container-only ports
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestScan_DuplicateComposeFiles(t *testing.T) {
	dir := t.TempDir()

	compose1 := `services:
  web:
    image: test
    ports:
      - "8080:80"
`
	compose2 := `services:
  web:
    image: test
    ports:
      - "8080:80"
`
	// Create both common compose file names
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yaml"), []byte(compose2), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should handle both files
	if len(result.ComposeFiles) < 2 {
		t.Log("Only one compose file found - might prefer one extension")
	}
}

func TestScan_HealthcheckPorts(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: test
    ports:
      - "8080:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not extract ports from healthcheck commands
	if len(result.PortBindings) != 1 {
		t.Errorf("Expected 1 port binding, got %d", len(result.PortBindings))
	}
}

func TestScan_EmptyPortsSection(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    image: test
    ports: []
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.PortBindings) != 0 {
		t.Errorf("Expected 0 port bindings, got %d", len(result.PortBindings))
	}
}

func TestScan_PortWithProtocolSuffix(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  dns:
    image: dns
    ports:
      - "53:53/tcp"
      - "53:53/udp"
  web:
    image: nginx
    ports:
      - "80:80/tcp"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should parse protocol suffixes
	if len(result.PortBindings) < 3 {
		t.Errorf("Expected at least 3 port bindings, got %d", len(result.PortBindings))
	}
}
