# DISCLAIMER

## portcheck — Local Port Collision Detector

### Scope of Tool

This tool is designed for **local development environments only**. It analyzes Docker Compose configurations to detect potential port conflicts.

### What This Tool Does

- Parses Docker Compose port configurations
- Identifies potential host port collisions
- Warns about privileged port usage
- Reports findings in text, JSON, or markdown

### What This Tool Does NOT Do

- Scan running processes or active ports
- Execute Docker or Compose commands
- Make network requests
- Modify any files
- Check actual port availability at runtime
- Provide network security analysis

### Liability

This software is provided **"as is"** without warranty of any kind, express or implied.

The authors and distributors:
- Make no guarantees about detection accuracy
- Cannot identify runtime port conflicts
- Accept no responsibility for port-related issues
- Are not liable for any damages arising from reliance on this tool

### Recommended Use

- As a pre-check before starting stacks
- In CI pipelines to catch conflicts early
- As a diagnostic aid, not a guarantee
- In combination with actual port testing

### Not For

- Runtime port monitoring
- Production deployment decisions
- Security auditing
- Network administration
