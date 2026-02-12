# portcheck

**Free and open source** — Local Port Collision Detector. Instantly find port conflicts in your Docker Compose stacks.

## The Problem

"Port already in use" is the most common local Docker error. It happens because:

- Multiple compose services bind the same port
- Multiple stacks running simultaneously with overlapping ports
- Forgetting which ports are in use
- Privileged ports requiring sudo permissions

## What It Does

- Detects host port collisions in compose files
- Identifies same port reused across stacks
- Warns on privileged ports (< 1024)
- Identifies potential conflicts with common services
- **Runtime scanning** — check actual running containers for port usage
- **Port suggestions** — automatically suggest free ports for conflicts
- **Profile-aware** — consider only active compose profiles
- **Host IP analysis** — show bind address details for each port

## Usage

```bash
# Scan current directory
portcheck scan

# Scan specific path
portcheck scan ./my-project

# Strict mode (exit 1 on any issues, for CI)
portcheck scan --strict

# JSON output
portcheck scan --format json

# Check running containers too
portcheck scan --runtime

# Get alternative port suggestions
portcheck scan --suggest

# Only check specific profiles
portcheck scan --profile dev --profile tools

# Show host IP binding details
portcheck scan --show-host-ip
```

## Example Output

```
Port Check Report
=================

Scanned: .
Compose files: 2
Port bindings: 5
Issues found: 2

❌ ERRORS
---------

Port 3000: Port 3000 bound by multiple services
  → 3000:3000 in docker-compose.yml (frontend)
  → 3000:3000 in docker-compose.dev.yml (api)

⚠️  WARNINGS
-----------

Port 80: Port 80 is privileged (requires root/sudo)
  → 80:80 in docker-compose.yml (nginx)
```

## CI Integration

```yaml
# GitHub Actions example
- name: Check ports
  run: portcheck scan --strict
```

## Installation

Download the appropriate binary for your platform from the GitHub releases page.

## Related Tools

- [envmerge](https://github.com/ecent1119/envmerge) — Resolve env variable conflicts
- [compose-flatten](https://github.com/ecent1119/compose-flatten) — Merge compose overrides
- [stackgen](https://github.com/ecent1119/stackgen) — Generate local Docker Compose stacks

## Support This Project

**portcheck is free and open source.**

If this tool saved you time, consider sponsoring:

[![Sponsor on GitHub](https://img.shields.io/badge/Sponsor-❤️-red?logo=github)](https://github.com/sponsors/ecent1119)

Your support helps maintain and improve this tool.

## License

MIT License. See LICENSE file.
