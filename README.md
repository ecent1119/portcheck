# portcheck

Find port collisions before `docker compose up` fails.

---

## The problem

- `docker compose up` fails with "port already in use"
- Multiple services in different compose files bind to the same port
- Port conflicts only discovered at runtime
- Privileged ports (< 1024) require root and cause silent failures

---

## What it does

- Scans all compose files in a directory (including subdirectories)
- Detects **port collisions** between services
- Warns about **privileged ports** that may fail without root
- Checks **port ranges** for overlaps
- Shows which service owns which host port

---

## New in v2.0

- **Runtime scanning** — check actual running containers for port usage
- **Port suggestions** — automatically suggest free ports for conflicts
- **Profile-aware** — consider only active compose profiles
- **Host IP analysis** — show bind address details for each port

---

## Example output

```
$ portcheck scan

Port Analysis Report
====================

📍 Host Port Bindings:
  80   → nginx (docker-compose.yml)
  443  → nginx (docker-compose.yml)
  3000 → api (docker-compose.yml)
  5432 → postgres (docker-compose.yml)
  8080 → web (services/web/docker-compose.yml)

⚠️  Issues Found:

  COLLISION: Port 8080
    - web (services/web/docker-compose.yml)
    - admin (services/admin/docker-compose.yml)

  PRIVILEGED: Port 80
    - nginx (docker-compose.yml)
    - Requires root/sudo to bind

  PRIVILEGED: Port 443
    - nginx (docker-compose.yml)
    - Requires root/sudo to bind

Summary: 2 collisions, 2 privileged ports
```

---

## Commands

```bash
# Scan current directory
portcheck scan

# Scan specific directory
portcheck scan --path ./microservices

# JSON output for CI
portcheck scan --format json

# Exit with error if issues found (for CI)
portcheck scan --strict
```

---

## What it checks

| Check | Description |
|-------|-------------|
| **Collisions** | Multiple services binding same host port |
| **Privileged** | Ports < 1024 requiring elevated privileges |
| **Ranges** | Port range overlaps (e.g., 8080-8090) |
| **Protocols** | TCP vs UDP conflicts |
| **Interfaces** | 0.0.0.0 vs 127.0.0.1 binding issues |

---

## CI Integration

```yaml
# GitHub Actions
- name: Check for port conflicts
  run: portcheck scan --strict --format json

# GitLab CI
port-check:
  script:
    - portcheck scan --strict
  allow_failure: false
```

---

## Scope

- Local development and testing only
- Read-only analysis of compose files
- No runtime port checking
- No network scanning
- No telemetry, no network calls

---

## Common problems this solves

- "docker compose port already in use"
- "port conflict docker compose"
- "find which container uses port"
- "multiple compose files same port"
- "docker port collision detection"
- "address already in use docker"
- "check port availability before docker up"

---

## Get it

👉 [Download on Gumroad](https://ecent.gumroad.com/l/rxgcia)

---

## Related tools

| Tool | Purpose |
|------|---------|
| **[stackgen](https://github.com/ecent119/stackgen)** | Generate Docker Compose stacks |
| **[compose-flatten](https://github.com/ecent119/compose-flatten)** | Merge compose files |
| **[devcheck](https://github.com/ecent119/devcheck)** | Validate compose configurations |
| **[compose-diff](https://github.com/ecent119/compose-diff)** | Compare compose files |

---

If this tool saved you time, consider starring the repo.

---

## License

MIT — this repository contains documentation and examples only.
