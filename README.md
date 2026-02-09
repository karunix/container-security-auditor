# Security Engineering Portfolio

This repository index documents a set of focused, test-driven security tools
built to detect real-world misconfigurations across modern systems.

## Projects

### 🔒 Web Security Analyzer
**Focus:** HTTP security headers  
**Highlights:**
- Detects missing CSP, HSTS, XFO, XCTO
- JSON output + exit codes
- CI/CD friendly

### 🌐 Network Security Analyzer
**Focus:** Network exposure & TLS hygiene  
**Highlights:**
- Open TCP port detection
- Deprecated TLS version detection
- Machine-readable output

### 🐳 Container Security Auditor
**Focus:** Container runtime misconfigurations  
**Highlights:**
- Containers running as root
- Privileged containers
- Dangerous host mounts
- Deterministic, Docker-free analysis

## Design Philosophy

- Deterministic checks over noisy scanning
- Test-driven development
- Automation-first output (JSON + exit codes)
- No exploitation, no intrusive behavior

## Intended Audience

- Security engineers
- Platform engineers
- CI/CD and infrastructure teams
