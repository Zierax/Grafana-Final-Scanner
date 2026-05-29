<div align="center">

# 🔍 Grafana Final Scanner

**Professional-Grade Security Assessment Tool for Grafana Deployments**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/badge/Release-v3.0.0-blue?logo=github)](https://github.com/Zierax/Grafana-Final-Scanner/releases)
[![GitHub Workflow Status](https://img.shields.io/badge/Tests-Passing-brightgreen?logo=github-actions)](.github/workflows/python-package.yml)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Code Style](https://img.shields.io/badge/Code%20Style-Ruff-7B2FF7?logo=python)](pyproject.toml)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen)](CONTRIBUTING.md)

**15+ CVE checks | Multi-source fingerprinting | Auto-detection | Web Dashboard | Multi-format reports**

</div>

---

## ⚠️ Legal Notice

> **This tool is intended for AUTHORIZED security assessments and educational purposes only.**
>
> By using this software, you agree to:
> - Only scan systems you own, manage, or have **explicit written permission** to test.
> - Unauthorized scanning may violate the **Computer Fraud and Abuse Act (CFAA)** and similar international laws.
> - This software is provided **"AS IS"** without warranties. The developer assumes **no liability** for misuse.
>
> **If unsure about authorization — DO NOT USE THIS TOOL.**

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Documentation](#-documentation)
- [Vulnerability Coverage](#-vulnerability-coverage)
- [Technical Architecture](#-technical-architecture)
- [Docker](#-docker)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Key Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **15+ CVE Checks** | Comprehensive coverage from 2018–2025 with version-aware filtering |
| **Smart Version Detection** | 7+ fallback strategies via API, HTML, JS, and headers |
| **Auto-Search Mode** | Automatically detect Grafana instances from mixed URL lists |
| **Vulnerability DB** | Persistent JSON database with deduplication and risk scoring |
| **Web Dashboard** | Built-in Flask UI for viewing and managing scan results |
| **Parallel Scanning** | Configurable threading for high-speed batch assessments |
| **False Positive Reduction** | Multi-indicator verification with strict content validation |
| **Multi-Format Reports** | JSON, HTML, and CSV with severity visualization |
| **Auth Support** | Bearer token and Basic auth for internal targets |
| **Configuration Analysis** | Security headers, CORS, anonymous access, plugins, and more |

### What's New in v3.0

- 🔍 **Auto-Search (`--auto-search`)** — Detect Grafana from mixed URL lists with 5 detection methods
- 🗄️ **Vulnerability Management (`--db`)** — Persistent database with deduplication, status tracking, and risk scoring
- 🌐 **Web Dashboard (`--serve`)** — Flask web server with dashboard, targets, and vulnerability management
- 🛡️ **15+ CVE Checks** — Extended including CVE-2025-4123, CVE-2024-9264, CVE-2024-8118
- 🎯 **Enhanced Detection** — 5 detection methods with confidence scoring
- 📊 **Risk Scoring** — Automatic calculation (0–100) based on severity and count

---

## ⚡ Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Clone & run
git clone https://github.com/Zierax/Grafana-Final-Scanner.git
cd Grafana-Final-Scanner
python scanner.py -u https://grafana.example.com

# 3. Optional: Web dashboard
pip install flask
python scanner.py --serve --db vulndb.json
```

> **Requirements**: Python 3.9+, `requests` library. Flask is optional (needed for dashboard).

---

## 📖 Usage Examples

```bash
# Single target scan
python scanner.py -u https://grafana.example.com

# Batch scan with HTML report
python scanner.py -f targets.txt -o report

# Auto-detect Grafana from URL list
python scanner.py --auto-search urls.txt -o discovery_report

# Verbose authenticated scan
python scanner.py -u https://grafana.target.com -v --auth-token "glsa_xxx"

# Vulnerability management with database
python scanner.py -f targets.txt --db vulndb.json

# Start web dashboard on custom port
python scanner.py --serve 9090 --host 0.0.0.0 --db vulndb.json

# High-speed parallel batch scan
python scanner.py -f targets.txt --threads 20 -o scan_results
```

### Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Single target URL | — |
| `--file` | `-f` | File with target URLs (one per line) | — |
| `--output` | `-o` | Base name for output reports (JSON, HTML, CSV) | — |
| `--timeout` | `-t` | HTTP timeout in seconds | 10 |
| `--no-ssl-verify` | | Disable SSL verification | False |
| `--verbose` | `-v` | Enable detailed logging | False |
| `--auth-token` | | Bearer token for authenticated scanning | — |
| `--auth-user` | | Username for basic authentication | — |
| `--auth-pass` | | Password for basic authentication | — |
| `--threads` | | Max threads for parallel scanning | 5 |
| `--db` | | Enable vulnerability management with JSON database | — |
| `--serve` | | Start web dashboard (requires Flask) | — |
| `--auto-search` | | Auto-detect Grafana from URL file | — |
| `--host` | | Web server bind address | 127.0.0.1 |
| `--no-banner` | | Suppress ASCII banner | False |
| `--help` | `-h` | Show help message | |

---

## 🖥️ Sample Output

Below is an example of the tool in action against a vulnerable Grafana instance:

```
████████╗ ██████╗  ██████╗ ██╗     
╚══██╔══╝██╔═══██╗██╔═══██╗██║     
   ██║   ██║   ██║██║   ██║██║     
   ██║   ██║   ██║██║   ██║██║     
   ██║   ╚██████╔╝╚██████╔╝███████╗
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
   GRAFANA FINAL SCANNER v3.0
   Security Audit Suite
   Zierax @ 2025

════════════════════════════════════════════════════════════════════════════════
║ TARGET ASSESSMENT
║ https://grafana.example.com
════════════════════════════════════════════════════════════════════════════════

 ℹ [INFO] Phase 1: Connectivity Verification
 ✓ [OK] Target reachable (HTTP 200)

 ℹ [INFO] Phase 2: Version Fingerprinting
 ✓ [OK] Version detected: Grafana v8.2.5

 ℹ [INFO] Phase 3: Vulnerability Scanning

 🔴 [CRITICAL] CVE-2021-43798    Directory Traversal
   └─ Directory traversal CONFIRMED - File read via 'alertlist' plugin
      (5/8 indicators, 1247 bytes)
   └─ Test URL: https://grafana.example.com/public/plugins/alertlist/../../etc/passwd

 🟠 [HIGH] CVE-2023-1410       SSRF via Data Source Proxy
   └─ Data source proxy endpoint accessible: /api/datasources/proxy/
   └─ Test URL: https://grafana.example.com/api/datasources/proxy/

 🟡 [MEDIUM] CVE-2024-1313     Information Disclosure
   └─ Sensitive information disclosed
   └─ Test URL: https://grafana.example.com/api/frontend/settings

 ℹ [INFO] Phase 4: Security Configuration Analysis
 ⚡ [WARN] Missing security headers (4): CSP, HSTS, XFO, X-Content-Type-Options
 🟡 [MEDIUM] Anonymous access ENABLED - unauthenticated viewing possible
 🟡 [MEDIUM] CORS reflects origin header - potential misconfiguration

════════════════════════════════════════════════════════════════════════════════
║ ASSESSMENT SUMMARY
════════════════════════════════════════════════════════════════════════════════

Targets Scanned:      1
Targets Reachable:    1
Vulnerable Targets:   1
Secure Targets:       0

Vulnerability Distribution:
  🔴 CRITICAL       1
  🟠 HIGH           1
  🟡 MEDIUM         1
  ✓ LOW             0
  ✓ INFO            0
```

---

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [**Usage Guide**](docs/usage.md) | Complete command reference, scanning modes, and best practices |
| [**Vulnerability Reference**](docs/vulnerabilities.md) | Detailed CVE descriptions, detection methods, and remediation |
| [**Architecture Guide**](docs/architecture.md) | Project structure, data flow, and design decisions |

Additional resources:
- [**Contributing Guidelines**](CONTRIBUTING.md) — How to contribute code, report bugs, and suggest features
- [**Changelog**](CHANGELOG.md) — Version history and release notes
- [**Security Policy**](SECURITY.md) — Responsible disclosure and vulnerability reporting
- [**Code of Conduct**](CODE_OF_CONDUCT.md) — Community standards

---

## 🛡️ Vulnerability Coverage

| CVE | Severity | Type | Affected Versions |
|:----|:--------:|:-----|:-----------------|
| **CVE-2025-4123** | 🔴 **CRITICAL** | Path Traversal & Open Redirect XSS | < 12.0.0+security-01 |
| **CVE-2024-9264** | 🔴 **CRITICAL** | DuckDB SQL Injection (RCE) | 11.0.0–11.2.1 |
| **CVE-2024-8118** | 🔴 **CRITICAL** | OAuth Authentication Bypass | 11.0.0–11.2.1 |
| **CVE-2021-43798** | 🔴 **CRITICAL** | Directory Traversal (File Read) | 8.0.0–8.3.0 |
| **CVE-2023-50164** | 🟠 **HIGH** | Plugin Path Traversal | < 9.2.10, 9.3.x < 9.3.6 |
| **CVE-2023-1410** | 🟠 **HIGH** | SSRF via Data Source Proxy | 8.0.0–9.2.16, 9.3.0–9.3.4 |
| **CVE-2023-2183** | 🟠 **HIGH** | Authentication Bypass | 8.x < 8.5.21, 9.x < 9.4.13 |
| **CVE-2018-15727** | 🟠 **HIGH** | Auth Bypass (Cookie Forging) | ≤ 5.2.2 |
| **CVE-2021-27358** | 🟠 **HIGH** | DoS via Snapshots API | 6.7.3–7.4.1 |
| **CVE-2021-39226** | 🟡 **MEDIUM** | Snapshot Enumeration | 8.0.0–8.3.0 |
| **CVE-2024-1313** | 🟡 **MEDIUM** | Information Disclosure | Multiple version ranges |
| **CVE-2020-11110** | 🟡 **MEDIUM** | Stored XSS | < 6.7.0 |
| **CVE-2021-41174** | 🟡 **MEDIUM** | AngularJS XSS | 8.0.0–8.3.0 |
| **CVE-2022-32275/76** | 🟡 **MEDIUM** | Version-specific Issues | 8.4.3 only |

### Configuration Checks

| Check | Severity | Description |
|-------|:--------:|-------------|
| Anonymous Access | 🟡 MEDIUM | Unauthenticated viewing enabled |
| Metrics Exposure | 🔵 LOW | Prometheus endpoint public |
| Plugin Analysis | 🟡 MEDIUM | Unsigned plugins detected |
| Security Headers | 🔵 LOW | CSP, HSTS, XFO audit |
| CORS Misconfiguration | 🟡 MEDIUM | Wildcard/reflective CORS |
| Self-Signup | 🟡 MEDIUM | Unauthorized registration |
| Server Info Disclosure | 🔵 LOW | Build info leaked |
| API Key Exposure | 🟡 MEDIUM | Sensitive data in responses |

---

## 🔧 Technical Architecture

### Scanning Process

```
User Input (URL / File / Auto-Search)
        │
        ▼
┌──────────────────┐
│  Connectivity    │ ─── TCP/HTTP handshake & SSL validation
│  Verification    │
└──────┬───────────┘
        │
        ▼
┌──────────────────┐
│  Version         │ ─── 7+ endpoint probing (API, HTML, JS, headers)
│  Fingerprinting  │
└──────┬───────────┘
        │
        ▼
┌──────────────────┐
│  Vulnerability   │ ─── 15+ CVE checks with version-aware filtering
│  Assessment      │ ─── Parallel thread pool execution
└──────┬───────────┘
        │
        ▼
┌──────────────────┐
│  Configuration   │ ─── Security headers, CORS, auth, plugins
│  Analysis        │
└──────┬───────────┘
        │
        ▼
┌──────────────────┐
│  Results         │ ─── JSON/HTML/CSV reports + database persistence
│  Compilation     │
└──────────────────┘
```

### False Positive Reduction

- **Version-Based Filtering**: Skip inapplicable CVE checks (~40% reduction)
- **Content Validation**: Require specific indicators, not just HTTP status (~60% reduction)
- **Multi-Vector Testing**: Test multiple variants for confirmation
- **Response Validation**: Content length, JSON structure, indicator matching
- **Rate Limit Detection**: Prevents false negatives from rate-limited responses

For full architecture details, see the [Architecture Guide](docs/architecture.md).

---

## 🐳 Docker

```bash
# Build
docker build -t grafana-scanner .

# Single scan
docker run --rm grafana-scanner -u https://grafana.example.com

# With database persistence
docker run --rm -v $(pwd)/vulndb.json:/app/vulndb.json \
  grafana-scanner -u https://grafana.example.com --db vulndb.json

# Web dashboard
docker run --rm -p 8080:8080 \
  -v $(pwd)/vulndb.json:/app/vulndb.json \
  grafana-scanner --serve 8080 --host 0.0.0.0 --db vulndb.json
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

We especially appreciate contributions in:
- New CVE detection modules
- False positive / false negative fixes
- Documentation and examples
- Test coverage improvements
- Web dashboard UI enhancements

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by [Ziad](https://github.com/Zierax)**

[![GitHub contributors](https://contrib.rocks/image?repo=Zierax/Grafana-Final-Scanner)](https://github.com/Zierax/Grafana-Final-Scanner/graphs/contributors)

*Thank you to all contributors who help make this project better.*

</div>
