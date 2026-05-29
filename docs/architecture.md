# Architecture Guide

## Project Structure

```
Grafana-Final-Scanner/
├── scanner.py               # Main scanner engine (all-in-one module)
├── requirements.txt         # Production dependencies
├── pyproject.toml           # Modern Python packaging configuration
├── Makefile                 # Development task automation
├── Dockerfile               # Container build definition
├── CHANGELOG.md             # Version history
├── CONTRIBUTING.md          # Contribution guidelines
├── SECURITY.md              # Security policy
├── CODE_OF_CONDUCT.md       # Community standards
├── LICENSE                  # MIT License
├── README.md                # Project documentation
├── .gitignore               # Git exclusion rules
├── .github/
│   └── workflows/
│       └── python-package.yml  # CI/CD pipeline
├── docs/
│   ├── usage.md             # Usage guide
│   ├── vulnerabilities.md   # Vulnerability reference
│   └── architecture.md      # This file
└── tests/
    ├── test_scanner.py      # Core scanner unit tests
    ├── test_edge_cases.py   # Edge case tests
    └── test_vulnerability_db.py  # Vulnerability DB tests
```

## Module Architecture

The project is currently a single-file module (`scanner.py`) containing all functionality. This monolithic design was chosen for simplicity and ease of distribution. The module is organized into the following logical sections:

### 1. Utility Layer

```
┌─────────────────────────────────────────────┐
│              Utility Layer                   │
├─────────────────────────────────────────────┤
│  Colors          - ANSI terminal formatting │
│  _positive_int   - Argument type validator  │
│  FLASK_AVAILABLE - Optional dependency flag │
└─────────────────────────────────────────────┘
```

### 2. Vulnerability Database Manager

```
┌─────────────────────────────────────────────┐
│           VulnerabilityDB Class              │
├─────────────────────────────────────────────┤
│  _load()              - Load from JSON      │
│  _save()              - Persist to JSON     │
│  add_target()         - Register target     │
│  add_vulnerability()  - Record finding      │
│  add_scan_history()   - Log scan execution  │
│  get_target()         - Query by URL        │
│  get_all_targets()    - List all targets    │
│  get_open_vulnerabilities() - Active vulns  │
│  update_vuln_status() - Change status       │
│  get_statistics()     - Aggregate metrics   │
│  _target_id()         - Stable URL hash     │
│  _generate_vuln_id()  - Unique ID           │
│  _get_remediation()   - Remediation advice  │
│  _calculate_risk_score() - 0-100 scoring    │
└─────────────────────────────────────────────┘
```

### 3. Scanner Engine

```
┌─────────────────────────────────────────────┐
│         GrafanaFinalScanner Class            │
├─────────────────────────────────────────────┤
│  Initialization                              │
│  ├── Session & auth configuration           │
│  ├── Thread pool & rate limiting            │
│  └── Vulnerability database                 │
│                                              │
│  Detection                                   │
│  ├── is_grafana_instance() - 5 methods      │
│  └── auto_search_from_file() - Parallel      │
│                                              │
│  Version Detection                           │
│  ├── detect_grafana_version() - 7 endpoints │
│  ├── compare_versions() - Semantic compare   │
│  ├── version_in_range() - Range checking    │
│  └── is_version_vulnerable() - CVE matching │
│                                              │
│  CVE Checks (15+)                            │
│  ├── check_cve_2021_43798()                  │
│  ├── check_cve_2025_4123()                   │
│  ├── check_cve_2024_9264()                   │
│  ├── check_cve_2018_15727()                  │
│  ├── check_cve_2021_39226()                  │
│  ├── check_cve_2023_50164()                  │
│  ├── check_cve_2023_1410()                   │
│  ├── check_cve_2023_2183()                   │
│  ├── check_cve_2024_1313()                   │
│  ├── check_cve_2024_8118()                   │
│  └── check_additional_cves() - 5 more       │
│                                              │
│  Configuration Analysis                      │
│  ├── check_security_headers()                │
│  ├── check_cors_misconfiguration()           │
│  └── check_security_config() - Composite     │
│                                              │
│  Scan Execution                              │
│  ├── scan_target() - Full assessment        │
│  ├── scan_from_file() - Batch scanning      │
│  ├── generate_report() - Summary output     │
│  ├── _save_json_report()                    │
│  ├── _save_html_report()                    │
│  └── _save_csv_report()                     │
└─────────────────────────────────────────────┘
```

### 4. Web Dashboard

```
┌─────────────────────────────────────────────┐
│          Flask Web Application               │
├─────────────────────────────────────────────┤
│  create_web_server() - App factory           │
│                                              │
│  Routes:                                     │
│  ├── /    - Dashboard overview              │
│  ├── /targets - Target management           │
│  ├── /vulnerabilities - Vuln management     │
│  ├── /api/stats - JSON statistics           │
│  ├── /api/targets - JSON targets            │
│  └── /api/vulnerabilities - JSON vulns     │
│                                              │
│  Features:                                   │
│  ├── Severity filtering                     │
│  ├── Status management (fixed/FP/accept)    │
│  └── Responsive dark theme                  │
└─────────────────────────────────────────────┘
```

### 5. CLI Entry Point

```
┌─────────────────────────────────────────────┐
│              Entry Point                     │
├─────────────────────────────────────────────┤
│  print_banner() - ASCII art banner          │
│  main() - CLI argument parser               │
│  if __name__ == '__main__' - Entry          │
└─────────────────────────────────────────────┘
```

## Data Flow

### Scan Execution Flow

```
User Input (URL / File / Auto-Search)
        │
        ▼
┌──────────────────┐
│  Connectivity    │  ─── TCP/HTTP handshake
│  Verification    │  ─── SSL validation
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  Version         │  ─── 7+ endpoint probing
│  Fingerprinting  │  ─── Multi-source validation
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  Vulnerability   │  ─── 15+ CVE checks
│  Assessment      │  ─── Version-aware filtering
└──────┬───────────┘  ─── Parallel thread pool
       │
       ▼
┌──────────────────┐
│  Configuration   │  ─── Security headers
│  Analysis        │  ─── CORS, auth, plugins
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  Results         │  ─── JSON/HTML/CSV reports
│  Compilation     │  ─── Database persistence
└──────────────────┘  ─── Statistical summary
```

## Key Design Decisions

### 1. Single-File Architecture

**Decision**: Despite the large file size (~170KB, ~3600 lines), the project remains a single Python file.

**Rationale**:
- Simplifies distribution — users only need one file
- Easy to copy, share, and run without package installation
- Reduces complexity for container deployments
- All dependencies are standard Python libraries

**Trade-off**: Reduced modularity and testability. If the project grows significantly, consider splitting into:
- `scanner/__init__.py`
- `scanner/vulndb.py`
- `scanner/checks.py`
- `scanner/config.py`
- `scanner/report.py`
- `scanner/server.py`
- `scanner/cli.py`

### 2. JSON File Database

**Decision**: Use JSON files for persistence instead of SQLite.

**Rationale**:
- Zero dependencies — works with Python's standard library
- Human-readable — users can inspect and edit the database
- Simple backup and migration — just copy the JSON file
- Adequate for typical use (hundreds of targets, thousands of vulns)

**Trade-off**: No query language, no concurrent write safety beyond thread locks, slower than SQLite for large datasets.

### 3. Optional Flask Dependency

**Decision**: Flask is imported as an optional dependency.

**Rationale**:
- Many users only need CLI scanning
- Reduces installation footprint for headless environments
- Clear error message if Flask is missing and `--serve` is used

### 4. Thread Safety

**Decision**: Use `threading.RLock()` for database operations and `threading.Lock()` for printing.

**Rationale**:
- RLock allows re-entrant locking (same thread can acquire multiple times)
- Print lock prevents interleaved output from parallel checks
- Simple, Pythonic approach without external dependencies

## Testing Strategy

The test suite covers:
- **Unit Tests**: Version comparison, range checking, CVE-specific vulnerability detection
- **Edge Cases**: Pre-release versions, empty strings, boundary conditions
- **Mock Tests**: HTTP responses, database operations, detection scenarios
- **Integration Tests**: File I/O, report generation, concurrent access

### Test Files

| File | Focus |
|------|-------|
| `tests/test_scanner.py` | Core scanner, version comparison, auth, reports |
| `tests/test_edge_cases.py` | Version boundary conditions, CVE edge cases, CORS |
| `tests/test_vulnerability_db.py` | Database CRUD, dedup, persistence, detection, web server |

## Security Considerations

1. **SSL Verification**: Disabled by default for flexibility with self-signed certs
2. **Rate Limiting**: Automatic detection prevents scanner abuse
3. **Database Security**: JSON file stores sensitive information — protect with filesystem permissions
4. **Docker**: Runs as non-root user for reduced privilege
5. **Authentication**: Token and basic auth supported for internal targets
6. **Network Exposure**: Web dashboard binds to localhost by default
