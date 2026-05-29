# Usage Guide

## Overview

Grafana Final Scanner is a professional-grade security assessment tool for Grafana deployments. This guide covers all available commands, options, and best practices.

## Command-Line Interface

### Basic Commands

```bash
# Scan a single target
python scanner.py --url https://grafana.example.com

# Scan multiple targets from a file
python scanner.py --file targets.txt --output scan_results

# Auto-detect Grafana instances from a URL list
python scanner.py --auto-search urls.txt --output discovery_report

# Start the web dashboard
python scanner.py --serve --db vulndb.json
```

### Argument Reference

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Single target URL to scan | None |
| `--file` | `-f` | File containing target URLs (one per line) | None |
| `--output` | `-o` | Base name for output reports (JSON, HTML, CSV) | None |
| `--timeout` | `-t` | HTTP request timeout in seconds | `10` |
| `--no-ssl-verify` | | Disable SSL certificate verification | `False` |
| `--verbose` | `-v` | Enable detailed logging output | `False` |
| `--auth-token` | | Bearer token for authenticated endpoints | None |
| `--auth-user` | | Username for basic authentication | None |
| `--auth-pass` | | Password for basic authentication | None |
| `--threads` | | Maximum threads for parallel scanning | `5` |
| `--db` | | Path to vulnerability database JSON file | None |
| `--serve` | | Start web dashboard (requires Flask) | None |
| `--auto-search` | | Auto-detect Grafana from URL file | None |
| `--host` | | Host to bind web server | `127.0.0.1` |
| `--no-banner` | | Suppress ASCII art banner | `False` |
| `--help` | `-h` | Show help message and exit | |

## Scanning Modes

### Single Target Scan

```bash
python scanner.py -u https://grafana.example.com
```

Scans a single Grafana instance with all 15+ CVE checks and configuration analysis. Results are printed to the terminal with color-coded severity indicators.

### Batch Scan from File

```bash
python scanner.py -f targets.txt -o report
```

Scans multiple targets sequentially from a file. Create `targets.txt` with one URL per line:

```
https://grafana-1.example.com
https://grafana-2.example.com
https://grafana.internal.local
```

Comments (lines starting with `#` or `//`) are ignored.

### Auto-Search Mode

```bash
python scanner.py --auto-search urls.txt -o discovery_report
```

Automatically detects Grafana instances from a mixed URL list. The tool probes each URL using 5 detection methods:

1. **API Health Check** — Checks `/api/health` for Grafana-specific JSON
2. **HTML Analysis** — Looks for Grafana indicators in page content
3. **Frontend Settings** — Probes `/api/frontend/settings`
4. **Endpoint Probing** — Tests multiple Grafana API endpoints
5. **Header Analysis** — Checks response headers for Grafana signatures

Only URLs with a confidence score ≥ 30% are classified as Grafana instances.

### Authenticated Scanning

```bash
# Bearer token authentication
python scanner.py -u https://grafana.internal --auth-token "glsa_xxx"

# Basic authentication
python scanner.py -u https://grafana.internal --auth-user admin --auth-pass password

# Both methods (for different endpoints)
python scanner.py -u https://grafana.internal --auth-token "glsa_xxx" --auth-user admin --auth-pass password
```

### High-Speed Parallel Scanning

```bash
# Scan 20 targets concurrently
python scanner.py -f targets.txt --threads 20 -o parallel_scan
```

Adjust thread count based on:
- Network bandwidth and latency
- Target server capacity
- Rate limiting thresholds

## Vulnerability Management

### Using the Database

```bash
# Create new database and scan
python scanner.py -u https://grafana.example.com --db vulndb.json

# Add to existing database
python scanner.py -u https://grafana2.example.com --db vulndb.json

# View database via web dashboard
python scanner.py --serve --db vulndb.json
```

### Database Features

- **Target Tracking**: URL, version, first seen, last scanned, scan count
- **Vulnerability Records**: CVE ID, severity, status, remediation advice
- **Risk Scoring**: Weighted calculation (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3), capped at 100
- **Deduplication**: Same CVE + same target = update, not duplicate
- **Scan History**: Timestamp, duration, findings per scan (last 1000 records)
- **Thread Safety**: Concurrent writes protected with RLock

### Vulnerability Statuses

| Status | Description |
|--------|-------------|
| `open` | Newly discovered, awaiting review |
| `confirmed` | Verified as a genuine vulnerability |
| `false_positive` | Determined to be incorrect detection |
| `fixed` | Remediated and no longer present |
| `accepted` | Risk accepted (e.g., compensating controls in place) |

## Web Dashboard

### Starting the Dashboard

```bash
# Default port 8080
python scanner.py --serve --db vulndb.json

# Custom port and host
python scanner.py --serve 9090 --host 0.0.0.0 --db vulndb.json
```

> **Security Note**: Using `--host 0.0.0.0` exposes the dashboard to all network interfaces. In production, use a reverse proxy with authentication.

### Dashboard Pages

1. **Dashboard** (`/`): Statistics overview with target count, vulnerability distribution, risk summary
2. **Targets** (`/targets`): List of tracked targets with version, scan count, and risk scores
3. **Vulnerabilities** (`/vulnerabilities`): Filterable table of all vulnerabilities with status management

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Database statistics |
| `/api/targets` | GET | All tracked targets |
| `/api/vulnerabilities` | GET | All vulnerabilities |
| `/api/vulnerabilities/<id>/status` | POST | Update vulnerability status |

## Report Formats

### JSON Report

```bash
python scanner.py -u https://grafana.example.com -o scan_results
# Creates: scan_results.json
```

Machine-readable format ideal for:
- Integration with other tools
- Automated processing
- Historical data analysis

### HTML Report

```bash
python scanner.py -u https://grafana.example.com -o scan_results
# Creates: scan_results.html
```

Professional HTML report with:
- Responsive design with dark theme
- Severity color-coded badges
- Summary metrics dashboard
- Detailed findings table

### CSV Report

```bash
python scanner.py -u https://grafana.example.com -o scan_results
# Creates: scan_results.csv
```

Spreadsheet-compatible format with columns:
- Target URL, Version, CVE ID, Severity
- Description, Message, Test URL, Timestamp

## Configuration Analysis

The scanner performs comprehensive security configuration analysis:

### Security Headers Audit

Checks for missing security headers:
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`

### CORS Misconfiguration

Detects:
- Wildcard `Access-Control-Allow-Origin: *`
- Reflected origin header
- Credentials-enabled endpoints

### Additional Checks

- Anonymous access enabled?
- Prometheus metrics exposed?
- Unsigned plugins installed?
- User self-signup enabled?
- Build information leaked?
- API keys in settings?

## Docker Usage

### Building

```bash
docker build -t grafana-scanner .
```

### Running

```bash
# Single scan
docker run --rm grafana-scanner -u https://grafana.example.com

# With database persistence
docker run --rm -v $(pwd)/vulndb.json:/app/vulndb.json \
  grafana-scanner -u https://grafana.example.com --db vulndb.json

# Web dashboard
docker run --rm -p 8080:8080 \
  -v $(pwd)/vulndb.json:/app/vulndb.json \
  grafana-scanner --serve 8080 --host 0.0.0.0 --db vulndb.json

# Batch scan
docker run --rm \
  -v $(pwd)/targets.txt:/app/targets.txt \
  -v $(pwd)/results:/app/reports \
  grafana-scanner -f targets.txt -o /app/reports/scan
```

## Environment Variables

While the scanner uses command-line arguments, consider these best practices:

```bash
# Store tokens in environment variables, not command history
export GRAFANA_TOKEN="glsa_xxx"
python scanner.py -u https://grafana.example.com --auth-token "$GRAFANA_TOKEN"

# Use a password manager or vault for credentials
# Never hardcode credentials in scripts
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully |
| `1` | Error (file not found, connection failed, etc.) |

## Performance Considerations

### Thread Count Recommendations

| Scenario | Threads | Reason |
|----------|---------|--------|
| Single target | 1-5 | Minimal overhead |
| Local network targets | 10-20 | Low latency |
| Internet targets | 5-10 | Avoid rate limiting |
| Large batch (100+) | 20-50 | Parallel detection |

### Rate Limiting

The scanner automatically detects rate limiting through:
- HTTP 429 status codes
- `X-RateLimit-Remaining: 0` headers
- `Retry-After` headers
- Rate limit messages in response bodies

When rate limited, the scanner pauses and retries once with backoff.
