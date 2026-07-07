# Changelog

All notable changes to the Grafana Final Scanner project will be documented in this file.

## [3.1.0] - 2025-07-07

This release focuses on security hardening and reliability fixes identified in a
full forensic code audit. It is recommended for all users, especially those who
expose the web dashboard or scan untrusted networks.

### Security
- **Web dashboard authentication (C-001):** Added `--dashboard-token` bearer token
  requirement. All dashboard routes and the statistics/API endpoints now return 401
  without a valid token. A warning is printed when the dashboard is bound to
  `0.0.0.0` without a token.
- **CSRF protection (C-001):** State-changing requests now require a matching
  `X-CSRF-Token` header (double-submit cookie, `SameSite=Strict`).
- **TLS verification on by default (C-003):** `verify_ssl` now defaults to `True`.
  Passing `--no-ssl-verify` prints an explicit warning that credentials may be
  exposed to interception. TLS warnings are no longer suppressed globally.
- **XSS-safe reports (C-007):** Added `sanitize_href`/`sanitize_text` helpers. HTML
  and web reports no longer embed `javascript:`, `data:`, or `vbscript:` URIs from
  scan responses.
- **Per-request rate limiting (C-005):** Removed the shared global "rate limited"
  flag that previously aborted entire batch scans. Rate limiting is now handled per
  request with backoff and retry, so one throttled host cannot skip unrelated
  targets.

### Fixed
- **Atomic database writes (C-002):** The JSON database is now written to a temp
  file, fsync'd, then atomically renamed. The previous good copy is kept as a
  `.bak`. Corrupted databases are moved aside (`.corrupt-<timestamp>`) instead of
  being silently discarded.
- **Thread-safe request layer:** Rate-limit state is no longer shared mutable
  instance state across threads.
- **Error handling:** Removed several bare `except:` blocks in the request and
  rate-limit paths in favor of specific exception handling.

### Changed
- Bumped default database schema version to `3.1`.
- Removed marketing/emoji fluff from the banner and console output.
- `requirements.txt` notes Flask as an optional dependency for `--serve`.

## [3.0.0] - 2025-05-29

### Added
- **New CVEs (5 additional):**
  - CVE-2025-4123 - "Grafana Ghost" Path Traversal & Open Redirect XSS (CRITICAL)
  - CVE-2024-9264 - DuckDB SQL Injection (CRITICAL)
  - CVE-2024-8118 - OAuth Authentication Bypass (CRITICAL)
  - CVE-2024-1313 - Information Disclosure via API (MEDIUM)
  - CVE-2023-2183 - Authentication Bypass via API (HIGH)

- **Auto-Search Feature (`--auto-search`):**
  - Multi-method Grafana instance detection (API, HTML, headers, endpoint probing)
  - Confidence scoring (0-100%) with 30% detection threshold
  - Parallel probing of URLs from mixed lists
  - Version detection during discovery phase

- **Vulnerability Management System (`--db`):**
  - Persistent JSON database with target tracking
  - Vulnerability deduplication by CVE + target URL
  - Status tracking (open, confirmed, false_positive, fixed, accepted)
  - Automatic risk scoring (0-100) per target
  - Scan history with duration and findings tracking (last 1000 records)
  - Thread-safe concurrent writes with RLock

- **Web Dashboard (`--serve`):**
  - Built-in Flask web server for viewing scan results
  - Dashboard with statistics overview
  - Target management with risk scores and version history
  - Vulnerability listing with severity badges and status filters
  - One-click vulnerability status updates
  - Responsive design with dark theme

- **Enhanced Grafana Detection:**
  - 5 detection methods with multi-indicator validation
  - API health check, HTML analysis, frontend settings, endpoint probing, header analysis
  - Auto-detection from mixed URL lists

- **Project Infrastructure:**
  - `pyproject.toml` for modern Python packaging (PEP 621)
  - `Makefile` for common development tasks (test, lint, build, docker)
  - `SECURITY.md` with responsible disclosure policy
  - `CODE_OF_CONDUCT.md` (Contributor Covenant 2.0)
  - `docs/` directory with comprehensive documentation
  - Improved `.gitignore` with project-specific exclusions
  - Pinned `requirements.txt` with version constraints

### Changed
- **Version detection expanded** from 4 to 7+ endpoints
- **Plugin coverage increased** for CVE-2021-43798 (5 → 35+ plugins)
- **Snapshot enumeration range extended** for CVE-2021-39226 (5 → 50 IDs)
- **Version comparison improved** with proper range-based checking
- **False positive reduction enhanced** with stricter content validation
- **CVE-2025-4123 detection expanded** with 7 test vectors
- **README.md extensively rewritten** with improved structure, badges, and navigation
- **CI/CD pipeline updated** with build summary job and improved caching
- **Renamed** `requirments.txt` → `requirements.txt` (fixed typo)

### Fixed
- **False Positive Reduction:**
  - CVE-2021-43798: Requires 3+ indicators AND content > 100 bytes
  - CVE-2018-15727: Uses actual API endpoints instead of HTML text parsing
  - CVE-2021-39226: Better JSON snapshot validation
  - All CVEs: Proper HTTP status code differentiation
  - Version-aware filtering prevents irrelevant CVE checks

- **Error Handling Improvements:**
  - Safe request wrapper with retry logic (2 retries)
  - Graceful handling of connection errors, timeouts, SSL errors
  - Rate limiting detection with automatic backoff
  - Thread-safe logging with print lock

### Security
- Rate limiting detection to prevent scanner from being blocked (429, X-RateLimit-Remaining, Retry-After)
- Connection retry with backoff
- Safe request wrapper prevents crashes on network failures
- Non-root user in Docker container
- SSL verification configurable (default: enabled)

## [2.0.0] - 2025-05-15

### Added
- **New CVE Checks (3 additional):**
  - CVE-2023-50164 - Plugin Path Traversal (HIGH)
  - CVE-2023-1410 - SSRF via Data Source Proxy (HIGH)
  - CVE-2023-2183 - Authentication Bypass via API (HIGH)
  - CVE-2024-1313 - Information Disclosure via API (MEDIUM)
  - CVE-2024-8118 - OAuth Authentication Bypass (CRITICAL)

- **Authentication Support:**
  - `--auth-token` flag for Bearer token authentication
  - `--auth-user` / `--auth-pass` flags for Basic authentication
  - Allows scanning of authenticated-only endpoints

- **Multi-Format Reporting:**
  - HTML report generation with modern responsive design
  - CSV report export for spreadsheet analysis
  - All formats generated automatically with single `-o` flag
  - Severity color-coded badges in HTML reports

- **Parallel Scanning:**
  - `--threads` flag for configurable concurrency (default: 5)
  - Thread pool executor for parallel CVE checks
  - Faster batch scanning with concurrent target processing

- **Enhanced Configuration Analysis:**
  - HTTP security headers audit (CSP, HSTS, XFO, etc.)
  - CORS misconfiguration detection
  - User self-signup availability check
  - API key exposure detection in settings

- **Rate Limiting Detection:**
  - Automatic detection of 429 responses
  - Rate limit header monitoring
  - Smart retry with backoff

### Changed
- Expanded version detection from 4 to 7+ endpoints
- Wider plugin coverage for CVE-2021-43798 (5 → 35+ plugins)
- More snapshot IDs for CVE-2021-39226 (5 → 50 IDs)
- Improved version comparison with proper range-based checking
- Better false positive reduction with stricter content validation
- Enhanced CVE-2025-4123 with 7 test vectors instead of 2
- Renamed `requirments.txt` → `requirements.txt` (fixed typo)

### Fixed
- False positive reduction across multiple CVEs
- Error handling with safe request wrapper and retry logic

### Security
- Rate limiting detection to prevent scanner from being blocked
- Connection retry with exponential backoff

## [1.0.0] - 2025-01-15

### Added
- Initial release with 10 CVE vulnerability checks
- Multi-source version detection (4 endpoints)
- Configuration security analysis
- JSON report generation
- Color-coded severity indicators
- Support for single and batch scanning
