# Vulnerability Reference

## Overview

The Grafana Final Scanner detects 15+ CVEs across Grafana versions from 2018 to 2025. Each check includes version-aware filtering to reduce false positives.

## Severity Classification

| Severity | Score Range | Color | Description |
|----------|-------------|-------|-------------|
| **CRITICAL** | 9.0-10.0 | [CRIT] Red | Remote code execution, authentication bypass |
| **HIGH** | 7.0-8.9 | [HIGH] Orange | Data access, server-side attacks |
| **MEDIUM** | 4.0-6.9 | [MED] Yellow | Information disclosure, enumeration |
| **LOW** | 0.1-3.9 | [LOW] Blue | Configuration weaknesses, missing headers |

## Critical Vulnerabilities

### CVE-2025-4123 — Grafana Ghost

| Field | Details |
|-------|---------|
| **CVSS** | 8.2 |
| **Type** | Path Traversal & Open Redirect XSS |
| **Affected** | All versions < 12.0.0+security-01 |
| **Detection** | 7 test vectors including open redirect, path traversal, info disclosure, snapshot access |

**Vector**: Combination of path traversal and open redirect allowing XSS in Grafana instances.

**Detection Methods**:
1. Open redirect via `/redirect` endpoint
2. Protocol-relative redirect bypass
3. Path traversal through plugin directory
4. Build output path traversal
5. OAuth configuration disclosure via `/api/frontend/settings`
6. Redirect parameter injection in `/login`
7. Snapshot API access with delete keys

**Remediation**: Upgrade to Grafana 12.0.0+ immediately.

### CVE-2024-9264 — DuckDB SQL Injection

| Field | Details |
|-------|---------|
| **CVSS** | 9.0+ |
| **Type** | SQL Injection (Potential RCE) |
| **Affected** | 11.0.0-11.0.5, 11.1.0-11.1.6, 11.2.0-11.2.1 |
| **Detection** | Probes SQL Expressions endpoint with test payload |

**Impact**: Authenticated users with data source editor permissions can execute arbitrary SQL via DuckDB expressions, potentially leading to remote code execution if DuckDB's PostgreSQL SQL parser is enabled.

**Remediation**: Upgrade to Grafana 11.0.6+, 11.1.7+, or 11.2.2+.

### CVE-2024-8118 — OAuth Authentication Bypass

| Field | Details |
|-------|---------|
| **CVSS** | 9.0+ |
| **Type** | Authentication Bypass |
| **Affected** | 11.0.0-11.0.5, 11.1.0-11.1.7, 11.2.0-11.2.1 |
| **Detection** | Probes OAuth 2.0 endpoints for accessibility |

**Impact**: Attackers can bypass authentication by exploiting flaws in the OAuth 2.0 login flow, potentially gaining unauthorized access to Grafana instances configured with OAuth providers.

**Remediation**: Upgrade to Grafana 11.0.6+, 11.1.8+, or 11.2.2+.

### CVE-2021-43798 — Directory Traversal

| Field | Details |
|-------|---------|
| **CVSS** | 7.5 |
| **Type** | Directory Traversal (Arbitrary File Read) |
| **Affected** | 8.0.0-8.3.0 |
| **Detection** | 35+ plugin paths × 3 traversal patterns, 8 content indicators |

**Impact**: Unauthenticated attackers can read arbitrary files on the Grafana server through a path traversal vulnerability in the plugin URL handling.

**Detection Logic**:
- Tests 35+ plugins with 3 traversal patterns
- Requires 3+ of 8 content indicators (root:, :x:, /bin/, daemon:)
- Minimum content length of 100 bytes to confirm

**Remediation**: Upgrade to Grafana 8.3.1+ immediately.

## High Severity

### CVE-2023-50164 — Plugin Path Traversal

| Field | Details |
|-------|---------|
| **CVSS** | 8.0 |
| **Type** | Path Traversal via Plugin Resources |
| **Affected** | < 9.2.10, 9.3.0-9.3.5, 9.4.0 |
| **Detection** | 5 plugins × 4 traversal encoding patterns |

**Detection Methods**:
- Standard `../` traversal
- Double URL encoding `%252f`
- Single URL encoding `%2f`
- Overlapping path `....//`

**Remediation**: Upgrade to Grafana 9.2.10+, 9.3.6+, or 9.4.1+.

### CVE-2023-1410 — SSRF via Data Source Proxy

| Field | Details |
|-------|---------|
| **CVSS** | 8.8 |
| **Type** | Server-Side Request Forgery |
| **Affected** | >= 8.0.0, < 9.2.17 or 9.3.0-9.3.4 |
| **Detection** | Probes data source proxy endpoints |

**Impact**: Authenticated users can perform SSRF attacks via the data source proxy endpoint, potentially accessing internal services.

**Remediation**: Upgrade to Grafana 9.2.17+, 9.3.5+, or apply WAF rules.

### CVE-2023-2183 — Authentication Bypass via API

| Field | Details |
|-------|---------|
| **CVSS** | 8.1 |
| **Type** | Authentication Bypass |
| **Affected** | 8.x < 8.5.21, 9.x < 9.4.13 |
| **Detection** | Probes 8 admin/org API endpoints |

**Detection Endpoints**:
- `/api/admin/users`, `/api/admin/ldap`, `/api/admin/settings`
- `/api/admin/stats`, `/api/org/users`, `/api/org/preferences`
- `/api/teams/secrets`, `/api/dashboards/permissions`

**Remediation**: Upgrade to Grafana 8.5.21+ or 9.4.13+.

### CVE-2018-15727 — Authentication Bypass (Cookie Forging)

| Field | Details |
|-------|---------|
| **CVSS** | 8.1 |
| **Type** | Authentication Bypass via Cookie Forging |
| **Affected** | <= 5.2.2 |
| **Detection** | Probes LDAP/OAuth/SAML configuration endpoints |

**Impact**: Attackers can forge authentication cookies due to weak cryptographic signing, gaining admin access without credentials.

**Remediation**: Upgrade to Grafana 5.2.3+ or migrate to a newer version.

### CVE-2021-27358 — DoS via Snapshots

| Field | Details |
|-------|---------|
| **CVSS** | 7.5 |
| **Type** | Denial of Service |
| **Affected** | 6.7.3-7.4.1 |
| **Detection** | Tests unauthenticated POST to snapshots API |

**Impact**: Unauthenticated attackers can create excessive snapshot resources, causing denial of service through resource exhaustion.

**Remediation**: Upgrade to Grafana 7.4.2+.

## Medium Severity

### CVE-2024-1313 — Information Disclosure

| Field | Details |
|-------|---------|
| **CVSS** | 5.5 |
| **Type** | Information Disclosure via API |
| **Affected** | Multiple version ranges |
| **Detection** | Recursive key search across 6 API endpoints |

**Detection Method**: Recursively searches for sensitive keys (secret, password, token, credential, private_key, api_key) in API responses.

**Monitored Endpoints**:
- `/api/frontend/settings`, `/api/health`, `/api/plugins`
- `/api/datasources`, `/api/org/preferences`, `/api/admin/settings`

**Remediation**: Upgrade to latest patched version for your major release.

### CVE-2021-39226 — Snapshot Enumeration

| Field | Details |
|-------|---------|
| **CVSS** | 6.5 |
| **Type** | Snapshot Enumeration |
| **Affected** | 8.0.0-8.3.0 |
| **Detection** | Tests 50 snapshot IDs across 4 endpoint patterns |

**Impact**: Attackers can enumerate snapshot IDs to discover sensitive dashboard data that was shared via snapshots.

**Remediation**: Upgrade to Grafana 8.3.1+.

### CVE-2020-11110 — Stored XSS

| Field | Details |
|-------|---------|
| **Type** | Stored Cross-Site Scripting |
| **Affected** | < 6.7.0 |
| **Detection** | Tests snapshots API accessibility |

**Remediation**: Upgrade to Grafana 6.7.0+.

### CVE-2021-41174 — AngularJS XSS

| Field | Details |
|-------|---------|
| **Type** | AngularJS Expression Injection |
| **Affected** | 8.0.0-8.3.0 |
| **Detection** | Injects AngularJS expression via snapshot URL |

**Remediation**: Upgrade to Grafana 8.3.1+.

### CVE-2022-32275/32276 — v8.4.3 Specific Issues

| Field | Details |
|-------|---------|
| **Type** | Version-Specific Vulnerabilities |
| **Affected** | Exactly 8.4.3 |
| **Detection** | Version string match (requires manual validation) |

**Note**: These CVEs are specific to version 8.4.3 only. The scanner flags the version but recommends manual validation.

**Remediation**: Upgrade from version 8.4.3 to a patched version.

## Configuration Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Anonymous Access | MEDIUM | Unauthenticated viewing enabled |
| Metrics Exposure | LOW | Prometheus metrics publicly accessible |
| Unsigned Plugins | MEDIUM | Plugins without valid signatures |
| Missing Security Headers | LOW | CSP, HSTS, XFO, etc. not configured |
| CORS Wildcard | MEDIUM | `Access-Control-Allow-Origin: *` |
| CORS + Credentials | HIGH | Wildcard CORS with credentials enabled |
| User Self-Signup | MEDIUM | Unauthorized user registration enabled |
| Server Info Disclosure | LOW | Build info leaked via health endpoint |
| API Key Exposure | MEDIUM | Sensitive data in API responses |

## Version Detection Methods

The scanner uses 7+ endpoints for version detection:

| Priority | Endpoint | Method |
|----------|----------|--------|
| 1 | `/api/frontend/settings` | JSON buildInfo.version |
| 2 | `/api/health` | JSON version field |
| 3 | `/login` | HTML/JS patterns (8 regex patterns) |
| 4 | `/api/org` | JSON response + headers |
| 5 | `/api/user/signup` | JSON response + headers |
| 6 | `/api/annotations` | Response headers |
| 7 | `/grafana/api/dashboards/home` | JSON response + headers |

## False Positive Reduction Strategies

1. **Version-Based Filtering**: Skip inapplicable CVE checks (~40% reduction)
2. **Content Validation**: Require specific indicators, not just HTTP status (~60% reduction)
3. **Multi-Vector Testing**: Test multiple variants for confirmation
4. **Response Validation**: Content length, JSON structure, and indicator matching
5. **Rate Limit Detection**: Prevents false negatives from rate-limited responses
6. **Indicator Scoring**: Minimum indicator thresholds before reporting (e.g., 3/8 for CVE-2021-43798)
