# Architecture

This document describes how Grafana Final Scanner is structured and how a
scan flows through the code. It reflects the state of v3.1.

## Files

```
scanner.py                Main module: engine, CVE checks, database, dashboard, CLI
requirements.txt          Production dependencies (requests; flask optional)
pyproject.toml            Packaging and tool config (pytest, ruff)
Makefile                  dev tasks (test, lint, docker)
Dockerfile                container image (non-root user)
CHANGELOG.md              version history
docs/                     usage.md, vulnerabilities.md, architecture.md
tests/                    pytest suite
```

`scanner.py` is a single module by design: one file is easy to copy and run
and keeps the dependency surface small. It is organized into clear sections:

- `VulnerabilityDB` — JSON database manager.
- `GrafanaFinalScanner` — detection, version fingerprinting, CVE checks,
  configuration analysis, and scan orchestration.
- `create_web_server` — Flask app factory for the dashboard.
- `main` — argument parsing and CLI entry point.

## VulnerabilityDB

A flat JSON file backed by an `RLock`. Key methods:

- `_load` / `_atomic_write` — read and write the database.
- `add_target`, `add_vulnerability`, `add_scan_history` — mutation.
- `get_target`, `get_all_targets`, `get_open_vulnerabilities` — queries.
- `update_vuln_status` — triage (open / fixed / false_positive / accepted).
- `get_statistics`, `_calculate_risk_score` — aggregation.

### Durability

Writes are atomic: the data is serialized to a temporary file, flushed,
`fsync`'d, then renamed over the target with `os.replace`. The previous good
copy is kept as `<db>.bak`. If the file on disk fails to parse, it is moved
to `<db>.corrupt-<timestamp>` and a fresh empty database is returned, so a
corrupt file never silently destroys history.

## GrafanaFinalScanner

Responsibilities:

- **Detection** — `is_grafana_instance` probes several endpoints and scores
  confidence; `auto_search_from_file` runs detection in parallel and then
  scans only confirmed instances.
- **Version fingerprinting** — `detect_grafana_version` tries 7 endpoints and
  returns the detected version.
- **CVE checks** — one method per CVE, each version-aware so irrelevant
  targets are skipped.
- **Configuration analysis** — security headers, CORS, anonymous access,
  self-signup, plugin analysis, exposed metrics.
- **Scan orchestration** — `scan_target` runs the full pipeline.

### Thread safety

`scan_target` mutates per-scan state (detected version, statistics, plugin
list). It is wrapped by a lock so concurrent calls on one instance are
serialized and cannot clobber each other's state. Detection (`is_grafana_instance`)
does not mutate that shared state. Rate limiting is handled per request with
backoff and retry; there is no shared global "blocked" flag.

## Web dashboard

`create_web_server` builds a Flask app. When `--dashboard-token` is set, every
route requires `Authorization: Bearer <token>` (or a `?token=` query
parameter). State-changing requests additionally require an `X-CSRF-Token`
header matching a `SameSite=Strict` cookie. Without a token the server prints
a warning when bound to a non-local interface.

## Data flow

```
target (URL / file / auto-search)
   -> connectivity check
   -> version fingerprinting
   -> CVE checks (version-aware)
   -> configuration analysis
   -> compile results
   -> write JSON/HTML/CSV reports
   -> persist to database (if --db)
```

## Security behavior

- TLS verification is on by default; `--no-ssl-verify` prints a warning.
- The dashboard is unauthenticated unless `--dashboard-token` is provided,
  and requires CSRF protection for mutations.
- Secret material (authorization headers, passwords, cookies, tokens) is
  redacted from all console output.
- HTML reports neutralize `javascript:`/`data:`/`vbscript:` URIs from
  responses.

## Testing

- `tests/test_scanner.py` — core engine, version comparison, auth, reports.
- `tests/test_cve_checks.py` — every CVE check (vulnerable/safe/version-skip/
  error paths).
- `tests/test_vulnerability_db.py` — database CRUD, deduplication, persistence.
- `tests/test_edge_cases.py` — boundary conditions and error handling.
- `tests/test_reporting_and_cli.py` — report generation and CLI flows.
- `tests/test_security_hardening.py` — atomic DB, XSS sanitization, SSL
  default, rate-limit backoff, dashboard auth/CSRF.

The CI runs the suite and ruff/flake8 on Python 3.9–3.12 and builds the
Docker image.

## Known limitations

- The JSON database is not suitable for very large datasets (no indexing,
  full rewrite per save). For heavy use, switch to SQLite.
- CVE checks use response content matching; a cooperative or specially
  crafted target could produce false negatives or positives.
