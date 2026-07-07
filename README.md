# Grafana Final Scanner

A command-line vulnerability scanner for Grafana. It fingerprints the
installed Grafana version, runs a set of version-aware CVE checks, audits
common configuration weaknesses, stores results in a local database, and can
serve them through a small web dashboard.

## Legal

This tool sends requests to Grafana instances and, for some checks, attempts
known exploit paths (path traversal, SQL injection, SSRF). Only run it against
systems you own or have written permission to test. Unauthorized scanning may
violate computer-misuse laws in your jurisdiction.

## Requirements

- Python 3.9 or newer
- `requests`
- `flask` (only required for `--serve`)

## Install

```
pip install -r requirements.txt
```

## Quick start

```
# Scan a single target
python scanner.py -u https://grafana.example.com

# Scan a list of URLs from a file
python scanner.py -f targets.txt -o report

# Detect Grafana instances in a mixed URL list, then scan them
python scanner.py --auto-search urls.txt -o discovery

# Persist results to a database and view them in the dashboard
python scanner.py -f targets.txt --db vulndb.json
python scanner.py --serve --db vulndb.json
```

## Command-line options

| Option | Description |
|--------|-------------|
| `-u, --url` | Scan a single target URL |
| `-f, --file` | Scan targets listed one per line in a file |
| `--auto-search FILE` | Detect Grafana in a URL list, then scan detected instances |
| `-o, --output BASE` | Base name for JSON/HTML/CSV report files |
| `--timeout N` | Per-request timeout in seconds (default 10) |
| `--threads N` | Concurrent scan threads (default 5) |
| `--db FILE` | Enable the JSON vulnerability database at the given path |
| `--serve [PORT]` | Start the Flask web dashboard (default port 8080) |
| `--host` | Address the dashboard binds to (default 127.0.0.1) |
| `--dashboard-token TOKEN` | Require this bearer token on all dashboard routes |
| `--auth-token` | Bearer token for scanning authenticated endpoints |
| `--auth-user` / `--auth-pass` | Basic authentication for scanning |
| `--no-ssl-verify` | Disable TLS certificate verification (prints a warning) |
| `-v, --verbose` | Print per-check detail |
| `--no-banner` | Suppress the startup header |

## Security behavior

- **TLS is verified by default.** Pass `--no-ssl-verify` only for internal
  hosts with self-signed certificates; doing so prints a warning because
  credentials could otherwise be exposed to interception.
- **The dashboard is unauthenticated unless you set `--dashboard-token`.**
  When the dashboard is bound to a non-local interface you must set a token.
  All state-changing requests also require a CSRF token.
- **Secrets are redacted** from all console output (authorization headers,
  passwords, cookies, tokens).

## Reports and database

With `-o`, the scanner writes `BASE.json`, `BASE.html`, and `BASE.csv`. The
HTML report neutralizes `javascript:`/`data:`/`vbscript:` URIs that could come
from a malicious target response.

With `--db`, findings are stored in a JSON file that is written atomically: a
`.bak` copy of the previous state is kept, and a file that fails to parse is
moved to `.corrupt-<timestamp>` instead of being silently discarded.

## Checks

The scanner runs version-aware CVE checks plus configuration audits (security
headers, CORS, anonymous access, self-signup, plugin analysis, exposed
metrics). The full CVE list and detection method notes are in
`docs/vulnerabilities.md`.

## Project layout

- `scanner.py` — engine, checks, database, web dashboard, CLI
- `docs/usage.md` — scanning modes and workflows
- `docs/vulnerabilities.md` — CVE reference
- `docs/architecture.md` — internal structure and data flow
- `tests/` — test suite

## Development

```
make test       # run the test suite
make lint       # ruff + flake8
```

The CI pipeline runs the tests and linters on Python 3.9–3.12 and builds the
Docker image.

## License

MIT. See `LICENSE`.
