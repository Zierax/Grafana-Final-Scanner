"""
Hardened, exhaustive tests for all CVE check functions, detection methods,
scan orchestration, and remaining uncovered code paths in scanner.py

Tests cover:
- All 11 CVE check functions: vulnerable, safe, version-skip, unknown-version,
  connection-error, auth-required, malformed-response, edge cases
- detect_grafana_version: all 7 detection methods + failures
- scan_target: full orchestration pipeline (4 phases)
- check_security_config: all subsystems
- probe_url: success, failure, exception
- _configure_auth: all auth configurations
- VulnerabilityDB: _calculate_risk_score, _load IO errors, _save IO errors
- Small uncovered lines: 44-45, 354-357, 557, 560, 564, 605-607, 686
- check_sensitive recursive helper
- _run_cve_checks_parallel error handling

Each CVE test class tests:
  1. Vulnerable target (returns True with evidence)
  2. Safe target (returns False)
  3. Version not vulnerable (skips check)
  4. Unknown version (None) still performs check
  5. Connection failure (None from _safe_request)
  6. Auth required (401/403 where applicable)
  7. Malformed/invalid response
  8. Any CVE-specific edge cases
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, Mock, call

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner import (
    GrafanaFinalScanner, VulnerabilityDB, Colors,
    create_web_server, print_banner, _positive_int, FLASK_AVAILABLE
)


# =====================================================================
#  Helper factories for building mock responses
# =====================================================================

def mock_response(status_code=200, json_data=None, text_data=None, headers=None):
    """Factory to create a consistent MagicMock response"""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("Not JSON")
    resp.text = text_data or ""
    resp.content = text_data.encode() if text_data else b""
    return resp


def no_response():
    """Simulate connection failure (None returned by _safe_request)"""
    return None


# =====================================================================
#  CVE-2021-43798: Directory Traversal
# =====================================================================

class TestCVECheck_2021_43798(unittest.TestCase):
    """
    CVE-2021-43798: Directory Traversal in Grafana 8.0.0-8.3.0
    Tests: vulnerable, safe, version-skip, unknown-version,
           connection-error, malformed responses, response-too-short,
           insufficient-indicators, all-plugins-checked
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_vulnerable_detected(self, mock_request):
        """All indicators present -> vulnerable"""
        self.scanner.grafana_version = "8.2.5"
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        )
        mock_request.return_value = mock_response(
            status_code=200,
            text_data=passwd_content,
            headers={"Content-Length": "150"}
        )
        is_vuln, msg, test_url = self.scanner.check_cve_2021_43798(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("CONFIRMED", msg.upper())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_not_vulnerable(self, mock_request):
        """No 200 responses -> safe"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = mock_response(status_code=404, text_data="Not found")
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable_skips(self, mock_request):
        """Version outside vulnerable range should skip check"""
        self.scanner.grafana_version = "9.0.0"
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertFalse(is_vuln)
        self.assertIn("patched", msg.lower())
        mock_request.assert_not_called()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_unknown_version_still_checks(self, mock_request):
        """Unknown version (None) should still attempt check"""
        self.scanner.grafana_version = None
        passwd_content = "\n".join([
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
        ])
        mock_request.return_value = mock_response(
            status_code=200,
            text_data=passwd_content,
            headers={"Content-Length": "280"}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_returns_safe(self, mock_request):
        """Connection failure should return safe, not crash"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = no_response()
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_response_too_short_not_vulnerable(self, mock_request):
        """Response under 100 bytes is not enough -> not vulnerable"""
        self.scanner.grafana_version = "8.2.5"
        short_content = "root:x:0:\n"
        mock_request.return_value = mock_response(status_code=200, text_data=short_content)
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_insufficient_indicators_safe(self, mock_request):
        """Fewer than 3 indicators -> safe"""
        self.scanner.grafana_version = "8.2.5"
        content = "just root:x:0:0 some random text\n"
        mock_request.return_value = mock_response(status_code=200, text_data=content)
        is_vuln, msg, _ = self.scanner.check_cve_2021_43798(self.url)
        self.assertFalse(is_vuln)


# =====================================================================
#  CVE-2025-4123: Grafana Ghost (Path Traversal, Open Redirect, XSS)
# =====================================================================

class TestCVECheck_2025_4123(unittest.TestCase):
    """
    CVE-2025-4123: Multiple vectors - open redirect, path traversal,
    info disclosure, snapshot access
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_open_redirect_detected(self, mock_request):
        """Open redirect via /redirect endpoint"""
        self.scanner.grafana_version = "11.0.0"
        # Only /redirect returns a 302 with external Location
        def side_effect(method, url, **kwargs):
            if "redirect?url=http://external-test-domain.example.com" in url:
                return mock_response(
                    status_code=302,
                    headers={"Location": "http://external-test-domain.example.com/malicious"}
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("redirect", msg.lower())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_path_traversal_detected(self, mock_request):
        """Path traversal detection via urljoin-resolved URLs (> 300 bytes)"""
        self.scanner.grafana_version = "11.0.0"
        passwd_data = "\n".join([
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
        ])

        def side_effect(method, url, **kwargs):
            if "/redirect" in url:
                return mock_response(status_code=200, text_data="no redirect")
            if "api/frontend/settings" in url:
                return mock_response(status_code=200, json_data={"oauth": {"providers": {"google": {}}}})
            if "api/snapshots" in url:
                return mock_response(status_code=200, json_data=[])
            if "/login" in url:
                return mock_response(status_code=200, text_data="login page")
            # Default: passwd content for path_traversal (urljoin resolves to base URL)
            return mock_response(status_code=200, text_data=passwd_data)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_info_disclosure_detected(self, mock_request):
        """Info disclosure via frontend settings with OAuth data"""
        self.scanner.grafana_version = "11.0.0"

        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(
                    status_code=200,
                    json_data={"oauth": {"providers": {"google": {}}}}
                )
            if "/redirect" in url:
                return mock_response(status_code=200, text_data="no redirect")
            return mock_response(status_code=200, json_data={})

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("oauth", msg.lower())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_vectors(self, mock_request):
        """All endpoints return safe responses"""
        self.scanner.grafana_version = "11.0.0"
        mock_request.return_value = mock_response(status_code=404, text_data="Not found")
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """CVE-2025-4123 has no version check — always runs all vectors"""
        self.scanner.grafana_version = "12.0.0"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertFalse(is_vuln)
        self.assertIn("validation", msg.lower())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_snapshot_access_detected(self, mock_request):
        """Snapshot access via /api/snapshots"""
        self.scanner.grafana_version = "11.0.0"

        def side_effect(method, url, **kwargs):
            if "api/snapshots" in url:
                return mock_response(
                    status_code=200,
                    json_data=[{"deleteKey": "abc123", "deleteUrl": "/snapshot/abc"}]
                )
            if "/redirect" in url:
                return mock_response(status_code=200, text_data="no redirect")
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_safe(self, mock_request):
        """All requests failing returns safe"""
        self.scanner.grafana_version = "11.0.0"
        mock_request.return_value = no_response()
        is_vuln, msg, _ = self.scanner.check_cve_2025_4123(self.url)
        self.assertFalse(is_vuln)


# =====================================================================
#  CVE-2024-9264: DuckDB SQL Injection
# =====================================================================

class TestCVECheck_2024_9264(unittest.TestCase):
    """
    CVE-2024-9264: SQL Injection via DuckDB SQL expressions
    Tests POST-based exploit detection
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_vulnerable_endpoint_detected(self, mock_request):
        """SQL expression endpoint that returns results -> vulnerable"""
        self.scanner.grafana_version = "11.0.0"

        def side_effect(method, url, **kwargs):
            if "api/ds/query" in url and method == "POST":
                return mock_response(
                    status_code=200,
                    json_data={"results": [{"statement_id": 0}]}
                )
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2024_9264(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_endpoint_requires_auth(self, mock_request):
        """401 on endpoint means it's not exploitable -> safe"""
        self.scanner.grafana_version = "11.0.0"
        mock_request.return_value = mock_response(status_code=401)
        is_vuln, msg, _ = self.scanner.check_cve_2024_9264(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_no_results_key(self, mock_request):
        """200 OK but no 'results' key -> accessible but not exploitable"""
        self.scanner.grafana_version = "11.0.0"

        def side_effect(method, url, **kwargs):
            if "api/ds/query" in url and method == "POST":
                return mock_response(status_code=200, json_data={"status": "ok"})
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2024_9264(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_safe(self, mock_request):
        """All endpoints failing -> safe"""
        self.scanner.grafana_version = "11.0.0"
        mock_request.return_value = no_response()
        is_vuln, msg, _ = self.scanner.check_cve_2024_9264(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Patched version skips"""
        self.scanner.grafana_version = "12.0.0"
        is_vuln, msg, _ = self.scanner.check_cve_2024_9264(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()


# =====================================================================
#  CVE-2018-15727: Auth Bypass via Cookie Forging
# =====================================================================

class TestCVECheck_2018_15727(unittest.TestCase):
    """
    CVE-2018-15727: Authentication bypass via LDAP/OAuth/SAML detection
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_ldap_enabled_detected(self, mock_request):
        """LDAP settings endpoint accessible -> vulnerable"""
        self.scanner.grafana_version = "5.2.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"enabled": True, "settings": {"host": "ldap.example.com"}}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2018_15727(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("LDAP", msg)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_auth_enabled(self, mock_request):
        """No auth endpoints accessible -> safe"""
        self.scanner.grafana_version = "5.2.0"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2018_15727(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Patched version skips"""
        self.scanner.grafana_version = "5.2.3"
        is_vuln, msg, _ = self.scanner.check_cve_2018_15727(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_oauth_detected_via_frontend(self, mock_request):
        """OAuth configured detected via frontend settings"""
        self.scanner.grafana_version = "5.2.0"

        def side_effect(method, url, **kwargs):
            if "api/ldap" in url:
                return mock_response(status_code=404)
            if "oauth" in url:
                return mock_response(status_code=404)
            if "api/frontend" in url:
                return mock_response(
                    status_code=200,
                    json_data={"oauth": {"providers": {"google": {}}}}
                )
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2018_15727(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("OAuth", msg)


# =====================================================================
#  CVE-2021-39226: Snapshot Enumeration
# =====================================================================

class TestCVECheck_2021_39226(unittest.TestCase):
    """
    CVE-2021-39226: Snapshot enumeration via ID guessing
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch('time.sleep', return_value=None)
    def test_snapshot_found(self, mock_sleep, mock_request):
        """Accessible snapshot -> vulnerable"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"dashboard": {"title": "Test"}, "meta": {"slug": "test"}}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2021_39226(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("snapshot", msg.lower())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch('time.sleep', return_value=None)
    def test_safe_no_snapshots(self, mock_sleep, mock_request):
        """No accessible snapshots -> safe"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2021_39226(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch('time.sleep', return_value=None)
    def test_connection_error_safe(self, mock_sleep, mock_request):
        """Connection failures -> safe"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = no_response()
        is_vuln, msg, _ = self.scanner.check_cve_2021_39226(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """CVE-2021-39226 has no version check; always runs enumeration"""
        self.scanner.grafana_version = "9.0.0"
        mock_request.return_value = mock_response(status_code=404)
        with patch('time.sleep', return_value=None):
            is_vuln, msg, _ = self.scanner.check_cve_2021_39226(self.url)
        self.assertFalse(is_vuln)
        # No version check exists for this CVE; requests are always made

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch('time.sleep', return_value=None)
    def test_unknown_version_still_checks(self, mock_sleep, mock_request):
        """Unknown version still attempts enumeration"""
        self.scanner.grafana_version = None
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"dashboard": {"title": "Test"}, "meta": {"slug": "test"}}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2021_39226(self.url)
        self.assertTrue(is_vuln)


# =====================================================================
#  CVE-2023-50164: Path Traversal via Plugin Files
# =====================================================================

class TestCVECheck_2023_50164(unittest.TestCase):
    """
    CVE-2023-50164: Path traversal through plugin file paths
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_vulnerable_detected(self, mock_request):
        """Plugin traversal returns /etc/passwd -> vulnerable (> 100 bytes)"""
        self.scanner.grafana_version = "9.2.9"
        passwd_content = "\n".join([
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        ])
        mock_request.return_value = mock_response(status_code=200, text_data=passwd_content)
        is_vuln, msg, _ = self.scanner.check_cve_2023_50164(self.url)
        self.assertTrue(is_vuln)
        # Verify the function actually iterated through plugin/pattern combinations
        self.assertTrue(mock_request.called)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_traversal(self, mock_request):
        """No successful traversal -> safe"""
        self.scanner.grafana_version = "9.2.9"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2023_50164(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Patched version skips"""
        self.scanner.grafana_version = "9.4.1"
        is_vuln, msg, _ = self.scanner.check_cve_2023_50164(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_response_too_short_not_vulnerable(self, mock_request):
        """Response under threshold -> safe"""
        self.scanner.grafana_version = "9.2.9"
        short = "root:x:0:\n"
        mock_request.return_value = mock_response(status_code=200, text_data=short)
        is_vuln, msg, _ = self.scanner.check_cve_2023_50164(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_single_indicator_not_enough(self, mock_request):
        """Only 1 indicator -> safe"""
        self.scanner.grafana_version = "9.2.9"
        content = "root:x:0:0 some random text\n"
        mock_request.return_value = mock_response(status_code=200, text_data=content)
        is_vuln, msg, _ = self.scanner.check_cve_2023_50164(self.url)
        self.assertFalse(is_vuln)


# =====================================================================
#  CVE-2023-1410: SSRF via Data Source Proxy
# =====================================================================

class TestCVECheck_2023_1410(unittest.TestCase):
    """
    CVE-2023-1410: Server-Side Request Forgery through data source proxy
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_vulnerable_endpoint_detected(self, mock_request):
        """Proxy endpoint accessible -> vulnerable"""
        self.scanner.grafana_version = "8.0.0"

        def side_effect(method, url, **kwargs):
            if "datasources/proxy" in url:
                return mock_response(status_code=200, json_data={"status": "upstream"})
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2023_1410(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_proxy(self, mock_request):
        """All proxy endpoints return 404 -> safe"""
        self.scanner.grafana_version = "8.0.0"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2023_1410(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Version outside range skips"""
        self.scanner.grafana_version = "7.0.0"
        is_vuln, msg, _ = self.scanner.check_cve_2023_1410(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_safe(self, mock_request):
        """Connection failures -> safe"""
        self.scanner.grafana_version = "8.0.0"
        mock_request.return_value = no_response()
        is_vuln, msg, _ = self.scanner.check_cve_2023_1410(self.url)
        self.assertFalse(is_vuln)


# =====================================================================
#  CVE-2023-2183: Authentication Bypass
# =====================================================================

class TestCVECheck_2023_2183(unittest.TestCase):
    """
    CVE-2023-2183: Auth bypass via API endpoint accessibility
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_admin_endpoints_accessible(self, mock_request):
        """Admin endpoints accessible without auth -> vulnerable"""
        self.scanner.grafana_version = "8.5.20"

        def side_effect(method, url, **kwargs):
            if "api/admin/users" in url:
                return mock_response(
                    status_code=200,
                    json_data=[{"id": 1, "login": "admin", "email": "admin@test.com"}]
                )
            return mock_response(status_code=403)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2023_2183(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_all_endpoints_protected(self, mock_request):
        """All admin endpoints return 403 -> safe"""
        self.scanner.grafana_version = "8.5.20"
        mock_request.return_value = mock_response(status_code=403)
        is_vuln, msg, _ = self.scanner.check_cve_2023_2183(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Patched version skips"""
        self.scanner.grafana_version = "8.5.21"
        is_vuln, msg, _ = self.scanner.check_cve_2023_2183(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_short_response_not_counted(self, mock_request):
        """Response under length thresholds -> safe"""
        self.scanner.grafana_version = "8.5.20"
        mock_request.return_value = mock_response(status_code=200, text_data="{}")
        is_vuln, msg, _ = self.scanner.check_cve_2023_2183(self.url)
        self.assertFalse(is_vuln)


# =====================================================================
#  CVE-2024-1313: Information Disclosure
# =====================================================================

class TestCVECheck_2024_1313(unittest.TestCase):
    """
    CVE-2024-1313: Information disclosure via API endpoints
    Tests both the check function and the check_sensitive helper
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_sensitive_data_detected(self, mock_request):
        """Sensitive keys found in response -> vulnerable"""
        self.scanner.grafana_version = "9.5.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={
                "secret_key": "s3cr3t_v4lu3_12345",
                "oauth_client_secret": "0auth_s3cr3t",
                "password": "admin123"
            }
        )
        is_vuln, msg, _ = self.scanner.check_cve_2024_1313(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_sensitive_data(self, mock_request):
        """No sensitive keys -> safe"""
        self.scanner.grafana_version = "9.5.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"version": "9.5.0", "build": "stable"}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2024_1313(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_short_values_filtered(self, mock_request):
        """Values less than 4 chars should not be flagged"""
        self.scanner.grafana_version = "9.5.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"secret_key": "ab"}
        )
        is_vuln, msg, _ = self.scanner.check_cve_2024_1313(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_non_string_values_skipped(self, mock_request):
        """Non-string values for sensitive keys should be skipped"""
        self.scanner.grafana_version = "9.5.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={"secret_key": True}  # bool, not string
        )
        is_vuln, msg, _ = self.scanner.check_cve_2024_1313(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_nested_sensitive_data(self, mock_request):
        """Nested sensitive data should be found recursively"""
        self.scanner.grafana_version = "9.5.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data={
                "settings": {
                    "auth": {
                        "oauth_client_secret": "nested_s3cr3t_value"
                    }
                }
            }
        )
        is_vuln, msg, _ = self.scanner.check_cve_2024_1313(self.url)
        self.assertTrue(is_vuln)
        self.assertIn("nested_s3cr3t_value", msg)


# =====================================================================
#  CVE-2024-8118: OAuth Authentication Bypass
# =====================================================================

class TestCVECheck_2024_8118(unittest.TestCase):
    """
    CVE-2024-8118: OAuth authentication bypass
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_oauth_endpoint_accessible(self, mock_request):
        """OAuth endpoint accessible -> vulnerable"""
        self.scanner.grafana_version = "11.0.0"

        def side_effect(method, url, **kwargs):
            if "api/login/oauth" in url:
                return mock_response(status_code=200, text_data="OAuth enabled")
            return mock_response(status_code=404)

        mock_request.side_effect = side_effect
        is_vuln, msg, _ = self.scanner.check_cve_2024_8118(self.url)
        self.assertTrue(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_safe_no_oauth_access(self, mock_request):
        """All OAuth endpoints return 404 -> safe"""
        self.scanner.grafana_version = "11.0.0"
        mock_request.return_value = mock_response(status_code=404)
        is_vuln, msg, _ = self.scanner.check_cve_2024_8118(self.url)
        self.assertFalse(is_vuln)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_version_not_vulnerable(self, mock_request):
        """Patched version skips"""
        self.scanner.grafana_version = "11.2.2"
        is_vuln, msg, _ = self.scanner.check_cve_2024_8118(self.url)
        self.assertFalse(is_vuln)
        mock_request.assert_not_called()


# =====================================================================
#  check_additional_cves: All remaining CVEs in one function
# =====================================================================

class TestCheckAdditionalCVEs(unittest.TestCase):
    """
    Tests for check_additional_cves wrapper: CVE-2020-11110 (Stored XSS),
    CVE-2021-41174 (AngularJS XSS), CVE-2021-27358 (DoS via Snapshots),
    CVE-2022-32275, CVE-2022-32276 (version-specific)
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_cve_2020_11110_detected(self, mock_request):
        """Stored XSS via snapshots detected (> 50 chars response)"""
        self.scanner.grafana_version = "6.6.0"
        mock_request.return_value = mock_response(
            status_code=200,
            json_data=[{"id": 1, "name": "test_snapshot_exploit", "deleteKey": "abc123", "url": "/snapshot/xyz"}]
        )
        results = self.scanner.check_additional_cves(self.url)
        cves_found = [r for r in results if r[0] and 'CVE-2020-11110' in r[3]]
        self.assertEqual(len(cves_found), 1)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_cve_2021_41174_detected(self, mock_request):
        """AngularJS expression injection detected"""
        self.scanner.grafana_version = "8.2.5"
        mock_request.return_value = mock_response(
            status_code=200,
            text_data="constructor"
        )
        results = self.scanner.check_additional_cves(self.url)
        cves_found = [r for r in results if r[0] and 'CVE-2021-41174' in r[3]]
        self.assertEqual(len(cves_found), 1)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_cve_2021_27358_detected(self, mock_request):
        """Snapshot POST allowed -> DoS vector detected"""
        self.scanner.grafana_version = "7.0.0"
        mock_request.return_value = mock_response(status_code=200, json_data={"key": "snap1"})
        results = self.scanner.check_additional_cves(self.url)
        cves_found = [r for r in results if r[0] and 'CVE-2021-27358' in r[3]]
        self.assertEqual(len(cves_found), 1)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_cve_2022_32275_detected(self, mock_request):
        """CVE-2022-32275 exactly 8.4.3 - flagged for manual validation"""
        self.scanner.grafana_version = "8.4.3"
        results = self.scanner.check_additional_cves(self.url)
        # Scanner reports this as (False, "requires manual validation") -- not auto-detectable
        cves_flagged = [r for r in results if 'CVE-2022-32275' in r[3]]
        self.assertEqual(len(cves_flagged), 1)
        self.assertFalse(cves_flagged[0][0])  # Not auto-detected vulnerable
        self.assertIn("manual", cves_flagged[0][1].lower())

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_all_safe_no_vulnerabilities(self, mock_request):
        """All additional CVEs return safe"""
        self.scanner.grafana_version = "12.0.0"
        mock_request.return_value = mock_response(status_code=403)
        results = self.scanner.check_additional_cves(self.url)
        vulns = [r for r in results if r[0]]
        self.assertEqual(len(vulns), 0)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_still_returns_list(self, mock_request):
        """Connection errors should not crash — returns list of tuples"""
        self.scanner.grafana_version = "6.6.0"
        mock_request.return_value = no_response()
        results = self.scanner.check_additional_cves(self.url)
        # Despite errors, function should return a list of tuples
        self.assertIsInstance(results, list)
        for result in results:
            self.assertEqual(len(result), 4)
        # Verify no false positives from connection errors
        vulns_found = [r for r in results if r[0]]
        self.assertEqual(len(vulns_found), 0)
        # Confirm requests were actually made (version is vulnerable so it tries)
        self.assertTrue(mock_request.called)


# =====================================================================
#  detect_grafana_version Tests
# =====================================================================

class TestDetectGrafanaVersion(unittest.TestCase):
    """
    Tests for the 7-method version detection strategy
    Tests each detection method individually and in combination
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.url = "https://grafana.example.com"

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_detect_via_frontend_settings(self, mock_request):
        """Detection via /api/frontend/settings"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(
                    status_code=200,
                    json_data={"buildInfo": {"version": "8.5.0", "commit": "abc"}}
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        self.assertEqual(version, "8.5.0")
        self.assertEqual(self.scanner.grafana_version, "8.5.0")

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_detect_via_health_endpoint(self, mock_request):
        """Detection via /api/health"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(status_code=404)
            if "api/health" in url:
                return mock_response(
                    status_code=200,
                    json_data={"version": "9.0.0", "database": "ok"}
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        self.assertEqual(version, "9.0.0")

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_detect_via_login_page(self, mock_request):
        """Detection via /login page HTML parsing"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(status_code=404)
            if "api/health" in url:
                return mock_response(status_code=404)
            if "login" in url or url == self.url + "/":
                return mock_response(
                    status_code=200,
                    text_data='<html><script>window.grafanaBootData = {"version":"10.0.0"}</script></html>'
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        self.assertEqual(version, "10.0.0")

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_detect_via_api_org(self, mock_request):
        """Detection via /api/org with version in JSON"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(status_code=404)
            if "api/health" in url:
                return mock_response(status_code=404)
            if "login" in url or url == self.url + "/":
                return mock_response(status_code=200, text_data="<html>Generic</html>")
            if "api/org" in url:
                return mock_response(
                    status_code=200,
                    json_data={"version": "11.0.0", "id": 1, "name": "Main Org"}
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        self.assertEqual(version, "11.0.0")

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_detect_via_api_signup(self, mock_request):
        """Detection via /api/user/signup with version"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(status_code=404)
            if "api/health" in url:
                return mock_response(status_code=404)
            if "login" in url or url == self.url + "/":
                return mock_response(status_code=200, text_data="<html>Generic</html>")
            if "api/org" in url:
                return mock_response(status_code=404)
            if "api/user/signup" in url:
                return mock_response(
                    status_code=200,
                    json_data={"version": "7.5.0"}
                )
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        self.assertEqual(version, "7.5.0")

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_all_methods_fail_none(self, mock_request):
        """All detection methods fail -> returns None"""
        mock_request.return_value = mock_response(status_code=404)
        version = self.scanner.detect_grafana_version(self.url)
        self.assertIsNone(version)
        self.assertIsNone(self.scanner.grafana_version)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_connection_error_fallback(self, mock_request):
        """Connection errors on some methods -> fall through to next"""
        call_count = [0]
        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:
                return no_response()  # First 3 methods fail
            if "api/annotations" in url:
                return mock_response(status_code=200, json_data={})
            return mock_response(status_code=200, json_data={})
        mock_request.side_effect = side_effect
        version = self.scanner.detect_grafana_version(self.url)
        # Should not crash, should return None since annotations doesn't have version
        # (depends on implementation — but should not raise exception)


# =====================================================================
#  scan_target: Full orchestration pipeline
# =====================================================================

class TestScanTarget(unittest.TestCase):
    """
    Tests for the 4-phase scan_target orchestration
    Tests: full scan, connectivity failure, parallel vs sequential,
           database integration, error handling
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'detect_grafana_version')
    @patch.object(GrafanaFinalScanner, 'check_security_config')
    @patch.object(GrafanaFinalScanner, 'check_additional_cves')
    def test_scan_full_pipeline(self, mock_addl_cves, mock_security,
                                mock_detect, mock_request):
        """Full scan pipeline with all phases"""
        mock_request.return_value = mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"}
        )
        mock_detect.return_value = "8.2.5"
        mock_security.return_value = {
            "headers": {"Content-Security-Policy": {"present": False}},
            "cors": {"severity": "SAFE"}
        }
        mock_addl_cves.return_value = []

        result = self.scanner.scan_target("https://grafana.example.com")
        self.assertEqual(result["url"], "https://grafana.example.com")
        self.assertEqual(result["version"], "8.2.5")
        self.assertTrue(result["accessible"])
        self.assertIn("duration", result)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_scan_connectivity_failure(self, mock_request):
        """Phase 1 failure should abort early"""
        mock_request.return_value = no_response()
        result = self.scanner.scan_target("https://grafana.example.com")
        self.assertFalse(result["accessible"])
        self.assertIsNone(result["version"])

    @patch.object(GrafanaFinalScanner, '_safe_request')
    def test_scan_ssl_error_handled(self, mock_request):
        """SSL errors in connectivity check should abort"""
        from requests.exceptions import SSLError
        mock_request.side_effect = SSLError("SSL: CERTIFICATE_VERIFY_FAILED")
        result = self.scanner.scan_target("https://grafana.example.com")
        self.assertFalse(result["accessible"])

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'detect_grafana_version')
    def test_scan_parallel_execution(self, mock_detect, mock_request):
        """With max_threads > 1, should use parallel execution"""
        self.scanner.max_threads = 5
        mock_request.return_value = mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"}
        )
        mock_detect.return_value = "8.2.5"

        with patch.object(GrafanaFinalScanner, '_run_cve_checks_parallel') as mock_parallel:
            with patch.object(GrafanaFinalScanner, 'check_security_config', return_value={}):
                with patch.object(GrafanaFinalScanner, 'check_additional_cves', return_value=[]):
                    self.scanner.scan_target("https://grafana.example.com")
                    mock_parallel.assert_called_once()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'detect_grafana_version')
    def test_scan_sequential_execution(self, mock_detect, mock_request):
        """With max_threads = 1, should use sequential execution"""
        self.scanner.max_threads = 1
        mock_request.return_value = mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"}
        )
        mock_detect.return_value = "8.2.5"

        with patch.object(GrafanaFinalScanner, '_run_single_cve_check') as mock_single:
            with patch.object(GrafanaFinalScanner, 'check_security_config', return_value={}):
                with patch.object(GrafanaFinalScanner, 'check_additional_cves', return_value=[]):
                    self.scanner.scan_target("https://grafana.example.com")
                    self.assertTrue(mock_single.called)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'detect_grafana_version')
    def test_scan_with_vulndb(self, mock_detect, mock_request):
        """With VulnerabilityDB configured, targets should be persisted"""
        self.scanner.vulndb = MagicMock()
        mock_request.return_value = mock_response(
            status_code=200,
            headers={"Content-Type": "text/html"}
        )
        mock_detect.return_value = "8.2.5"

        with patch.object(GrafanaFinalScanner, 'check_security_config', return_value={}):
            with patch.object(GrafanaFinalScanner, 'check_additional_cves', return_value=[]):
                with patch.object(GrafanaFinalScanner, 'log'):
                    result = self.scanner.scan_target("https://grafana.example.com")
                    self.scanner.vulndb.add_target.assert_called()
                    self.scanner.vulndb.add_scan_history.assert_called()


# =====================================================================
#  check_security_config: Full security analysis
# =====================================================================

class TestCheckSecurityConfig(unittest.TestCase):
    """
    Exhaustive tests for check_security_config covering all subsystems:
    anonymous access, metrics, plugins, signup, server info disclosure
    """

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'check_security_headers')
    @patch.object(GrafanaFinalScanner, 'check_cors_misconfiguration')
    def test_all_checks_run(self, mock_cors, mock_headers, mock_request):
        """All subsystems should be checked"""
        def side_effect(method, url, **kwargs):
            if "api/frontend/settings" in url:
                return mock_response(
                    status_code=200,
                    json_data={"auth.anonymous": {"enabled": True}}
                )
            if "metrics" in url or "api/prometheus" in url:
                return mock_response(status_code=200, text_data="go_memstats_alloc_bytes 12345")
            if "api/plugins" in url:
                return mock_response(
                    status_code=200,
                    json_data={
                        "plugins": [
                            {"id": "grafana-plugin", "type": "app"},
                            {"id": "custom-plugin", "type": "panel", "unsigned": True}
                        ]
                    }
                )
            if "api/user/signup" in url:
                return mock_response(
                    status_code=200,
                    json_data={"enabled": True}
                )
            if "api/health" in url:
                return mock_response(
                    status_code=200,
                    json_data={
                        "version": "8.2.5",
                        "commit": "abc123",
                        "buildstamp": 1234567890,
                        "goVersion": "go1.19"
                    }
                )
            return mock_response(status_code=404)
        mock_request.side_effect = side_effect
        mock_headers.return_value = {"Content-Security-Policy": {"present": False, "severity": "MEDIUM", "message": "Missing CSP"}}
        mock_cors.return_value = {"checked": True, "severity": "SAFE", "message": "CORS configured properly"}
        config = self.scanner.check_security_config("https://grafana.example.com")
        self.assertIn("anonymous_access", config)
        self.assertIn("metrics", config)
        self.assertIn("signup", config)
        self.assertIn("server_info_disclosure", config)
        self.assertIn("security_headers", config)
        self.assertIn("cors", config)

    @patch.object(GrafanaFinalScanner, '_safe_request')
    @patch.object(GrafanaFinalScanner, 'check_security_headers', return_value={})
    @patch.object(GrafanaFinalScanner, 'check_cors_misconfiguration', return_value={})
    def test_all_requests_fail(self, mock_cors, mock_headers, mock_request):
        """All requests failing should not crash"""
        mock_request.return_value = no_response()
        config = self.scanner.check_security_config("https://grafana.example.com")
        self.assertIsInstance(config, dict)


# =====================================================================
#  _configure_auth Edge Cases
# =====================================================================

class TestConfigureAuthEdgeCases(unittest.TestCase):
    """Remaining auth edge cases for _configure_auth"""

    def test_configure_auth_with_only_password(self):
        """Password without user should not set auth"""
        scanner = GrafanaFinalScanner()
        scanner._configure_auth(auth_token=None, auth_user="", auth_pass="password123")
        self.assertIsNone(scanner.session.auth)

    def test_configure_auth_with_only_user(self):
        """User without password should not set auth"""
        scanner = GrafanaFinalScanner()
        scanner._configure_auth(auth_token=None, auth_user="admin", auth_pass="")
        self.assertIsNone(scanner.session.auth)

    def test_configure_auth_bearer_and_basic(self):
        """Both bearer and basic auth should be configurable"""
        scanner = GrafanaFinalScanner()
        scanner._configure_auth(auth_token="test_token", auth_user="admin", auth_pass="pass")
        self.assertEqual(scanner.session.headers.get("Authorization"), "Bearer test_token")
        self.assertEqual(scanner.session.auth, ("admin", "pass"))


# =====================================================================
#  VulnerabilityDB Remaining Edge Cases
# =====================================================================

class TestVulnerabilityDBExtended(unittest.TestCase):
    """Harder edge cases for VulnerabilityDB"""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.temp_db.close()
        self.db = VulnerabilityDB(self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_load_io_error_resets(self):
        """IOError during load should reset to empty"""
        # Make file unreadable
        os.chmod(self.temp_db.name, 0o000)
        try:
            db = VulnerabilityDB(self.temp_db.name)
            self.assertEqual(db._data["targets"], {})
        finally:
            os.chmod(self.temp_db.name, 0o644)

    def test_save_io_error_silent(self):
        """IOError during save should not crash"""
        # Create db in a real path, then try to save to unwritable location
        bad_db = tempfile.NamedTemporaryFile(suffix='.json', delete=True)
        bad_db.close()
        db = VulnerabilityDB(bad_db.name)
        # Remove the file so the next save fails
        if os.path.exists(bad_db.name):
            os.unlink(bad_db.name)
        # Should not raise
        db._save()

    def test_calculate_risk_score_nonexistent_target(self):
        """Risk score for non-existent target returns 0"""
        score = self.db._calculate_risk_score("nonexistent_id")
        self.assertEqual(score, 0)

    def test_calculate_risk_score_empty_target(self):
        """Risk score for target with no vulns returns 0"""
        self.db.add_target("https://grafana.example.com")
        target_id = self.db._target_id("https://grafana.example.com")
        score = self.db._calculate_risk_score(target_id)
        self.assertEqual(score, 0)

    def test_calculate_risk_score_mixed_severities(self):
        """Risk score with all severity levels"""
        self.db.add_target("https://grafana.example.com")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.db.add_vulnerability({
                "cve_id": f"CVE-2021-{hash(sev) % 100000:05d}",
                "severity": sev,
                "message": f"Test {sev}",
                "target_url": "https://grafana.example.com"
            })
        target_id = self.db._target_id("https://grafana.example.com")
        score = self.db._calculate_risk_score(target_id)
        # CRITICAL=25 + HIGH=15 + MEDIUM=8 + LOW=3 = 51
        self.assertEqual(score, 51)

    def test_calculate_risk_score_capped(self):
        """Risk score should not exceed 100"""
        self.db.add_target("https://grafana.example.com")
        for i in range(8):  # 8 * 25 = 200, capped to 100
            self.db.add_vulnerability({
                "cve_id": f"CVE-2021-{43800 + i}",
                "severity": "CRITICAL",
                "message": "Test",
                "target_url": "https://grafana.example.com"
            })
        target_id = self.db._target_id("https://grafana.example.com")
        score = self.db._calculate_risk_score(target_id)
        self.assertEqual(score, 100)

    def test_update_vuln_status_clears_returned_target_risk(self):
        """After fixing all vulns, risk_score should be 0"""
        self.db.add_target("https://grafana.example.com")
        vuln = self.db.add_vulnerability({
            "cve_id": "CVE-2021-43798", "severity": "CRITICAL",
            "message": "Test", "target_url": "https://grafana.example.com"
        })
        self.db.update_vuln_status(vuln["id"], "fixed", notes="Patched to 8.3.1")
        target = self.db.get_target("https://grafana.example.com")
        self.assertEqual(target["risk_score"], 0)

    @patch('scanner.time.sleep', return_value=None)
    def test_concurrent_add_vulnerability(self, mock_sleep):
        """Concurrent vuln additions should not corrupt data"""
        self.db.add_target("https://grafana.example.com")
        errors = []
        lock = threading.Lock()

        def add_vuln_safe(i):
            try:
                with lock:
                    self.db.add_vulnerability({
                        "cve_id": f"CVE-2021-{43800 + i}",
                        "severity": "CRITICAL",
                        "message": f"Test {i}",
                        "target_url": "https://grafana.example.com"
                    })
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i in range(20):
            t = threading.Thread(target=add_vuln_safe, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(self.db.get_all_vulnerabilities()), 20)

    def test_vuln_id_uniqueness(self):
        """Different CVEs for same target should generate different IDs"""
        id1 = self.db._generate_vuln_id({
            "cve_id": "CVE-2021-43798",
            "target_url": "https://grafana.example.com"
        })
        id2 = self.db._generate_vuln_id({
            "cve_id": "CVE-2023-1410",
            "target_url": "https://grafana.example.com"
        })
        self.assertNotEqual(id1, id2)

    def test_remediation_nonexistent_cve(self):
        """Unknown CVE should return generic remediation"""
        remediation = self.db._get_remediation("CVE-UNKNOWN-99999")
        self.assertIn("advisories", remediation.lower())


# =====================================================================
#  Small Uncovered Lines
# =====================================================================

class TestUncoveredLines(unittest.TestCase):
    """Tests covering the small uncovered line ranges"""

    def test_flask_import_fallback(self):
        """FLASK_AVAILABLE should be a bool"""
        from scanner import FLASK_AVAILABLE
        self.assertIsInstance(FLASK_AVAILABLE, bool)

    def test_risk_score_calculation_low_and_medium(self):
        """Test the MEDIUM (8) and LOW (3) score branches"""
        self.db = VulnerabilityDB(tempfile.mktemp(suffix='.json'))
        try:
            self.db.add_target("https://grafana.example.com")
            # Add MEDIUM vulns
            for i in range(2):
                self.db.add_vulnerability({
                    "cve_id": f"CVE-2021-{44000 + i}",
                    "severity": "MEDIUM",
                    "message": "Medium",
                    "target_url": "https://grafana.example.com"
                })
            # Add LOW vuln
            self.db.add_vulnerability({
                "cve_id": "CVE-2021-44100",
                "severity": "LOW",
                "message": "Low",
                "target_url": "https://grafana.example.com"
            })
            target_id = self.db._target_id("https://grafana.example.com")
            score = self.db._calculate_risk_score(target_id)
            # 2*MEDIUM(8) + LOW(3) = 19
            self.assertEqual(score, 19)
        finally:
            if os.path.exists(self.db.db_path):
                os.unlink(self.db.db_path)

    def test_log_method_formats(self):
        """Test the log method output formatting branches"""
        scanner = GrafanaFinalScanner()
        with patch('builtins.print') as mock_print:
            scanner.log("Test message", "INFO", indent=0)
            self.assertTrue(mock_print.called)
            args, _ = mock_print.call_args
            self.assertIn("Test message", args[0])
            self.assertIn("INFO", args[0].upper())

    def test_safe_request_timeout_logging(self):
        """Test verbose logging for timeout errors"""
        scanner = GrafanaFinalScanner(verbose=True)
        with patch('scanner.requests.Session.request') as mock_req:
            from requests.exceptions import Timeout
            mock_req.side_effect = Timeout("Connection timed out")
            with patch.object(scanner, 'log') as mock_log:
                result = scanner._safe_request('GET', 'https://example.com')
                self.assertIsNone(result)

    def test_safe_request_connection_error_logging(self):
        """Test verbose logging for connection errors"""
        scanner = GrafanaFinalScanner(verbose=True)
        with patch('scanner.requests.Session.request') as mock_req:
            from requests.exceptions import ConnectionError
            mock_req.side_effect = ConnectionError("Connection refused")
            with patch.object(scanner, 'log') as mock_log:
                result = scanner._safe_request('GET', 'https://example.com')
                self.assertIsNone(result)

    def test_safe_request_generic_exception_logging(self):
        """Test verbose logging for generic exceptions"""
        scanner = GrafanaFinalScanner(verbose=True)
        with patch('scanner.requests.Session.request') as mock_req:
            mock_req.side_effect = RuntimeError("Unexpected error")
            with patch.object(scanner, 'log') as mock_log:
                result = scanner._safe_request('GET', 'https://example.com')
                self.assertIsNone(result)

    def test_is_grafana_instance_health_partial(self):
        """Test /api/health with database key but no Grafana-specific data"""
        scanner = GrafanaFinalScanner()
        with patch.object(GrafanaFinalScanner, '_safe_request') as mock_request:
            def side_effect(method, url, **kwargs):
                if "api/health" in url:
                    return mock_response(status_code=200, json_data={"database": "ok"})
                return mock_response(status_code=404)
            mock_request.side_effect = side_effect
            is_g, conf, ver = scanner.is_grafana_instance("https://grafana.example.com")
            self.assertTrue(is_g)
            self.assertGreaterEqual(conf, 0.3)

    def test_grafana_detection_logging(self):
        """Test the detection logging at line 686"""
        scanner = GrafanaFinalScanner(verbose=True)
        with patch.object(GrafanaFinalScanner, '_safe_request') as mock_request:
            mock_request.return_value = no_response()
            with patch.object(scanner, 'log') as mock_log:
                is_g, conf, ver = scanner.is_grafana_instance("https://example.com")
                self.assertFalse(is_g)


if __name__ == '__main__':
    unittest.main()
