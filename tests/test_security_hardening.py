"""
Security and reliability hardening tests for Grafana Final Scanner.

These tests cover the fixes introduced in v3.1:
  - Atomic, recoverable vulnerability database writes (C-002)
  - SSL verification enabled by default with explicit opt-out warning (C-003)
  - XSS-safe URL/text sanitization in reports (C-007)
  - Per-request rate-limit backoff without a shared global flag (C-005)
  - Dashboard authentication and CSRF protection (C-001)
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scanner import (
    GrafanaFinalScanner,
    VulnerabilityDB,
    sanitize_href,
    sanitize_text,
    create_web_server,
)


class TestUrlSanitization(unittest.TestCase):
    """XSS hardening for report/dashboard link targets (C-007)."""

    def test_safe_http_url_passthrough(self):
        url = 'https://grafana.example.com/api/health'
        self.assertEqual(sanitize_href(url), url)

    def test_safe_mailto_url_passthrough(self):
        self.assertEqual(sanitize_href('mailto:sec@example.com'),
                         'mailto:sec@example.com')

    def test_javascript_scheme_rejected(self):
        self.assertEqual(sanitize_href('javascript:alert(document.cookie)'), '#')

    def test_data_scheme_rejected(self):
        self.assertEqual(sanitize_href('data:text/html,<script>alert(1)</script>'), '#')

    def test_vbscript_scheme_rejected(self):
        self.assertEqual(sanitize_href('vbscript:msgbox(1)'), '#')

    def test_encoded_javascript_scheme_rejected(self):
        # Attempt to bypass via HTML entities must still be caught.
        self.assertEqual(sanitize_href('java&#115;cript:alert(1)'), '#')

    def test_empty_url_falls_back_to_hash(self):
        self.assertEqual(sanitize_href(''), '#')
        self.assertEqual(sanitize_href(None), '#')

    def test_sanitize_text_escapes_html(self):
        self.assertEqual(sanitize_text('<b>x</b>'), '&lt;b&gt;x&lt;/b&gt;')
        self.assertEqual(sanitize_text(None), '')


class TestHtmlReportXss(unittest.TestCase):
    """The generated HTML report must not embed executable URIs (C-007)."""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.tmp = tempfile.NamedTemporaryFile(suffix='.html', delete=False)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def _result_with(self, test_url):
        return [{
            'url': 'https://grafana.example.com',
            'version': '9.2.0',
            'vulnerabilities': [{
                'severity': 'CRITICAL',
                'cve_id': 'CVE-2021-43798',
                'message': 'Path traversal detected',
                'test_url': test_url,
            }],
        }]

    def test_javascript_url_is_neutralized_in_report(self):
        self.scanner._save_html_report(
            self._result_with('javascript:alert(document.cookie)'), self.tmp.name)
        content = open(self.tmp.name, 'r', encoding='utf-8').read()
        self.assertNotIn('javascript:alert', content)
        self.assertIn('href="#"', content)

    def test_data_url_is_neutralized_in_report(self):
        self.scanner._save_html_report(
            self._result_with('data:text/html,<script>alert(1)</script>'), self.tmp.name)
        content = open(self.tmp.name, 'r', encoding='utf-8').read()
        self.assertNotIn('data:text/html', content)


class TestVulnerabilityDBAtomicWrites(unittest.TestCase):
    """Atomic, recoverable database persistence (C-002)."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.tmp.close()
        self.db = VulnerabilityDB(self.tmp.name)

    def tearDown(self):
        for path in (self.tmp.name, self.tmp.name + '.bak'):
            if os.path.exists(path):
                os.unlink(path)
        for f in os.listdir('.'):
            if f.startswith(os.path.basename(self.tmp.name) + '.corrupt-'):
                os.unlink(f)

    def test_save_creates_valid_file(self):
        self.db.add_target('https://grafana.example.com', '9.2.0')
        self.assertTrue(os.path.exists(self.tmp.name))
        with open(self.tmp.name, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data['version'], '3.1')
        self.assertIn('grafana.example.com', data['targets'])

    def test_save_creates_backup_of_previous(self):
        self.db.add_target('https://grafana.example.com', '9.2.0')
        first_mtime = os.path.getmtime(self.tmp.name)
        # Second write should produce a .bak of the previous good copy.
        self.db.add_target('https://other.example.com', '10.0.0')
        self.assertTrue(os.path.exists(self.tmp.name + '.bak'))
        with open(self.tmp.name + '.bak', 'r', encoding='utf-8') as f:
            backup = json.load(f)
        self.assertIn('grafana.example.com', backup['targets'])
        self.assertNotIn('other.example.com', backup['targets'])

    def test_corrupted_db_is_preserved_not_silently_discarded(self):
        # Seed a valid DB, then corrupt the file on disk.
        self.db.add_target('https://grafana.example.com', '9.2.0')
        with open(self.tmp.name, 'w', encoding='utf-8') as f:
            f.write('{ this is not valid json')
        db2 = VulnerabilityDB(self.tmp.name)
        # A fresh (empty) database is returned ...
        self.assertEqual(db2._data['targets'], {})
        # ... and the corrupted file is moved aside rather than destroyed.
        db_dir = os.path.dirname(os.path.abspath(self.tmp.name))
        corrupt_files = [f for f in os.listdir(db_dir)
                         if f.startswith(os.path.basename(self.tmp.name) + '.corrupt-')]
        self.assertEqual(len(corrupt_files), 1)
        for f in corrupt_files:
            os.unlink(os.path.join(db_dir, f))

    def test_missing_required_keys_are_backfilled(self):
        with open(self.tmp.name, 'w', encoding='utf-8') as f:
            json.dump({'version': '3.1'}, f)
        db = VulnerabilityDB(self.tmp.name)
        self.assertEqual(db._data['targets'], {})
        self.assertEqual(db._data['vulnerabilities'], [])
        self.assertEqual(db._data['scan_history'], [])


class TestSSLVerificationDefault(unittest.TestCase):
    """TLS verification must be on by default (C-003)."""

    def test_verify_ssl_defaults_true(self):
        scanner = GrafanaFinalScanner()
        self.assertTrue(scanner.verify_ssl)

    def test_opt_out_prints_warning(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            GrafanaFinalScanner(verify_ssl=False)
        self.assertIn('DISABLED', buf.getvalue())


class TestRateLimitBackoff(unittest.TestCase):
    """Rate limiting is per-request and must not use a shared global flag (C-005)."""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_host_of_extracts_netloc(self):
        self.assertEqual(self.scanner._host_of('https://grafana.example.com/x'),
                         'grafana.example.com')
        self.assertEqual(self.scanner._host_of('http://10.0.0.1:3000/'),
                         '10.0.0.1:3000')

    def test_parse_retry_after_integer(self):
        resp = MagicMock()
        resp.headers = {'Retry-After': '45'}
        self.assertEqual(self.scanner._parse_retry_after(resp), 45)

    def test_parse_retry_after_invalid_returns_zero(self):
        resp = MagicMock()
        resp.headers = {'Retry-After': 'soon'}
        self.assertEqual(self.scanner._parse_retry_after(resp), 0)

    def test_parse_retry_after_missing_returns_zero(self):
        resp = MagicMock()
        resp.headers = {}
        self.assertEqual(self.scanner._parse_retry_after(resp), 0)

    def test_no_shared_rate_limited_attribute(self):
        # The global flag that previously aborted whole batch scans is gone.
        self.assertFalse(hasattr(self.scanner, '_rate_limited'))

    @patch('scanner.time.sleep')
    @patch('requests.Session.request')
    def test_rate_limited_response_is_retried(self, mock_request, mock_sleep):
        rl = MagicMock()
        rl.status_code = 429
        rl.headers = {}
        ok = MagicMock()
        ok.status_code = 200
        ok.headers = {}
        mock_request.side_effect = [rl, ok]
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(mock_request.call_count, 2)

    @patch('scanner.time.sleep')
    @patch('requests.Session.request')
    def test_persistent_rate_limit_returns_none(self, mock_request, mock_sleep):
        rl = MagicMock()
        rl.status_code = 429
        rl.headers = {}
        mock_request.return_value = rl
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)


class TestDashboardAuth(unittest.TestCase):
    """Web dashboard must be authenticated and CSRF-protected (C-001)."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def _make_scanner(self):
        return GrafanaFinalScanner(db_path=self.tmp.name)

    def test_open_dashboard_allows_access_without_token(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token=None)
        client = app.test_client()
        self.assertEqual(client.get('/').status_code, 200)
        self.assertEqual(client.get('/targets').status_code, 200)

    def test_protected_dashboard_rejects_missing_token(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        self.assertEqual(client.get('/').status_code, 401)
        self.assertEqual(client.get('/api/stats').status_code, 401)

    def test_protected_dashboard_accepts_bearer_token(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        self.assertEqual(
            client.get('/', headers={'Authorization': 'Bearer s3cr3t'}).status_code, 200)

    def test_protected_dashboard_accepts_query_token(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        self.assertEqual(client.get('/?token=s3cr3t').status_code, 200)

    def test_protected_dashboard_rejects_wrong_token(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        self.assertEqual(
            client.get('/', headers={'Authorization': 'Bearer wrong'}).status_code, 401)

    def test_status_update_requires_csrf(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        headers = {'Authorization': 'Bearer s3cr3t'}
        r = client.post('/api/vulnerabilities/nope/status',
                        json={'status': 'fixed'}, headers=headers)
        self.assertEqual(r.status_code, 403)

    def test_status_update_with_csrf_is_authorized(self):
        scanner = self._make_scanner()
        app = create_web_server(scanner, dashboard_token='s3cr3t')
        client = app.test_client()
        # First request sets the CSRF cookie.
        resp = client.get('/', headers={'Authorization': 'Bearer s3cr3t'})
        set_cookie = resp.headers.get('Set-Cookie', '')
        import re
        m = re.search(r'gfs_csrf=([^;]+)', set_cookie)
        self.assertIsNotNone(m)
        csrf = m.group(1)
        r = client.post('/api/vulnerabilities/nope/status',
                        json={'status': 'fixed'},
                        headers={'Authorization': 'Bearer s3cr3t',
                                 'X-CSRF-Token': csrf})
        # Authorized, but the vulnerability id does not exist -> 404.
        self.assertEqual(r.status_code, 404)


if __name__ == '__main__':
    unittest.main()
