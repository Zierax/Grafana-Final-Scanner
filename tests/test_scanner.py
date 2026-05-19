"""
Unit tests for GrafanaFinalScanner

Tests cover:
- Version comparison and range checking
- CVE version vulnerability detection
- Authentication configuration
- Argument validators
- Report generation helpers
- Response parsing methods
"""

import argparse
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, Mock

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner import GrafanaFinalScanner, _positive_int, Colors


class TestPositiveInt(unittest.TestCase):
    """Test the _positive_int argument validator"""

    def test_valid_positive(self):
        """Valid positive integers should pass"""
        self.assertEqual(_positive_int('1'), 1)
        self.assertEqual(_positive_int('10'), 10)
        self.assertEqual(_positive_int('999'), 999)

    def test_zero_rejected(self):
        """Zero should be rejected"""
        with self.assertRaises(argparse.ArgumentTypeError):
            _positive_int('0')

    def test_negative_rejected(self):
        """Negative numbers should be rejected"""
        with self.assertRaises(argparse.ArgumentTypeError):
            _positive_int('-1')

    def test_non_integer_rejected(self):
        """Non-integer strings should be rejected"""
        with self.assertRaises(ValueError):
            _positive_int('abc')

    def test_float_rejected(self):
        """Float strings should be rejected"""
        with self.assertRaises(ValueError):
            _positive_int('1.5')


class TestGrafanaFinalScannerInit(unittest.TestCase):
    """Test scanner initialization"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_default_values(self):
        """Default initialization values should be correct"""
        self.assertEqual(self.scanner.timeout, 10)
        self.assertFalse(self.scanner.verify_ssl)
        self.assertFalse(self.scanner.verbose)
        self.assertEqual(self.scanner.max_threads, 5)
        self.assertIsNone(self.scanner.grafana_version)
        self.assertEqual(self.scanner.build_info, {})
        self.assertFalse(self.scanner._rate_limited)
        # Verify initial stats
        self.assertEqual(self.scanner.stats['total_checks'], 0)
        self.assertEqual(self.scanner.stats['vulnerabilities_found'], 0)
        self.assertEqual(self.scanner.stats['checks_passed'], 0)
        self.assertEqual(self.scanner.stats['errors'], 0)

    def test_custom_values(self):
        """Custom initialization values should be stored"""
        scanner = GrafanaFinalScanner(
            timeout=30,
            verify_ssl=True,
            verbose=True,
            max_threads=10
        )
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.verify_ssl)
        self.assertTrue(scanner.verbose)
        self.assertEqual(scanner.max_threads, 10)


class TestCompareVersions(unittest.TestCase):
    """Test version comparison logic"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_equal_versions(self):
        """Equal versions should return 0"""
        self.assertEqual(self.scanner.compare_versions('8.0.0', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('11.2.0', '11.2.0'), 0)
        self.assertEqual(self.scanner.compare_versions('5.0.0', '5.0'), 0)

    def test_less_than(self):
        """Version a < version b should return -1"""
        self.assertEqual(self.scanner.compare_versions('8.0.0', '8.0.1'), -1)
        self.assertEqual(self.scanner.compare_versions('8.0.0', '9.0.0'), -1)
        self.assertEqual(self.scanner.compare_versions('7.5.0', '8.0.0'), -1)

    def test_greater_than(self):
        """Version a > version b should return 1"""
        self.assertEqual(self.scanner.compare_versions('8.0.1', '8.0.0'), 1)
        self.assertEqual(self.scanner.compare_versions('9.0.0', '8.0.0'), 1)
        self.assertEqual(self.scanner.compare_versions('11.0.0', '10.9.9'), 1)

    def test_pre_release_tags(self):
        """Pre-release tags should be stripped for comparison"""
        self.assertEqual(self.scanner.compare_versions('8.0.0-beta1', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('11.2.0-rc1', '11.2.0'), 0)


class TestVersionInRange(unittest.TestCase):
    """Test version range checking"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_no_bounds(self):
        """No bounds should return True for any version"""
        self.assertTrue(self.scanner.version_in_range('8.0.0'))

    def test_empty_string_returns_false(self):
        """Empty version string should return False"""
        self.assertFalse(self.scanner.version_in_range(''))

    def test_min_bound_only(self):
        """Min bound inclusive should work correctly"""
        self.assertTrue(self.scanner.version_in_range('8.0.0', '8.0.0'))
        self.assertTrue(self.scanner.version_in_range('9.0.0', '8.0.0'))
        self.assertFalse(self.scanner.version_in_range('7.0.0', '8.0.0'))

    def test_max_bound_only(self):
        """Max bound inclusive should work correctly"""
        self.assertTrue(self.scanner.version_in_range('8.0.0', max_v='8.0.0'))
        self.assertTrue(self.scanner.version_in_range('7.0.0', max_v='8.0.0'))
        self.assertFalse(self.scanner.version_in_range('9.0.0', max_v='8.0.0'))

    def test_both_bounds(self):
        """Both bounds inclusive should work correctly"""
        self.assertTrue(self.scanner.version_in_range('8.0.0', '8.0.0', '8.3.0'))
        self.assertTrue(self.scanner.version_in_range('8.2.5', '8.0.0', '8.3.0'))
        self.assertTrue(self.scanner.version_in_range('8.3.0', '8.0.0', '8.3.0'))
        self.assertFalse(self.scanner.version_in_range('7.0.0', '8.0.0', '8.3.0'))
        self.assertFalse(self.scanner.version_in_range('9.0.0', '8.0.0', '8.3.0'))


class TestIsVersionVulnerable(unittest.TestCase):
    """Test CVE-specific version vulnerability checks"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_unknown_version_default_true(self):
        """Unknown version should default to vulnerable"""
        self.scanner.grafana_version = None
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))

    def test_cve_2021_43798(self):
        """CVE-2021-43798: Affects 8.0.0-8.3.0"""
        versions_vulnerable = ['8.0.0', '8.1.0', '8.2.5', '8.3.0']
        versions_patched = ['8.3.1', '9.0.0', '7.0.0', '11.0.0']

        for v in versions_vulnerable:
            self.scanner.grafana_version = v
            self.assertTrue(
                self.scanner.is_version_vulnerable('CVE-2021-43798'),
                f"{v} should be vulnerable to CVE-2021-43798"
            )

        for v in versions_patched:
            self.scanner.grafana_version = v
            self.assertFalse(
                self.scanner.is_version_vulnerable('CVE-2021-43798'),
                f"{v} should be patched for CVE-2021-43798"
            )

    def test_cve_2024_9264(self):
        """CVE-2024-9264: Affects 11.0.0-11.0.5, 11.1.0-11.1.6, 11.2.0-11.2.1"""
        self.scanner.grafana_version = '11.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))

        self.scanner.grafana_version = '11.0.5'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))

        self.scanner.grafana_version = '11.2.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))

        self.scanner.grafana_version = '11.2.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))

        self.scanner.grafana_version = '12.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))

    def test_cve_2018_15727(self):
        """CVE-2018-15727: Affects <= 5.2.2"""
        self.scanner.grafana_version = '5.2.2'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2018-15727'))

        self.scanner.grafana_version = '5.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2018-15727'))

        self.scanner.grafana_version = '5.2.3'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2018-15727'))

        self.scanner.grafana_version = '6.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2018-15727'))

    def test_cve_2023_50164(self):
        """CVE-2023-50164: Affects < 9.2.10, 9.3.x < 9.3.6, 9.4.x < 9.4.1"""
        self.scanner.grafana_version = '9.2.9'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))

        self.scanner.grafana_version = '9.2.10'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-50164'))

        self.scanner.grafana_version = '9.3.5'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))

        self.scanner.grafana_version = '9.3.6'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-50164'))

        self.scanner.grafana_version = '9.4.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))

    def test_cve_2023_1410(self):
        """CVE-2023-1410: Affects >= 8.0.0, < 9.2.17, < 9.3.5"""
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))

        self.scanner.grafana_version = '9.2.16'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))

        self.scanner.grafana_version = '9.2.17'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))

        self.scanner.grafana_version = '7.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))

    def test_cve_2023_2183(self):
        """CVE-2023-2183: Affects 8.x < 8.5.21, 9.x < 9.4.13"""
        self.scanner.grafana_version = '8.5.20'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))

        self.scanner.grafana_version = '8.5.21'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))

        self.scanner.grafana_version = '9.2.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))

    def test_cve_2022_32275(self):
        """CVE-2022-32275: Affects exactly 8.4.3"""
        self.scanner.grafana_version = '8.4.3'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2022-32275'))

        self.scanner.grafana_version = '8.4.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2022-32275'))

        self.scanner.grafana_version = '8.5.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2022-32275'))

    def test_cve_2021_27358(self):
        """CVE-2021-27358: Affects 6.7.3-7.4.1"""
        self.scanner.grafana_version = '6.7.3'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-27358'))

        self.scanner.grafana_version = '7.4.1'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-27358'))

        self.scanner.grafana_version = '6.7.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-27358'))

        self.scanner.grafana_version = '7.5.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-27358'))

    def test_unknown_cve_returns_true(self):
        """Unknown CVE ID should default to vulnerable"""
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-UNKNOWN-0000'))


class TestAuthConfiguration(unittest.TestCase):
    """Test authentication configuration"""

    def test_bearer_token(self):
        """Bearer token should set Authorization header"""
        scanner = GrafanaFinalScanner(auth_token='glsa_test_token_123')
        auth_header = scanner.session.headers.get('Authorization', '')
        self.assertEqual(auth_header, 'Bearer glsa_test_token_123')

    def test_basic_auth(self):
        """Basic auth should set session auth tuple"""
        scanner = GrafanaFinalScanner(auth_user='admin', auth_pass='password123')
        self.assertEqual(scanner.session.auth, ('admin', 'password123'))

    def test_both_auth_methods(self):
        """Both auth methods should be configurable simultaneously"""
        scanner = GrafanaFinalScanner(
            auth_token='test_token',
            auth_user='admin',
            auth_pass='pass'
        )
        self.assertEqual(scanner.session.headers.get('Authorization'), 'Bearer test_token')
        self.assertEqual(scanner.session.auth, ('admin', 'pass'))

    def test_no_auth(self):
        """No auth should leave headers and auth unset"""
        scanner = GrafanaFinalScanner()
        self.assertIsNone(scanner.session.headers.get('Authorization'))
        self.assertIsNone(scanner.session.auth)

    @patch('builtins.print')
    def test_auth_logging(self, mock_print):
        """Auth configuration should log appropriate messages"""
        GrafanaFinalScanner(auth_token='test')
        GrafanaFinalScanner(auth_user='u', auth_pass='p')


class TestParseMethods(unittest.TestCase):
    """Test version parsing from responses"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_parse_frontend_settings(self):
        """Parse version from frontend settings JSON"""
        response = MagicMock()
        response.json.return_value = {
            'buildInfo': {
                'version': '8.2.5',
                'commit': 'abc123',
                'buildstamp': 1234567890
            }
        }

        version = self.scanner._parse_frontend_settings(response)
        self.assertEqual(version, '8.2.5')
        self.assertEqual(self.scanner.build_info['version'], '8.2.5')

    def test_parse_frontend_settings_no_version(self):
        """Frontend settings without version should return None"""
        response = MagicMock()
        response.json.return_value = {'some': 'data'}
        version = self.scanner._parse_frontend_settings(response)
        self.assertIsNone(version)

    def test_parse_health_endpoint(self):
        """Parse version from health endpoint"""
        response = MagicMock()
        response.json.return_value = {'version': '9.0.0', 'database': 'ok'}
        version = self.scanner._parse_health_endpoint(response)
        self.assertEqual(version, '9.0.0')

    def test_parse_version_header(self):
        """Parse version from response headers"""
        response = MagicMock()
        response.headers = {'X-Grafana-Version': '11.2.0'}
        version = self.scanner._parse_version_header_only(response)
        self.assertEqual(version, '11.2.0')

    def test_parse_version_header_invalid(self):
        """Invalid header values should return None"""
        response = MagicMock()
        response.headers = {'X-Grafana-Version': 'abc'}
        version = self.scanner._parse_version_header_only(response)
        self.assertIsNone(version)

    def test_parse_login_page_json_pattern(self):
        """Parse version from login page JSON in HTML"""
        response = MagicMock()
        response.text = '<script>"version": "8.2.0"</script>'
        response.status_code = 200

        # Test the regex directly
        import re
        pattern = r'"(?:version|grafanaVersion)"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+(?:\-beta\d+)?)"'
        match = re.search(pattern, response.text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), '8.2.0')


class TestCheckRateLimit(unittest.TestCase):
    """Test rate limit detection"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_status_429(self):
        """Status 429 should be detected as rate limit"""
        response = MagicMock()
        response.status_code = 429
        response.headers = {}
        self.assertTrue(self.scanner._check_rate_limit(response))
        self.assertTrue(self.scanner._rate_limited)

    def test_x_rate_limit_remaining_zero(self):
        """X-RateLimit-Remaining: 0 should be detected"""
        response = MagicMock()
        response.status_code = 200
        response.headers = {'X-RateLimit-Remaining': '0'}
        self.assertTrue(self.scanner._check_rate_limit(response))
        self.assertTrue(self.scanner._rate_limited)

    def test_retry_after_header(self):
        """Retry-After header should be detected"""
        response = MagicMock()
        response.status_code = 200
        response.headers = {'Retry-After': '60'}
        self.assertTrue(self.scanner._check_rate_limit(response))
        self.assertTrue(self.scanner._rate_limited)

    def test_normal_response_not_rate_limited(self):
        """Normal response should not be rate limited"""
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        self.assertFalse(self.scanner._check_rate_limit(response))


class TestHTMLReportGeneration(unittest.TestCase):
    """Test HTML report generation"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.sample_results = [
            {
                'url': 'https://grafana.example.com',
                'version': '8.2.5',
                'timestamp': '2025-01-01T00:00:00',
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2021-43798',
                        'severity': 'CRITICAL',
                        'message': 'Directory traversal confirmed',
                        'test_url': 'https://grafana.example.com/test'
                    }
                ],
                'configuration': {},
                'statistics': {},
                'accessible': True,
                'build_info': {}
            }
        ]

    @patch('builtins.print')
    def test_json_report_saved(self, mock_print):
        """JSON report should be saved correctly"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            self.scanner._save_json_report(self.sample_results, temp_path)
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['url'], 'https://grafana.example.com')
            self.assertEqual(data[0]['vulnerabilities'][0]['cve_id'], 'CVE-2021-43798')
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_csv_report_saved(self, mock_print):
        """CSV report should be saved correctly"""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            temp_path = f.name

        try:
            self.scanner._save_csv_report(self.sample_results, temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('CVE-2021-43798', content)
            self.assertIn('CRITICAL', content)
            self.assertIn('grafana.example.com', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_html_report_saved(self, mock_print):
        """HTML report should be saved correctly"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            self.scanner._save_html_report(self.sample_results, temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<html', content)
            self.assertIn('CVE-2021-43798', content)
            self.assertIn('CRITICAL', content)
            self.assertIn('grafana.example.com', content)
            # Verify HTML is properly structured
            self.assertIn('</html>', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_generate_report_uses_next_available_numbered_filename(self, mock_print):
        """Existing report files should force the next numbered basename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = os.path.join(temp_dir, 'report')

            for extension in ('.json', '.html', '.csv'):
                with open(f'{base_path}_1001{extension}', 'w', encoding='utf-8') as f:
                    f.write('existing')

            self.scanner.generate_report(self.sample_results, base_path)

            for extension in ('.json', '.html', '.csv'):
                self.assertTrue(os.path.exists(f'{base_path}_1002{extension}'))
                self.assertTrue(os.path.exists(f'{base_path}_1001{extension}'))

    @patch('scanner.time.sleep', return_value=None)
    def test_scan_from_file_returns_partial_results_on_interrupt(self, mock_sleep):
        """Batch scans should return completed targets when interrupted"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('https://one.example.com\n')
            f.write('https://two.example.com\n')
            temp_path = f.name

        try:
            scan_results = [
                {
                    'url': 'https://one.example.com',
                    'timestamp': '2025-01-01T00:00:00',
                    'version': None,
                    'build_info': {},
                    'vulnerabilities': [],
                    'configuration': {},
                    'statistics': {},
                    'accessible': True,
                    'interrupted': False,
                },
                KeyboardInterrupt(),
            ]

            with patch.object(GrafanaFinalScanner, 'scan_target', side_effect=scan_results):
                results = self.scanner.scan_from_file(temp_path)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['url'], 'https://one.example.com')
        finally:
            os.unlink(temp_path)


class TestSafeRequest(unittest.TestCase):
    """Test safe request wrapper"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('requests.Session.request')
    def test_successful_request(self, mock_request):
        """Successful request should return response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)

    @patch('requests.Session.request')
    def test_rate_limited_request_skipped(self, mock_request):
        """If already rate limited, requests should be skipped"""
        self.scanner._rate_limited = True
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)
        mock_request.assert_not_called()


class TestColors(unittest.TestCase):
    """Test Colors class constants"""

    def test_colors_defined(self):
        """All required color constants should be defined"""
        required = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'RESET', 'BOLD', 'DIM']
        for color in required:
            self.assertTrue(hasattr(Colors, color), f"Missing color: {color}")

    def test_colors_are_strings(self):
        """Color constants should be strings"""
        self.assertIsInstance(Colors.CRITICAL, str)
        self.assertIsInstance(Colors.HIGH, str)
        self.assertIsInstance(Colors.RESET, str)


class TestSecurityConfig(unittest.TestCase):
    """Test security configuration checking"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_check_security_headers_present(self, mock_request):
        """Security headers check should detect present headers"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000',
        }
        mock_request.return_value = mock_response

        results = self.scanner.check_security_headers('https://example.com')
        self.assertIn('Content-Security-Policy', results)
        self.assertTrue(results['Content-Security-Policy']['present'])
        self.assertIn('X-Frame-Options', results)
        self.assertTrue(results['X-Frame-Options']['present'])

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_check_security_headers_missing(self, mock_request):
        """Security headers check should detect missing headers"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        results = self.scanner.check_security_headers('https://example.com')
        missing_count = sum(1 for h, info in results.items() if not info.get('present'))
        self.assertGreater(missing_count, 0)


if __name__ == '__main__':
    unittest.main()
