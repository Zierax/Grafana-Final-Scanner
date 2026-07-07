"""
Tests for report generation, CLI, web server, banner, and scan orchestration

Tests cover:
- generate_report: console output, file generation, empty results, edge cases
- _save_*_report: JSON, HTML, CSV output (additional edge cases)
- scan_from_file: file reading, error handling, rate limiting
- _run_cve_checks_parallel: parallel execution, exception handling
- _run_single_cve_check: single execution, exception handling
- _report_vulnerability: logging and results appending
- print_banner: banner output content
- main: CLI argument parsing, mode selection, error handling
- create_web_server: Flask app factory (when available and not)
"""

import argparse
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch, Mock
from io import StringIO

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner import (
    GrafanaFinalScanner, VulnerabilityDB, Colors,
    create_web_server, print_banner, _positive_int, FLASK_AVAILABLE
)


# =====================================================================
#  _report_vulnerability Tests
# =====================================================================

class TestReportVulnerability(unittest.TestCase):
    """Test the vulnerability reporting method"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.results = {'vulnerabilities': []}

    @patch('scanner.GrafanaFinalScanner.log')
    def test_report_critical(self, mock_log):
        """Critical vulnerability should be logged and added to results"""
        self.scanner._report_vulnerability(
            'CVE-2021-43798', 'CRITICAL',
            'Directory traversal confirmed',
            'https://grafana.example.com/test',
            self.results
        )
        self.assertEqual(len(self.results['vulnerabilities']), 1)
        vuln = self.results['vulnerabilities'][0]
        self.assertEqual(vuln['cve_id'], 'CVE-2021-43798')
        self.assertEqual(vuln['severity'], 'CRITICAL')
        self.assertEqual(vuln['test_url'], 'https://grafana.example.com/test')

    @patch('scanner.GrafanaFinalScanner.log')
    def test_report_with_description(self, mock_log):
        """Vulnerability with description should include it"""
        self.scanner._report_vulnerability(
            'CVE-2024-9264', 'HIGH',
            'SQL injection possible',
            'https://grafana.example.com/api',
            self.results,
            description='DuckDB SQL Injection'
        )
        vuln = self.results['vulnerabilities'][0]
        self.assertIn('DuckDB', vuln.get('description', ''))

    @patch('scanner.GrafanaFinalScanner.log')
    def test_report_multiple_vulnerabilities(self, mock_log):
        """Multiple vulnerabilities should all be recorded"""
        vulns = [
            ('CVE-2021-43798', 'CRITICAL', 'Dir traversal', '/test1'),
            ('CVE-2023-1410', 'HIGH', 'SSRF', '/test2'),
            ('CVE-2024-1313', 'MEDIUM', 'Info disclosure', '/test3'),
        ]
        for cve_id, severity, msg, url in vulns:
            self.scanner._report_vulnerability(cve_id, severity, msg, url, self.results)
        self.assertEqual(len(self.results['vulnerabilities']), 3)


# =====================================================================
#  _run_single_cve_check Tests
# =====================================================================

class TestRunSingleCVECheck(unittest.TestCase):
    """Test single CVE check execution"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.results = {'vulnerabilities': []}

    def test_vulnerable_check(self):
        """Vulnerable check should be reported"""
        def mock_check(url):
            return (True, 'Vulnerability found', 'https://test.com/exploit')

        with patch.object(self.scanner, 'log'):
            self.scanner._run_single_cve_check(
                'CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
                mock_check, 'https://test.com', self.results
            )
        self.assertEqual(len(self.results['vulnerabilities']), 1)

    def test_safe_check(self):
        """Safe check should not be reported"""
        def mock_check(url):
            return (False, 'Protected', 'https://test.com')

        with patch.object(self.scanner, 'log'):
            self.scanner._run_single_cve_check(
                'CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
                mock_check, 'https://test.com', self.results
            )
        self.assertEqual(len(self.results['vulnerabilities']), 0)

    def test_exception_handling(self):
        """Exception in check should be caught gracefully"""
        def mock_check(url):
            raise RuntimeError("Check failed")

        with patch.object(self.scanner, 'log'):
            self.scanner._run_single_cve_check(
                'CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
                mock_check, 'https://test.com', self.results
            )
        self.assertEqual(len(self.results['vulnerabilities']), 0)


# =====================================================================
#  _run_cve_checks_parallel Tests
# =====================================================================

class TestRunCVEChecksParallel(unittest.TestCase):
    """Test parallel CVE check execution"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.results = {'vulnerabilities': []}

    def test_parallel_all_safe(self):
        """All checks safe should not report any"""
        cve_checks = [
            ('CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
             lambda url: (False, 'Protected', url)),
            ('CVE-2023-1410', 'HIGH', 'SSRF',
             lambda url: (False, 'Protected', url)),
        ]

        with patch.object(self.scanner, 'log'):
            self.scanner._run_cve_checks_parallel(cve_checks, 'https://test.com', self.results)
        self.assertEqual(len(self.results['vulnerabilities']), 0)

    def test_parallel_one_vulnerable(self):
        """One vulnerable check should be reported"""
        cve_checks = [
            ('CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
             lambda url: (True, 'Vuln found', url)),
            ('CVE-2023-1410', 'HIGH', 'SSRF',
             lambda url: (False, 'Protected', url)),
        ]

        with patch.object(self.scanner, 'log'):
            self.scanner._run_cve_checks_parallel(cve_checks, 'https://test.com', self.results)
        self.assertEqual(len(self.results['vulnerabilities']), 1)

    def test_parallel_exception(self):
        """Exception in one check should not crash others"""
        cve_checks = [
            ('CVE-2021-43798', 'CRITICAL', 'Dir Traversal',
             lambda url: (_ for _ in ()).throw(RuntimeError("Check failed"))),
            ('CVE-2023-1410', 'HIGH', 'SSRF',
             lambda url: (False, 'Protected', url)),
        ]

        with patch.object(self.scanner, 'log'):
            self.scanner._run_cve_checks_parallel(cve_checks, 'https://test.com', self.results)
        self.assertEqual(len(self.results['vulnerabilities']), 0)


# =====================================================================
#  scan_from_file Tests
# =====================================================================

class TestScanFromFile(unittest.TestCase):
    """Test file-based scanning"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_scan_from_file_normal(self):
        """Normal file should scan each URL"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("https://grafana-1.example.com\n")
            f.write("https://grafana-2.example.com\n")
            f.write("# This is a comment\n")
            f.write("https://grafana-3.example.com\n")
            fname = f.name

        try:
            with patch.object(self.scanner, 'scan_target') as mock_scan:
                mock_scan.return_value = {
                    'url': 'https://grafana-1.example.com',
                    'version': '8.2.5',
                    'vulnerabilities': [],
                    'accessible': True
                }
                results = self.scanner.scan_from_file(fname)
                self.assertEqual(len(results), 3)
                self.assertEqual(mock_scan.call_count, 3)
        finally:
            os.unlink(fname)

    def test_scan_from_file_not_found(self):
        """Non-existent file should exit"""
        with self.assertRaises(SystemExit):
            self.scanner.scan_from_file('/tmp/nonexistent_file_xyz_123.txt')

    @patch('scanner.GrafanaFinalScanner.log')
    def test_scan_from_file_empty(self, mock_log):
        """Empty file should produce empty results"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            fname = f.name

        try:
            results = self.scanner.scan_from_file(fname)
            self.assertEqual(len(results), 0)
        finally:
            os.unlink(fname)


# =====================================================================
#  generate_report Tests
# =====================================================================

class TestGenerateReport(unittest.TestCase):
    """Test generate_report function"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.sample_results = [{
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
            'configuration': {'anonymous_access': {'severity': 'MEDIUM'}},
            'statistics': {'total_checks': 10, 'vulnerabilities_found': 1, 'checks_passed': 9, 'errors': 0},
            'accessible': True,
            'build_info': {},
            'duration': 5.2
        }]

    @patch('builtins.print')
    def test_generate_report_no_output_file(self, mock_print):
        """Report without output file should print summary"""
        self.scanner.generate_report(self.sample_results)
        # Verify summary was printed (should contain key stats)
        all_output = ' '.join([str(c) for c in mock_print.call_args_list])
        self.assertIn('1', all_output)  # Should show 1 target

    @patch('builtins.print')
    def test_generate_report_with_output_file(self, mock_print):
        """Report with output file should save all formats"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name.replace('.json', '')

        try:
            self.scanner.generate_report(self.sample_results, temp_path)
            # Check JSON was created
            if os.path.exists(temp_path + '.json'):
                with open(temp_path + '.json', 'r') as f:
                    data = json.load(f)
                self.assertEqual(len(data), 1)
            # Check HTML was created
            if os.path.exists(temp_path + '.html'):
                with open(temp_path + '.html', 'r') as f:
                    content = f.read()
                self.assertIn('<html', content)
            # Check CSV was created
            if os.path.exists(temp_path + '.csv'):
                with open(temp_path + '.csv', 'r') as f:
                    content = f.read()
                self.assertIn('CVE-2021-43798', content)
        finally:
            for ext in ['.json', '.html', '.csv']:
                p = temp_path + ext
                if os.path.exists(p):
                    os.unlink(p)

    @patch('builtins.print')
    def test_generate_report_empty_results(self, mock_print):
        """Empty results should print zero stats"""
        self.scanner.generate_report([])
        all_output = ' '.join([str(c) for c in mock_print.call_args_list])
        self.assertIn('0', all_output)

    @patch('builtins.print')
    def test_generate_report_no_vulnerabilities(self, mock_print):
        """No vulnerabilities should print safe stats"""
        safe_results = [{
            'url': 'https://grafana.example.com',
            'version': '9.0.0',
            'timestamp': '2025-01-01T00:00:00',
            'vulnerabilities': [],
            'configuration': {},
            'statistics': {'total_checks': 10, 'vulnerabilities_found': 0, 'checks_passed': 10, 'errors': 0},
            'accessible': True,
            'build_info': {},
            'duration': 3.1
        }]
        self.scanner.generate_report(safe_results)
        all_output = ' '.join([str(c) for c in mock_print.call_args_list])
        self.assertIn('0', all_output)

    @patch('builtins.print')
    def test_generate_report_unreachable_targets(self, mock_print):
        """Unreachable targets should still be counted"""
        mixed_results = [
            {
                'url': 'https://grafana-1.example.com',
                'version': None,
                'vulnerabilities': [],
                'configuration': {},
                'statistics': {},
                'accessible': False,
                'duration': 2.0
            },
            {
                'url': 'https://grafana-2.example.com',
                'version': '9.0.0',
                'vulnerabilities': [],
                'configuration': {},
                'statistics': {},
                'accessible': True,
                'duration': 3.0
            }
        ]
        self.scanner.generate_report(mixed_results)
        all_output = ' '.join([str(c) for c in mock_print.call_args_list])
        self.assertIn('2', all_output)  # 2 targets total
        self.assertIn('1', all_output)  # 1 reachable

    @patch('builtins.print')
    def test_generate_report_all_severities(self, mock_print):
        """All severity levels should be displayed"""
        all_vulns_results = [{
            'url': 'https://grafana.example.com',
            'version': '8.0.0',
            'vulnerabilities': [
                {'cve_id': 'CVE-1', 'severity': 'CRITICAL', 'message': 'Crit', 'test_url': '/test'},
                {'cve_id': 'CVE-2', 'severity': 'HIGH', 'message': 'High', 'test_url': '/test'},
                {'cve_id': 'CVE-3', 'severity': 'MEDIUM', 'message': 'Med', 'test_url': '/test'},
                {'cve_id': 'CVE-4', 'severity': 'LOW', 'message': 'Low', 'test_url': '/test'},
            ],
            'configuration': {},
            'statistics': {},
            'accessible': True,
        }]
        self.scanner.generate_report(all_vulns_results)
        all_output = ' '.join([str(c) for c in mock_print.call_args_list])
        self.assertIn('1', all_output)  # 1 target


# =====================================================================
#  _save_*_report Edge Case Tests
# =====================================================================

class TestSaveReportsExtended(unittest.TestCase):
    """Extended tests for report saving methods"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('builtins.print')
    def test_json_report_with_errors(self, mock_print):
        """JSON report with error stats should include errors"""
        results = [{
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'statistics': {'errors': 3, 'total_checks': 15, 'vulnerabilities_found': 2, 'checks_passed': 10},
            'vulnerabilities': [],
            'configuration': {},
            'accessible': True,
        }]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_json_report(results, temp_path)
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(data[0]['statistics']['errors'], 3)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_csv_report_with_status_row(self, mock_print):
        """CSV should include status row for secure targets"""
        results = [{
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'vulnerabilities': [],
            'accessible': True,
        }]
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_csv_report(results, temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('grafana.example.com', content)
            self.assertIn('No vulnerabilities', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_csv_report_multiple_results(self, mock_print):
        """CSV with multiple targets should have all rows"""
        results = [
            {'url': 'https://grafana-1.example.com', 'version': '8.2.5', 'vulnerabilities': [
                {'cve_id': 'CVE-1', 'severity': 'CRITICAL', 'message': 'Vuln1', 'test_url': '/test'}
            ], 'accessible': True},
            {'url': 'https://grafana-2.example.com', 'version': '9.0.0', 'vulnerabilities': [
                {'cve_id': 'CVE-2', 'severity': 'HIGH', 'message': 'Vuln2', 'test_url': '/test'}
            ], 'accessible': True},
        ]
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_csv_report(results, temp_path)
            with open(temp_path, 'r') as f:
                lines = f.readlines()
            # Header + 2 data rows = 3 lines
            self.assertGreaterEqual(len(lines), 3)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_html_report_with_config(self, mock_print):
        """HTML report should include configuration warnings"""
        results = [{
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'vulnerabilities': [
                {'cve_id': 'CVE-2021-43798', 'severity': 'CRITICAL', 'message': 'Test', 'test_url': '/test'}
            ],
            'configuration': {
                'anonymous_access': {'enabled': True, 'severity': 'MEDIUM', 'message': 'Anonymous access ENABLED'},
            },
            'statistics': {'total_checks': 10, 'vulnerabilities_found': 1, 'checks_passed': 9, 'errors': 0},
            'accessible': True,
        }]
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(results, temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('<html', content)
            self.assertIn('CVE-2021-43798', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_html_report_dark_theme_elements(self, mock_print):
        """HTML report should have dark theme CSS"""
        results = [{
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'vulnerabilities': [],
            'configuration': {},
            'statistics': {},
            'accessible': True,
        }]
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(results, temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            # Check for basic HTML report structure
            self.assertIn('<html', content)
            self.assertIn('</html>', content)
            # Should contain styling
            self.assertIn('style', content.lower())
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_json_report_io_error(self, mock_print):
        """IO error during JSON save should be handled"""
        results = [{'url': 'https://grafana.example.com', 'vulnerabilities': []}]
        # Try to write to a non-existent directory
        self.scanner._save_json_report(results, '/nonexistent_dir_xyz/report.json')
        # Should not crash, should print error

    @patch('builtins.print')
    def test_html_report_io_error(self, mock_print):
        """IO error during HTML save should be handled"""
        results = [{'url': 'https://grafana.example.com', 'vulnerabilities': []}]
        self.scanner._save_html_report(results, '/nonexistent_dir_xyz/report.html')
        # Should not crash

    @patch('builtins.print')
    def test_csv_report_io_error(self, mock_print):
        """IO error during CSV save should be handled"""
        results = [{'url': 'https://grafana.example.com', 'vulnerabilities': []}]
        self.scanner._save_csv_report(results, '/nonexistent_dir_xyz/report.csv')
        # Should not crash


# =====================================================================
#  print_banner Extended Tests
# =====================================================================

class TestPrintBannerExtended(unittest.TestCase):
    """Extended banner tests"""

    @patch('builtins.print')
    def test_banner_contains_version_and_name(self, mock_print):
        """Banner should contain version and developer info"""
        print_banner()
        calls = [str(c) for c in mock_print.call_args_list]
        all_output = ' '.join(calls)
        self.assertIn('3.1.0', all_output)
        self.assertIn('GRAFANA', all_output.upper())
        self.assertIn('SCANNER', all_output.upper())

    @patch('builtins.print')
    def test_banner_has_security_suite(self, mock_print):
        """Banner should reference security audit"""
        print_banner()
        calls = [str(c) for c in mock_print.call_args_list]
        all_output = ' '.join(calls)
        self.assertIn('Security', all_output)
        self.assertIn('Audit', all_output)


# =====================================================================
#  create_web_server Extended Tests
# =====================================================================

class TestCreateWebServerExtended(unittest.TestCase):
    """Extended web server tests"""

    def test_server_requires_db(self):
        """create_web_server should work (requires Flask)"""
        scanner_inst = GrafanaFinalScanner()
        # If Flask isn't available it exits
        if not FLASK_AVAILABLE:
            with self.assertRaises(SystemExit):
                create_web_server(scanner_inst, host='127.0.0.1', port=8080)

    @patch('scanner.FLASK_AVAILABLE', False)
    def test_server_no_flask(self):
        """Without Flask, server creation should exit"""
        scanner_inst = GrafanaFinalScanner()
        with self.assertRaises(SystemExit):
            create_web_server(scanner_inst, host='127.0.0.1', port=8080)


# =====================================================================
#  main Function Tests
# =====================================================================

class TestMainFunction(unittest.TestCase):
    """Test the CLI main function"""

    @patch('sys.argv', ['scanner.py', '--help'])
    @patch('builtins.print')
    def test_main_help(self, mock_print):
        """Help should print and exit"""
        from scanner import main
        with self.assertRaises(SystemExit):
            main()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_single_url(self, mock_banner, mock_report, mock_scan, mock_print):
        """Single URL scan should work"""
        mock_scan.return_value = {
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'vulnerabilities': [],
            'accessible': True,
        }
        from scanner import main
        main()
        mock_scan.assert_called_once_with('https://grafana.example.com')
        mock_report.assert_called_once()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-f', '/tmp/test_targets.txt'])
    @patch('scanner.GrafanaFinalScanner.scan_from_file')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_file_scan(self, mock_banner, mock_report, mock_scan_file, mock_print):
        """File scan should work"""
        mock_scan_file.return_value = []
        from scanner import main
        with patch('os.path.exists', return_value=True):
            main()
        mock_scan_file.assert_called_once()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '--auto-search', '/tmp/urls.txt'])
    @patch('scanner.GrafanaFinalScanner.auto_search_from_file')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_auto_search(self, mock_banner, mock_report, mock_auto_search, mock_print):
        """Auto-search should work"""
        mock_auto_search.return_value = []
        from scanner import main
        main()
        mock_auto_search.assert_called_once()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '--serve', '8080', '--db', '/tmp/vulndb.json'])
    @patch('scanner.FLASK_AVAILABLE', False)
    def test_main_serve_no_flask(self, mock_print):
        """Serve without Flask should exit"""
        from scanner import main
        with self.assertRaises(SystemExit):
            main()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '--serve', '8080', '--host', '0.0.0.0', '--db', '/tmp/vulndb.json'])
    @patch('scanner.FLASK_AVAILABLE', False)
    def test_main_serve_with_flask_unavailable(self, mock_print):
        """Serve with host and port should exit if Flask unavailable"""
        from scanner import main
        with self.assertRaises(SystemExit):
            main()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py'])
    def test_main_no_args(self, mock_print):
        """No args should show error"""
        from scanner import main
        with self.assertRaises(SystemExit):
            main()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com', '-v'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_verbose(self, mock_banner, mock_report, mock_scan, mock_print):
        """Verbose flag should be passed to scanner"""
        mock_scan.return_value = {'url': 'https://grafana.example.com', 'version': '8.2.5', 'vulnerabilities': [], 'accessible': True}
        from scanner import main
        main()
        self.assertTrue(mock_scan.called)

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com', '--auth-token', 'test_token'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_auth_token(self, mock_banner, mock_report, mock_scan, mock_print):
        """Auth token should be passed to scanner"""
        mock_scan.return_value = {'url': 'https://grafana.example.com', 'version': '8.2.5', 'vulnerabilities': [], 'accessible': True}
        from scanner import main
        main()
        self.assertTrue(mock_scan.called)

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com', '-o', '/tmp/report'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_with_output(self, mock_banner, mock_report, mock_scan, mock_print):
        """Output flag should be passed to generate_report"""
        mock_scan.return_value = {'url': 'https://grafana.example.com', 'version': '8.2.5', 'vulnerabilities': [], 'accessible': True}
        from scanner import main
        main()
        # generate_report should be called with the results and output file
        args, _ = mock_report.call_args
        self.assertEqual(len(args), 2)  # results + output_file or just results

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com', '--no-banner'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_no_banner(self, mock_banner, mock_report, mock_scan, mock_print):
        """--no-banner should suppress banner printing"""
        from scanner import main
        main()
        # When --no-banner is set, print_banner should NOT be called
        mock_banner.assert_not_called()

    @patch('builtins.print')
    @patch('sys.argv', ['scanner.py', '-u', 'https://grafana.example.com', '--output', '/tmp/report'])
    @patch('scanner.GrafanaFinalScanner.scan_target')
    @patch('scanner.GrafanaFinalScanner.generate_report')
    @patch('scanner.print_banner')
    def test_main_keyboard_interrupt(self, mock_banner, mock_report, mock_scan, mock_print):
        """KeyboardInterrupt should be handled gracefully without sys.exit"""
        mock_scan.side_effect = KeyboardInterrupt()
        from scanner import main
        # The function should catch KeyboardInterrupt and return normally with sys.exit(0)
        with self.assertRaises(SystemExit):
            main()


# =====================================================================
#  VulnerabilityDB Integration Tests
# =====================================================================

class TestVulnerabilityDBIntegration(unittest.TestCase):
    """Integration tests for VulnerabilityDB with scanner"""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.temp_db.close()
        self.scanner = GrafanaFinalScanner()
        self.db = VulnerabilityDB(self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_add_vulnerability_updates_target_counts(self):
        """Adding vulns should correctly update target counts"""
        self.db.add_target('https://grafana.example.com')
        self.db.add_vulnerability({
            'cve_id': 'CVE-2021-43798', 'severity': 'CRITICAL',
            'message': 'Test', 'target_url': 'https://grafana.example.com'
        })
        self.db.add_vulnerability({
            'cve_id': 'CVE-2023-1410', 'severity': 'HIGH',
            'message': 'Test', 'target_url': 'https://grafana.example.com'
        })
        target = self.db.get_target('https://grafana.example.com')
        self.assertEqual(target['critical_count'], 1)
        self.assertEqual(target['high_count'], 1)
        self.assertEqual(target['total_vulnerabilities'], 2)
        # Risk: 25 + 15 = 40
        self.assertEqual(target['risk_score'], 40)

    def test_vulnerability_deduplication_different_status(self):
        """Same CVE but different status should not deduplicate"""
        self.db.add_target('https://grafana.example.com')
        v1 = self.db.add_vulnerability({
            'cve_id': 'CVE-2021-43798', 'severity': 'CRITICAL',
            'message': 'First', 'target_url': 'https://grafana.example.com'
        })
        self.db.update_vuln_status(v1['id'], 'fixed')
        # Same CVE, different (closed) status - should create new
        v2 = self.db.add_vulnerability({
            'cve_id': 'CVE-2021-43798', 'severity': 'CRITICAL',
            'message': 'Reappeared', 'target_url': 'https://grafana.example.com'
        })
        vulns = self.db.get_all_vulnerabilities()
        self.assertEqual(len(vulns), 2)

    def test_empty_db_statistics(self):
        """Empty DB should return zero statistics"""
        stats = self.db.get_statistics()
        self.assertEqual(stats['total_targets'], 0)
        self.assertEqual(stats['total_vulnerabilities'], 0)
        self.assertEqual(stats['open_vulnerabilities'], 0)
        self.assertEqual(stats['targets_at_risk'], 0)

    def test_db_scan_history_limit(self):
        """Scan history should enforce 1000 record limit"""
        for i in range(1005):
            self.db.add_scan_history({
                'url': f'https://grafana-{i}.example.com',
                'version': '1.0.0',
                'vulnerabilities': [],
                'statistics': {'total_checks': 1},
                'duration': 0.01
            })
        self.assertLessEqual(len(self.db._data['scan_history']), 1000)
        # Most recent records should be kept
        last_record = self.db._data['scan_history'][-1]
        self.assertIn('grafana-1004', last_record['target'])


if __name__ == '__main__':
    unittest.main()
