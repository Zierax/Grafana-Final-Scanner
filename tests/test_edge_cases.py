"""
Edge case tests for GrafanaFinalScanner

Tests cover boundary conditions, error paths, and unusual inputs:
- Version comparison: pre-release, malformed, uneven parts, empty strings
- Parse methods: exceptions, missing keys, empty responses
- Safe request: timeouts, connection errors, retry, rate limit body
- CVE boundaries: exact patch thresholds for all 15 CVEs
- Report generation: empty results, no vulns, special chars
- Auth: empty strings, special chars, unicode
- CORS: wildcard, reflection, credentials
- Security config: None responses, malformed data
"""

import argparse
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch, Mock

import requests

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner import GrafanaFinalScanner, _positive_int, Colors

# =====================================================================
#  Version Comparison Edge Cases
# =====================================================================

class TestCompareVersionsEdgeCases(unittest.TestCase):
    """Edge cases for version comparison"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_pre_release_beta(self):
        """Beta versions should compare equal to release"""
        self.assertEqual(self.scanner.compare_versions('8.0.0-beta1', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('11.2.0-beta2', '11.2.0'), 0)

    def test_pre_release_rc(self):
        """RC versions should compare equal to release"""
        self.assertEqual(self.scanner.compare_versions('8.0.0-rc1', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('9.0.0-rc3', '9.0.0'), 0)

    def test_pre_release_alpha(self):
        """Alpha versions should strip suffix"""
        self.assertEqual(self.scanner.compare_versions('8.0.0-alpha1', '8.0.0'), 0)

    def test_pre_release_with_underscore(self):
        """Pre-release with underscore should strip suffix"""
        self.assertEqual(self.scanner.compare_versions('8.0.0_beta1', '8.0.0'), 0)

    def test_uneven_parts_two_parts(self):
        """Version with 2 parts should compare against 3 parts"""
        self.assertEqual(self.scanner.compare_versions('8.0', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('8.0', '9.0.0'), -1)
        self.assertEqual(self.scanner.compare_versions('9.0', '8.0.0'), 1)

    def test_uneven_parts_one_part(self):
        """Version with 1 part should compare against 3 parts"""
        self.assertEqual(self.scanner.compare_versions('8', '8.0.0'), 0)
        self.assertEqual(self.scanner.compare_versions('8', '7.9.9'), 1)
        self.assertEqual(self.scanner.compare_versions('8', '9.0.0'), -1)

    def test_empty_string_vs_valid(self):
        """Empty string should be treated as 0.0.0"""
        self.assertEqual(self.scanner.compare_versions('', '8.0.0'), -1)
        self.assertEqual(self.scanner.compare_versions('', ''), 0)

    def test_non_numeric_part(self):
        """Non-numeric part should be treated as 0"""
        self.assertEqual(self.scanner.compare_versions('8.a.0', '8.0.0'), 0)

    def test_large_version_numbers(self):
        """Very large version numbers should compare correctly"""
        self.assertEqual(self.scanner.compare_versions('999.999.999', '998.999.999'), 1)
        self.assertEqual(self.scanner.compare_versions('100.0.0', '99.999.999'), 1)

    def test_minimum_version(self):
        """0.0.0 should be the minimum valid version"""
        self.assertEqual(self.scanner.compare_versions('0.0.0', '0.0.1'), -1)
        self.assertEqual(self.scanner.compare_versions('0.0.0', '0.0.0'), 0)

    def test_compare_equal_with_different_parts(self):
        """Different representations of same version"""
        self.assertEqual(self.scanner.compare_versions('8.1.0', '8.1'), 0)
        self.assertEqual(self.scanner.compare_versions('8.0.0', '8'), 0)


class TestVersionInRangeEdgeCases(unittest.TestCase):
    """Edge cases for version range checking"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_none_version(self):
        """None version should return False (not crash)"""
        result = self.scanner.version_in_range(None)
        self.assertFalse(result)

    def test_version_with_letters(self):
        """Version string with trailing letters"""
        self.assertTrue(self.scanner.version_in_range('8.0.0abc', '8.0.0', '9.0.0'))

    def test_exact_lower_bound(self):
        """Version exactly at lower bound is inclusive"""
        self.assertTrue(self.scanner.version_in_range('8.5.0', '8.5.0', '9.0.0'))

    def test_exact_upper_bound(self):
        """Version exactly at upper bound is inclusive"""
        self.assertTrue(self.scanner.version_in_range('9.0.0', '8.5.0', '9.0.0'))

    def test_min_only_none_explicit(self):
        """Explicit None for min_v and max_v should work like no bounds"""
        self.assertTrue(self.scanner.version_in_range('8.0.0', None, None))

    def test_version_with_spaces(self):
        """Version with spaces should not crash"""
        self.assertFalse(self.scanner.version_in_range('  ', '8.0.0', '9.0.0'))

    def test_zero_zero_vs_any(self):
        """0.0.0 should be less than any real version"""
        self.assertFalse(self.scanner.version_in_range('0.0.0', '8.0.0'))

    def test_min_equal_to_max(self):
        """Single-version range (min == max)"""
        self.assertTrue(self.scanner.version_in_range('8.4.3', '8.4.3', '8.4.3'))
        self.assertFalse(self.scanner.version_in_range('8.4.2', '8.4.3', '8.4.3'))
        self.assertFalse(self.scanner.version_in_range('8.4.4', '8.4.3', '8.4.3'))


# =====================================================================
#  All CVE Boundary Tests
# =====================================================================

class TestAllCVEBoundaries(unittest.TestCase):
    """Test every CVE at exact patch boundaries"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_cve_2025_4123_boundaries(self):
        """CVE-2025-4123: All versions < 12.0.0"""
        self.scanner.grafana_version = '11.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2025-4123'))
        self.scanner.grafana_version = '12.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2025-4123'))
        self.scanner.grafana_version = '12.0.1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2025-4123'))
        self.scanner.grafana_version = '0.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2025-4123'))
        self.scanner.grafana_version = '1.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2025-4123'))

    def test_cve_2024_9264_all_boundaries(self):
        """CVE-2024-9264: 11.0.0-11.0.5, 11.1.0-11.1.6, 11.2.0-11.2.1"""
        # Range 1: 11.0.0 - 11.0.5
        self.scanner.grafana_version = '10.9.9'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.0.5'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.0.6'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        # Range 2: 11.1.0 - 11.1.6
        self.scanner.grafana_version = '11.1.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.1.6'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.1.7'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        # Range 3: 11.2.0 - 11.2.1
        self.scanner.grafana_version = '11.2.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.2.1'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-9264'))
        self.scanner.grafana_version = '11.2.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-9264'))

    def test_cve_2024_8118_all_boundaries(self):
        """CVE-2024-8118: 11.0.0-11.0.5, 11.1.0-11.1.7, 11.2.0-11.2.1"""
        self.scanner.grafana_version = '11.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.0.5'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.0.6'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.1.7'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.1.8'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.2.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.2.1'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-8118'))
        self.scanner.grafana_version = '11.2.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-8118'))

    def test_cve_2021_43798_boundaries(self):
        """CVE-2021-43798: 8.0.0 - 8.3.0"""
        self.scanner.grafana_version = '7.9.9'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '8.3.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '8.3.1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '9.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-43798'))

    def test_cve_2021_27358_boundaries(self):
        """CVE-2021-27358: 6.7.3 - 7.4.1"""
        self.scanner.grafana_version = '6.7.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-27358'))
        self.scanner.grafana_version = '6.7.3'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-27358'))
        self.scanner.grafana_version = '7.4.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-27358'))
        self.scanner.grafana_version = '7.4.1'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-27358'))
        self.scanner.grafana_version = '7.4.2'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-27358'))

    def test_cve_2021_41174_boundaries(self):
        """CVE-2021-41174: 8.0.0 - 8.3.0"""
        self.scanner.grafana_version = '7.9.9'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-41174'))
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-41174'))
        self.scanner.grafana_version = '8.3.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-41174'))
        self.scanner.grafana_version = '8.3.1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-41174'))

    def test_cve_2021_39226_boundaries(self):
        """CVE-2021-39226: 8.0.0 - 8.3.0"""
        self.scanner.grafana_version = '7.9.9'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-39226'))
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-39226'))
        self.scanner.grafana_version = '8.3.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-39226'))
        self.scanner.grafana_version = '8.3.1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-39226'))

    def test_cve_2020_11110_boundaries(self):
        """CVE-2020-11110: < 6.7.0"""
        self.scanner.grafana_version = '6.6.9'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2020-11110'))
        self.scanner.grafana_version = '6.7.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2020-11110'))
        self.scanner.grafana_version = '5.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2020-11110'))
        self.scanner.grafana_version = '7.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2020-11110'))

    def test_cve_2018_15727_boundaries(self):
        """CVE-2018-15727: <= 5.2.2"""
        self.scanner.grafana_version = '5.2.2'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2018-15727'))
        self.scanner.grafana_version = '5.2.3'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2018-15727'))
        self.scanner.grafana_version = '4.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2018-15727'))
        self.scanner.grafana_version = '6.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2018-15727'))

    def test_cve_2023_50164_all_boundaries(self):
        """CVE-2023-50164: < 9.2.10, < 9.3.6, < 9.4.1"""
        # Range 1: < 9.2.10
        self.scanner.grafana_version = '9.2.9'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        self.scanner.grafana_version = '9.2.10'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        # Range 2: 9.3.0 - 9.3.5
        self.scanner.grafana_version = '9.3.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        self.scanner.grafana_version = '9.3.5'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        self.scanner.grafana_version = '9.3.6'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        # Range 3: 9.4.0 only
        self.scanner.grafana_version = '9.4.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        # Non-range: 9.4.1
        self.scanner.grafana_version = '9.4.1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-50164'))
        # Lower versions in the 0.0.0-9.2.9 range ARE vulnerable
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-50164'))

    def test_cve_2023_1410_all_boundaries(self):
        """CVE-2023-1410: >= 8.0.0, < 9.2.17 or 9.3.0 - 9.3.4"""
        self.scanner.grafana_version = '7.9.9'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        # Range 1: 8.0.0 - 9.2.16
        self.scanner.grafana_version = '9.2.16'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        self.scanner.grafana_version = '9.2.17'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        # Range 2: 9.3.0 - 9.3.4
        self.scanner.grafana_version = '9.3.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        self.scanner.grafana_version = '9.3.4'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        self.scanner.grafana_version = '9.3.5'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))
        # Not in range
        self.scanner.grafana_version = '9.4.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-1410'))

    def test_cve_2023_2183_all_boundaries(self):
        """CVE-2023-2183: 8.x < 8.5.21, 9.x < 9.4.13"""
        # 8.x range
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '8.5.20'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '8.5.21'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '8.6.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        # 9.x range
        self.scanner.grafana_version = '9.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '9.4.12'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '9.4.13'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        self.scanner.grafana_version = '9.5.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))
        # 10.x not affected
        self.scanner.grafana_version = '10.0.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2023-2183'))

    def test_cve_2024_1313_all_boundaries(self):
        """CVE-2024-1313: Multiple version ranges"""
        # Starting with 9.5.x range: 9.5.0 - 9.5.6
        self.scanner.grafana_version = '9.5.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        self.scanner.grafana_version = '9.5.6'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        self.scanner.grafana_version = '9.5.7'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        # 9.4.x range: 9.4.0 - 9.4.10
        self.scanner.grafana_version = '9.4.10'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        self.scanner.grafana_version = '9.4.11'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        # 8.0.x range: 8.0.0 - 8.5.17
        self.scanner.grafana_version = '8.0.0'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        self.scanner.grafana_version = '8.5.17'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2024-1313'))
        self.scanner.grafana_version = '8.6.0'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2024-1313'))

    def test_cve_2022_32275_edge(self):
        """CVE-2022-32275: Exactly 8.4.3 (exact string match)"""
        self.scanner.grafana_version = '8.4.3'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2022-32275'))
        # Pre-release tags use exact string comparison, so they won't match
        self.scanner.grafana_version = '8.4.3-beta1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2022-32275'))
        # Every other version should be false
        for v in ['8.4.2', '8.4.4', '8.5.0', '8.3.0', '9.0.0']:
            self.scanner.grafana_version = v
            self.assertFalse(
                self.scanner.is_version_vulnerable('CVE-2022-32275'),
                f"{v} should not be CVE-2022-32275"
            )

    def test_cve_2022_32276_edge(self):
        """CVE-2022-32276: Exactly 8.4.3"""
        self.scanner.grafana_version = '8.4.3'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2022-32276'))
        for v in ['8.4.2', '8.4.4', '9.0.0']:
            self.scanner.grafana_version = v
            self.assertFalse(self.scanner.is_version_vulnerable('CVE-2022-32276'))

    def test_all_cves_with_unknown_version(self):
        """All CVEs should default to vulnerable when version is unknown"""
        self.scanner.grafana_version = None
        all_cves = [
            'CVE-2025-4123', 'CVE-2024-9264', 'CVE-2024-8118',
            'CVE-2021-43798', 'CVE-2022-32275', 'CVE-2022-32276',
            'CVE-2021-27358', 'CVE-2020-11110', 'CVE-2021-41174',
            'CVE-2021-39226', 'CVE-2018-15727', 'CVE-2023-50164',
            'CVE-2023-1410', 'CVE-2023-2183', 'CVE-2024-1313'
        ]
        for cve_id in all_cves:
            with self.subTest(cve_id=cve_id):
                self.assertTrue(
                    self.scanner.is_version_vulnerable(cve_id),
                    f"{cve_id} should be vulnerable when version unknown"
                )

    def test_exception_in_version_check(self):
        """Exception in version check should default to vulnerable"""
        self.scanner.grafana_version = '8.0.0'
        # This should work normally
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        # Unknown CVE should return True
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-UNKNOWN-99999'))

    def test_pre_release_with_cve_check(self):
        """Pre-release versions should be checked correctly"""
        self.scanner.grafana_version = '8.0.0-beta1'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '8.3.0-beta2'
        self.assertTrue(self.scanner.is_version_vulnerable('CVE-2021-43798'))
        self.scanner.grafana_version = '8.3.1-rc1'
        self.assertFalse(self.scanner.is_version_vulnerable('CVE-2021-43798'))


# =====================================================================
#  Parse Methods Edge Cases
# =====================================================================

class TestParseMethodsEdgeCases(unittest.TestCase):
    """Edge cases for response parsing"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    def test_parse_frontend_settings_json_exception(self):
        """response.json() raising exception should return None"""
        response = MagicMock()
        response.json.side_effect = ValueError("Invalid JSON")
        version = self.scanner._parse_frontend_settings(response)
        self.assertIsNone(version)

    def test_parse_frontend_settings_with_buildinfo_but_no_version(self):
        """buildInfo present but missing version key should return None"""
        response = MagicMock()
        response.json.return_value = {'buildInfo': {'commit': 'abc123'}}
        version = self.scanner._parse_frontend_settings(response)
        self.assertIsNone(version)

    def test_parse_health_endpoint_missing_version(self):
        """Health response without version key should return None"""
        response = MagicMock()
        response.json.return_value = {'database': 'ok'}
        version = self.scanner._parse_health_endpoint(response)
        self.assertIsNone(version)

    def test_parse_health_endpoint_invalid_json(self):
        """Health endpoint non-JSON response should return None"""
        response = MagicMock()
        response.json.side_effect = ValueError("Not JSON")
        version = self.scanner._parse_health_endpoint(response)
        self.assertIsNone(version)

    def test_parse_login_page_no_match(self):
        """Login page without version info should return None"""
        response = MagicMock()
        response.text = '<html><body>Login</body></html>'
        version = self.scanner._parse_login_page(response)
        self.assertIsNone(version)

    def test_parse_login_page_empty_text(self):
        """Empty response text should return None"""
        response = MagicMock()
        response.text = ''
        version = self.scanner._parse_login_page(response)
        self.assertIsNone(version)

    def test_parse_login_page_grafana_boot_data(self):
        """Parse version from window.grafanaBootData"""
        response = MagicMock()
        response.text = 'window.grafanaBootData = { "version": "9.2.0" }'
        version = self.scanner._parse_login_page(response)
        self.assertEqual(version, '9.2.0')

    def test_parse_login_page_grafana_v_prefix(self):
        """Parse version from 'Grafana vX.Y.Z' pattern"""
        response = MagicMock()
        response.text = 'Grafana v8.5.0 is running'
        version = self.scanner._parse_login_page(response)
        self.assertEqual(version, '8.5.0')

    def test_parse_login_page_meta_tag(self):
        """Parse version from meta tag"""
        response = MagicMock()
        response.text = '<meta name="grafana-version" content="11.2.0">'
        version = self.scanner._parse_login_page(response)
        self.assertEqual(version, '11.2.0')

    def test_parse_login_page_build_version(self):
        """Parse version from buildVersion field"""
        response = MagicMock()
        response.text = '"buildVersion": "8.5.0"'
        version = self.scanner._parse_login_page(response)
        self.assertEqual(version, '8.5.0')

    def test_parse_version_header_no_headers(self):
        """Empty headers should return None"""
        response = MagicMock()
        response.headers = {}
        version = self.scanner._parse_version_header_only(response)
        self.assertIsNone(version)

    def test_parse_version_header_alternative_name(self):
        """X-Grafana-Build-Version should also work"""
        response = MagicMock()
        response.headers = {'X-Grafana-Build-Version': '8.2.5'}
        version = self.scanner._parse_version_header_only(response)
        self.assertEqual(version, '8.2.5')

    def test_parse_version_header_invalid_format(self):
        """Header with non-semantic version should return None"""
        response = MagicMock()
        response.headers = {'X-Grafana-Version': 'latest'}
        version = self.scanner._parse_version_header_only(response)
        self.assertIsNone(version)

    def test_parse_api_response_list_data(self):
        """API returning list instead of dict should check headers"""
        response = MagicMock()
        response.json.return_value = ['item1', 'item2']
        response.headers = {}
        version = self.scanner._parse_api_response(response)
        self.assertIsNone(version)

    def test_parse_api_response_with_version_in_data(self):
        """API response with version key in data"""
        response = MagicMock()
        response.json.return_value = {'version': '8.5.0'}
        response.headers = {}
        version = self.scanner._parse_api_response(response)
        self.assertEqual(version, '8.5.0')

    def test_parse_api_response_json_exception(self):
        """API non-JSON response should check headers"""
        response = MagicMock()
        response.json.side_effect = ValueError("Not JSON")
        response.headers = {}
        version = self.scanner._parse_api_response(response)
        self.assertIsNone(version)

    def test_parse_api_response_header_fallback(self):
        """API response should fall back to header check"""
        response = MagicMock()
        response.json.side_effect = ValueError("Not JSON")
        response.headers = {'X-Grafana-Version': '8.2.5'}
        version = self.scanner._parse_api_response(response)
        self.assertEqual(version, '8.2.5')


# =====================================================================
#  Safe Request Edge Cases
# =====================================================================

class TestSafeRequestEdgeCases(unittest.TestCase):
    """Edge cases for safe HTTP request wrapper"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('requests.Session.request')
    @patch('scanner.time.sleep', return_value=None)
    def test_timeout_returns_none(self, mock_sleep, mock_request):
        """Timeout exception should return None"""
        mock_request.side_effect = requests.exceptions.Timeout("Connection timed out")
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)

    @patch('requests.Session.request')
    def test_connection_error_returns_none(self, mock_request):
        """Connection error should return None"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)

    @patch('requests.Session.request')
    def test_generic_exception_returns_none(self, mock_request):
        """Any other exception should return None"""
        mock_request.side_effect = RuntimeError("Something went wrong")
        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)

    @patch('requests.Session.request')
    @patch('scanner.time.sleep', return_value=None)
    def test_retry_on_timeout_then_succeed(self, mock_sleep, mock_request):
        """Should retry on timeout and succeed on second attempt"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.side_effect = [requests.exceptions.Timeout("Timeout"), mock_response]

        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(mock_request.call_count, 2)

    @patch('requests.Session.request')
    @patch('scanner.time.sleep', return_value=None)
    def test_rate_limit_response_body(self, mock_sleep, mock_request):
        """Rate limit message in response body should be detected"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {'message': 'Rate limit exceeded'}
        mock_request.return_value = mock_response

        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)
        self.assertTrue(self.scanner._rate_limited)

    @patch('requests.Session.request')
    @patch('scanner.time.sleep', return_value=None)
    def test_too_many_requests_in_body(self, mock_sleep, mock_request):
        """'too many requests' message in body should be detected"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {'error': 'Too many requests, slow down'}
        mock_request.return_value = mock_response

        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNone(result)
        self.assertTrue(self.scanner._rate_limited)

    @patch('requests.Session.request')
    def test_json_exception_in_rate_limit_check(self, mock_request):
        """JSON parse error in rate limit check should not crash"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.side_effect = ValueError("Not JSON")
        mock_request.return_value = mock_response

        result = self.scanner._safe_request('GET', 'https://example.com')
        self.assertIsNotNone(result)


# =====================================================================
#  Report Generation Edge Cases
# =====================================================================

class TestReportGenerationEdgeCases(unittest.TestCase):
    """Edge cases for report generation"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()
        self.empty_results = []
        self.no_vuln_results = [{
            'url': 'https://grafana.example.com',
            'version': '8.2.5',
            'timestamp': '2025-01-01T00:00:00',
            'vulnerabilities': [],
            'configuration': {},
            'statistics': {},
            'accessible': True,
            'build_info': {}
        }]
        self.special_char_results = [{
            'url': 'https://grafana.example.com/?q=<script>alert(1)</script>',
            'version': '8.2.5',
            'timestamp': '2025-01-01T00:00:00',
            'vulnerabilities': [{
                'cve_id': 'CVE-2021-43798',
                'severity': 'CRITICAL',
                'message': 'Path traversal with <>&"\'> characters',
                'test_url': 'https://grafana.example.com/test?x=1&y=2'
            }],
            'configuration': {},
            'statistics': {},
            'accessible': True,
            'build_info': {}
        }]
        self.many_vuln_results = [{
            'url': f'https://grafana-{i}.example.com',
            'version': '8.2.5',
            'timestamp': '2025-01-01T00:00:00',
            'vulnerabilities': [
                {
                    'cve_id': f'CVE-2024-{9000 + j}',
                    'severity': severity,
                    'message': f'Test vulnerability {j}',
                    'test_url': f'https://test-{j}.example.com'
                }
                for j, severity in enumerate(
                    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] * 3
                )
            ],
            'configuration': {},
            'statistics': {},
            'accessible': True,
            'build_info': {}
        } for i in range(5)]
        # Result with missing optional keys
        self.minimal_result = [{
            'url': 'https://grafana.example.com',
            'vulnerabilities': [{
                'cve_id': 'CVE-2021-43798',
                'severity': 'CRITICAL',
                'message': 'Test'
            }]
        }]

    @patch('builtins.print')
    def test_empty_results_json(self, mock_print):
        """Empty results should produce valid JSON"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_json_report(self.empty_results, temp_path)
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(data, [])
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_empty_results_csv(self, mock_print):
        """Empty results should produce CSV with header only"""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_csv_report(self.empty_results, temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('Target URL', content)
            self.assertIn('CVE ID', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_empty_results_html(self, mock_print):
        """Empty results should produce valid HTML with 'no vulnerabilities'"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(self.empty_results, temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<html', content)
            self.assertIn('No vulnerabilities detected', content)
            self.assertIn('</html>', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_no_vulnerabilities_html(self, mock_print):
        """Results without vulns should show no vulns in HTML"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(self.no_vuln_results, temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('No vulnerabilities detected', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_html_escaping_special_chars(self, mock_print):
        """Special characters in URLs/messages should be HTML-escaped"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(self.special_char_results, temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            # Raw HTML special chars should NOT appear unescaped in output
            self.assertNotIn('<script>', content)
            self.assertIn('&lt;script&gt;', content)
            # Verify the URL's query params are escaped
            self.assertIn('&amp;', content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_many_vulns_json(self, mock_print):
        """Many vulnerabilities should serialize correctly"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
                temp_path = f.name
            self.scanner._save_json_report(self.many_vuln_results, temp_path)
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(len(data), 5)
            total_vulns = sum(len(r['vulnerabilities']) for r in data)
            self.assertEqual(total_vulns, 5 * 12)  # 5 targets * 12 vulns each
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_minimal_result_json(self, mock_print):
        """Minimal result (missing optional keys) should serialize"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_json_report(self.minimal_result, temp_path)
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['url'], 'https://grafana.example.com')
            self.assertEqual(data[0]['vulnerabilities'][0]['cve_id'], 'CVE-2021-43798')
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_minimal_result_html(self, mock_print):
        """Minimal result without optional keys should generate HTML"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            temp_path = f.name
        try:
            self.scanner._save_html_report(self.minimal_result, temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<html', content)
            self.assertIn('CVE-2021-43798', content)
        finally:
            os.unlink(temp_path)


# =====================================================================
#  Auth Edge Cases
# =====================================================================

class TestAuthEdgeCases(unittest.TestCase):
    """Edge cases for authentication configuration"""

    def test_empty_token(self):
        """Empty token should not set Authorization header"""
        scanner = GrafanaFinalScanner(auth_token='')
        self.assertIsNone(scanner.session.headers.get('Authorization'))

    def test_empty_user_with_password(self):
        """Empty user with password should not set auth"""
        scanner = GrafanaFinalScanner(auth_user='', auth_pass='password123')
        self.assertIsNone(scanner.session.auth)

    def test_user_without_password(self):
        """User without password should not set auth"""
        scanner = GrafanaFinalScanner(auth_user='admin', auth_pass='')
        self.assertIsNone(scanner.session.auth)

    def test_special_chars_in_password(self):
        """Special characters in password should be preserved"""
        scanner = GrafanaFinalScanner(auth_user='admin', auth_pass="admin' --")
        self.assertEqual(scanner.session.auth, ("admin", "admin' --"))

    def test_unicode_in_token(self):
        """Unicode in token should be preserved"""
        scanner = GrafanaFinalScanner(auth_token='glsa_tok\u00e9n_123')
        expected = 'Bearer glsa_tok\u00e9n_123'
        self.assertEqual(scanner.session.headers.get('Authorization'), expected)

    def test_symbols_in_password(self):
        """Dollar signs and special symbols in password"""
        scanner = GrafanaFinalScanner(auth_user='admin', auth_pass='p@$$w0rd!')
        self.assertEqual(scanner.session.auth, ('admin', 'p@$$w0rd!'))

    def test_long_token(self):
        """Very long token should be accepted"""
        long_token = 'glsa_' + 'a' * 500
        scanner = GrafanaFinalScanner(auth_token=long_token)
        expected = f'Bearer {long_token}'
        self.assertEqual(scanner.session.headers.get('Authorization'), expected)


# =====================================================================
#  CORS Edge Cases
# =====================================================================

class TestCORSEdgeCases(unittest.TestCase):
    """Edge cases for CORS misconfiguration detection"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_no_cors_headers(self, mock_request):
        """No CORS headers should return SAFE"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        result = self.scanner.check_cors_misconfiguration('https://example.com')
        self.assertTrue(result.get('checked'))
        self.assertEqual(result.get('severity'), 'SAFE')
        self.assertIn('No CORS headers', result.get('message', ''))

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_wildcard_cors(self, mock_request):
        """Wildcard ACAO should be MEDIUM severity"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Access-Control-Allow-Origin': '*'}
        mock_request.return_value = mock_response

        result = self.scanner.check_cors_misconfiguration('https://example.com')
        self.assertTrue(result.get('wildcard'))
        self.assertEqual(result.get('severity'), 'MEDIUM')

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_reflected_origin(self, mock_request):
        """Reflected origin ACAO should be MEDIUM severity"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Access-Control-Allow-Origin': 'https://evil.com'}
        mock_request.return_value = mock_response

        result = self.scanner.check_cors_misconfiguration('https://example.com')
        self.assertTrue(result.get('reflection'))
        self.assertEqual(result.get('severity'), 'MEDIUM')

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_wildcard_with_credentials_high(self, mock_request):
        """Wildcard ACAO with credentials should be HIGH severity"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }
        mock_request.return_value = mock_response

        result = self.scanner.check_cors_misconfiguration('https://example.com')
        self.assertEqual(result.get('severity'), 'HIGH')

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_request_none_returns_empty(self, mock_request):
        """Request returning None should return empty dict"""
        mock_request.return_value = None

        result = self.scanner.check_cors_misconfiguration('https://example.com')
        self.assertEqual(result, {})


# =====================================================================
#  Security Headers Edge Cases
# =====================================================================

class TestSecurityConfigEdgeCases(unittest.TestCase):
    """Edge cases for security configuration checking"""

    def setUp(self):
        self.scanner = GrafanaFinalScanner()

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_security_headers_none_response(self, mock_request):
        """None response from request should return empty dict"""
        mock_request.return_value = None
        results = self.scanner.check_security_headers('https://example.com')
        self.assertEqual(results, {})

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_security_headers_case_insensitive(self, mock_request):
        """Header names should be case-insensitive"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'content-security-policy': "default-src 'self'",
            'x-frame-options': 'DENY'
        }
        mock_request.return_value = mock_response

        results = self.scanner.check_security_headers('https://example.com')
        self.assertIn('Content-Security-Policy', results)
        self.assertTrue(results['Content-Security-Policy']['present'])

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_check_security_config_all_fail(self, mock_request):
        """When all requests fail, config should be minimal"""
        mock_request.return_value = None
        config = self.scanner.check_security_config('https://example.com')
        # Should still have metrics check (which won't detect metrics)
        self.assertIn('metrics', config)

    @patch('scanner.GrafanaFinalScanner._safe_request')
    def test_check_security_headers_request_exception(self, mock_request):
        """Exception in request should return empty dict"""
        mock_request.side_effect = Exception("Network error")
        results = self.scanner.check_security_headers('https://example.com')
        self.assertEqual(results, {})


# =====================================================================
#  Initialization Edge Cases
# =====================================================================

class TestInitializationEdgeCases(unittest.TestCase):
    """Edge cases for scanner initialization"""

    def test_negative_threads_defaults(self):
        """Negative threads is prevented by the arg parser, but just in case"""
        # The _positive_int validator prevents this, but verify the class stores it
        scanner = GrafanaFinalScanner(max_threads=1)
        self.assertEqual(scanner.max_threads, 1)

    def test_large_threads(self):
        """Very large thread count should be accepted"""
        scanner = GrafanaFinalScanner(max_threads=100)
        self.assertEqual(scanner.max_threads, 100)

    def test_zero_timeout(self):
        """Zero timeout should be accepted (though unusual)"""
        scanner = GrafanaFinalScanner(timeout=0)
        self.assertEqual(scanner.timeout, 0)

    def test_no_user_agent_override(self):
        """Default User-Agent should be set"""
        scanner = GrafanaFinalScanner()
        ua = scanner.session.headers.get('User-Agent', '')
        self.assertIn('Mozilla', ua)
        self.assertIn('Chrome', ua)

    def test_print_lock_exists(self):
        """_print_lock should be a threading.Lock"""
        scanner = GrafanaFinalScanner()
        self.assertIsNotNone(scanner._print_lock)
        self.assertIsInstance(scanner._print_lock, type(threading.Lock()))


import threading


# =====================================================================
#  Thread Safety Edge Cases
# =====================================================================

class TestThreadSafety(unittest.TestCase):
    """Test thread safety mechanisms"""

    def test_print_lock_acquire_release(self):
        """_print_lock should be acquirable and releasable"""
        scanner = GrafanaFinalScanner()
        self.assertTrue(scanner._print_lock.acquire(blocking=False))
        scanner._print_lock.release()

    def test_log_uses_print_lock(self):
        """log method should not block when lock is available"""
        scanner = GrafanaFinalScanner()
        scanner.log("Test message", "INFO")


# =====================================================================
#  _positive_int Edge Cases
# =====================================================================

class TestPositiveIntEdgeCases(unittest.TestCase):
    """Edge cases for _positive_int validator"""

    def test_minimum_positive(self):
        """1 should be the minimum accepted value"""
        self.assertEqual(_positive_int('1'), 1)

    def test_very_large_number(self):
        """Very large positive integer should work"""
        self.assertEqual(_positive_int('999999999'), 999999999)

    def test_whitespace_accepted(self):
        """String with whitespace is accepted by int() (strips whitespace)"""
        self.assertEqual(_positive_int(' 5 '), 5)

    def test_empty_string_rejected(self):
        """Empty string should fail"""
        with self.assertRaises(ValueError):
            _positive_int('')

    def test_hex_number_rejected(self):
        """Hexadecimal string should be rejected"""
        with self.assertRaises(ValueError):
            _positive_int('0xff')


if __name__ == '__main__':
    unittest.main()
