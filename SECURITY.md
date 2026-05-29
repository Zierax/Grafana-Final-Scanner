# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :warning: Limited  |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

This tool is designed for authorized security assessments of Grafana instances. If you discover a security vulnerability in the Grafana Final Scanner itself (not a Grafana instance being scanned), please follow responsible disclosure:

### How to Report

1. **Open a private security advisory** on GitHub:
   - Navigate to the repository: `https://github.com/Zierax/Grafana-Final-Scanner`
   - Click `Security` → `Advisories` → `New draft security advisory`
   - Fill in the details of the vulnerability

2. **Provide comprehensive information**:
   - Steps to reproduce the issue
   - Affected versions
   - Potential impact
   - Any known mitigations or workarounds

3. **Allow time for a fix**:
   - We will acknowledge receipt within 48 hours
   - We will work on a patch and coordinate disclosure timing
   - We will credit you in the release notes unless you prefer anonymity

### What to Expect

- **Response Time**: Initial acknowledgment within 48 hours
- **Updates**: Status updates every 7 days until resolution
- **Resolution Timeline**: Critical vulnerabilities: 14 days; High: 30 days; Medium/Low: Next release cycle

## Ethical Use Reminder

This tool is intended exclusively for:

- **Authorized security assessments** of systems you own or manage
- **Educational purposes** in controlled environments
- **Penetration testing engagements** with explicit written authorization

**Unauthorized scanning of systems you do not own or have explicit permission to test may violate:**
- The Computer Fraud and Abuse Act (CFAA) in the United States
- The Computer Misuse Act in the United Kingdom
- Similar computer crime laws in other jurisdictions
- Terms of service of cloud providers and hosting platforms

The developers of this tool assume **no liability** for misuse or damages resulting from unauthorized use.

## Self-Assessment Guidelines

If you discover a vulnerability using this tool:

1. Immediately stop testing and document your findings
2. Notify the system owner with your evidence
3. Do not disclose the vulnerability publicly until it is remediated
4. Follow any coordinated disclosure processes the owner has in place

## Security Best Practices for Users

When using Grafana Final Scanner:

- **Use a dedicated machine or container** — Avoid running scans from production systems
- **Limit network exposure** — Do not expose the web dashboard (--serve) to public networks
- **Protect authentication credentials** — Use environment variables or secure vaults, not command-line history
- **Secure the vulnerability database** — The --db file contains sensitive information about your infrastructure
- **Regularly update** — Keep the scanner updated to benefit from the latest CVE coverage and fixes
- **Use a virtual environment** — Isolate Python dependencies to avoid conflicts

---

**Thank you for helping keep Grafana Final Scanner and the community safe.**
