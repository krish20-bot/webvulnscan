# WebVulnScan

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)

A modular, extensible web application vulnerability scanner built in Python. Detects common **OWASP Top 10** vulnerabilities including SQL injection, cross-site scripting, missing security headers, exposed sensitive files, and information disclosure.

Built for learning offensive security fundamentals — and designed to be extended.

---

## Quick Start
```bash
git clone https://github.com/krish20-bot/webvulnscan.git
cd webvulnscan
pip install -r requirements.txt
python3 main.py https://your-target.com -o report.json
```

> **Legal Notice:** Only scan websites you own or have explicit written permission to test. Unauthorized scanning is illegal under the CFAA and similar laws worldwide.

---

## What It Detects

| Module | Vulnerabilities | Severity |
|--------|----------------|----------|
| **Security Headers** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Insecure cookies. Information-leaking headers. | HIGH - LOW |
| **SQL Injection** | Error-based SQLi via URL parameter injection. Tests against MySQL, PostgreSQL, SQL Server, Oracle, and SQLite error signatures. | HIGH |
| **Cross-Site Scripting** | Reflected XSS in URL parameters. Injects script tags, event handlers, and SVG payloads. | HIGH |
| **Directory Enumeration** | Exposed admin panels, config files (.env, .git/HEAD), backups (.sql, .zip), API docs, debug endpoints. | HIGH - LOW |
| **Information Disclosure** | Internal IPs, email addresses, stack traces, sensitive HTML comments, directory listings, version numbers. | MEDIUM - LOW |

---

## Example Output
```
  WebVulnScan — Web Application Vulnerability Scanner

[*] Target: http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit
[*] Started: 2026-03-20 12:55:00

[*] Running: Security Headers
    HIGH — Missing Strict-Transport-Security
    MEDIUM — Missing X-Content-Type-Options
    MEDIUM — Missing X-Frame-Options

[*] Running: SQL Injection
    HIGH — Possible SQLi in 'id'

[*] Running: Cross-Site Scripting (XSS)
    INFO — No Reflected XSS Detected

[*] Running: Directory Enumeration
    LOW — Exposed: /robots.txt

[*] Running: Information Disclosure
    MEDIUM — HTTP (not HTTPS)

==================================================
  SCAN COMPLETE — 12 findings
  HIGH: 2  MEDIUM: 4  LOW: 4  INFO: 2
==================================================
[*] Report saved to report.json
```

---

## Usage
```bash
# Basic scan
python3 main.py https://target.com

# Scan with URL parameters (SQLi / XSS testing)
python3 main.py "https://target.com/page?id=1&search=test" -o report.json

# Authenticated scan (with cookies)
python3 main.py "https://target.com/dashboard" -c "PHPSESSID=abc123; security=low" -o report.json
```

| Flag | Description |
|------|-------------|
| `url` | Target URL to scan (required) |
| `-o, --output` | Save JSON report to file |
| `-c, --cookie` | Cookie string for authenticated scanning |

---

## Architecture
```
webvulnscan/
├── main.py                          # CLI entry point & scan orchestrator
├── report.py                        # JSON report generator with risk scoring
├── requirements.txt
├── scanners/
│   ├── __init__.py                  # BaseScanner class
│   ├── header_scanner.py            # HTTP security header analysis
│   ├── sqli_scanner.py              # SQL injection detection (error-based)
│   ├── xss_scanner.py               # Reflected XSS detection
│   ├── directory_scanner.py         # Sensitive file/directory probing
│   └── info_disclosure_scanner.py   # Data leak detection
├── examples/
│   └── sample_report.json
├── docs/
│   └── EXTENDING.md                 # Guide to writing custom scanners
├── .gitignore
├── LICENSE
└── README.md
```

Every scanner inherits from `BaseScanner` and implements a `scan()` method. Adding a new module takes 3 steps — see [docs/EXTENDING.md](docs/EXTENDING.md).

---

## Practice Targets

| App | Install | What to Test |
|-----|---------|--------------|
| [DVWA](https://github.com/digininja/DVWA) | `docker run --rm -p 8080:80 vulnerables/web-dvwa` | SQLi, XSS, command injection |
| [Juice Shop](https://owasp.org/www-project-juice-shop/) | `docker run --rm -p 3000:3000 bkimminich/juice-shop` | Modern web vulns, API issues |
| [WebGoat](https://owasp.org/www-project-webgoat/) | `docker run --rm -p 8080:8080 webgoat/webgoat` | Guided vulnerability lessons |

---

## Roadmap

- [ ] HTML report generation
- [ ] Web crawler for automatic endpoint discovery
- [ ] Form-based testing (POST parameters)
- [ ] Blind SQL injection (time-based)
- [ ] Command injection scanner
- [ ] SSL/TLS certificate analysis
- [ ] Subdomain enumeration
- [ ] DOM-based XSS via headless browser
- [ ] REST / GraphQL API fuzzing
- [ ] Plugin auto-loader

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-scanner`
3. Test against DVWA or Juice Shop
4. Submit a pull request

See [docs/EXTENDING.md](docs/EXTENDING.md) for guidance on writing scanner modules.

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [TryHackMe](https://tryhackme.com/)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

**Built for learning. Use responsibly.**
