# WebVulnScan

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Version](https://img.shields.io/badge/Version-2.0-orange)
![Modules](https://img.shields.io/badge/Scanners-9%20Modules-red)

A modular web application vulnerability scanner and exploitation framework built in Python. Detects and exploits **OWASP Top 10** vulnerabilities — from reconnaissance to full database extraction.

---

## Features

- **9 vulnerability scanner modules** — headers, SQLi, blind SQLi, XSS, command injection, form injection, directory enumeration, info disclosure, SSL/TLS
- **SQL injection exploitation** — automatically extracts databases, tables, and row data via UNION-based and blind techniques
- **Web crawler** — spiders the target to discover all endpoints and forms before scanning
- **Subdomain enumeration** — brute-forces 76 common subdomains via DNS
- **Port scanner** — multi-threaded TCP scan of 26 common ports with service and risk identification
- **Form testing** — tests POST/GET forms for SQLi, XSS, command injection, and missing CSRF tokens
- **SSL/TLS analysis** — checks certificate validity, expiry, protocols, and cipher strength
- **HTML reports** — styled dark-themed interactive reports with risk scoring
- **Authenticated scanning** — pass session cookies to scan behind login pages
- **`--full` flag** — runs everything in one command

---

## Quick Start
```bash
git clone https://github.com/krish20-bot/webvulnscan.git
cd webvulnscan
pip install -r requirements.txt

# Basic scan
python3 main.py https://target.com -o report.json --html report.html

# Full recon + scan + exploit
python3 main.py "https://target.com/page?id=1" -c "COOKIE=value" --full --exploit
```

> **Legal Notice:** Only scan websites you own or have explicit written permission to test.

---

## What It Detects (and Exploits)

| Module | What It Does | Severity |
|--------|-------------|----------|
| **Security Headers** | Missing HSTS, CSP, X-Frame-Options, insecure cookies, info-leaking headers | HIGH — LOW |
| **SQL Injection** | Error-based detection across MySQL, PostgreSQL, SQL Server, Oracle, SQLite | HIGH |
| **Blind SQL Injection** | Time-based SLEEP/WAITFOR detection with multi-round confirmation | HIGH |
| **SQLi Exploitation** | Full data extraction: DB version, tables, columns, row dumps via UNION + blind | HIGH |
| **Cross-Site Scripting** | Reflected XSS via script tags, event handlers, SVG payloads | HIGH |
| **Command Injection** | OS command injection via semicolons, pipes, backticks, subshells | HIGH |
| **Form Injection** | Tests POST/GET forms for SQLi, XSS, command injection + CSRF detection | HIGH — MEDIUM |
| **Directory Enumeration** | Exposed admin panels, .env, .git/HEAD, backups, API docs, debug endpoints | HIGH — LOW |
| **Information Disclosure** | Internal IPs, emails, stack traces, version numbers, HTTP without HTTPS | MEDIUM — LOW |
| **SSL/TLS Security** | Certificate expiry, self-signed certs, weak ciphers, insecure TLS 1.0/1.1 | HIGH — INFO |
| **Subdomain Enumeration** | DNS brute-force of 76 common subdomains to find forgotten assets | INFO |
| **Port Scanner** | Multi-threaded scan of 26 ports with risk flagging for exposed databases/services | MEDIUM — INFO |

---

## SQLi Exploitation Demo
```
  [EXPLOIT] Extracting via 'id'
    [+] Columns found: 2
    [+] Injectable column: position 1
    [+] Database: 10.1.26-MariaDB-0+deb9u1
    [+] Current database: dvwa
    [+] Current user: app@localhost
    [+] Tables: guestbook, users

    [*] Auto-dumping: users
    [+] Columns: user_id, first_name, last_name, user, password, avatar

    +--- users ---
    | user_id | first_name | last_name | user    | password                         |
    | --------+------------+-----------+---------+----------------------------------|
    | 1       | admin      | admin     | admin   | 5f4dcc3b5aa765d61d8327deb882cf99 |
    | 2       | Gordon     | Brown     | gordonb | e99a18c428cb38d5f260853678922e03 |
    | 3       | Hack       | Me        | 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b |
    | 4       | Pablo      | Picasso   | pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 |
    | 5       | Bob        | Smith     | smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 |
```

---

## Screenshots

### Terminal Output
![Terminal Output](screenshots/terminal_output.png)

### HTML Report — Risk Score & Severity
![HTML Report](screenshots/html_report_top.png)

### HTML Report — Expanded Findings
![Findings Detail](screenshots/html_findings.png)

### Crawler Mode
![Crawler](screenshots/crawler_mode.png)

---

## Usage
```bash
# Simple scan
python3 main.py https://target.com

# Scan with reports
python3 main.py https://target.com -o report.json --html report.html

# Authenticated scan
python3 main.py "https://target.com/page?id=1" -c "PHPSESSID=abc; security=low"

# Crawl entire site then scan all endpoints
python3 main.py https://target.com --crawl --html full_scan.html

# Blind SQL injection detection
python3 main.py "https://target.com/page?id=1" --blind

# Exploit SQLi — auto-dump sensitive tables
python3 main.py "https://target.com/page?id=1" -c "COOKIE=value" --exploit

# Exploit SQLi — dump a specific table
python3 main.py "https://target.com/page?id=1" -c "COOKIE=value" --exploit --dump users

# Subdomain enumeration + port scanning
python3 main.py https://target.com --subdomains --ports

# Everything at once
python3 main.py https://target.com -c "COOKIE=value" --full --exploit --html report.html
```

### All CLI Options

| Flag | Description |
|------|-------------|
| `url` | Target URL to scan (required) |
| `-o, --output` | Save JSON report to file |
| `--html` | Save styled HTML report to file |
| `-c, --cookie` | Cookie string for authenticated scanning |
| `--crawl` | Spider the site to discover endpoints before scanning |
| `--max-pages N` | Maximum pages to crawl (default: 30) |
| `--blind` | Enable time-based blind SQL injection detection |
| `--exploit` | Exploit confirmed SQLi to extract database contents |
| `--dump TABLE` | Dump a specific table (use with --exploit) |
| `--subdomains` | Enumerate subdomains via DNS brute-force |
| `--ports` | Scan for open ports with service identification |
| `--full` | Enable all recon and scan features at once |

---

## Architecture
```
webvulnscan/
├── main.py                          # CLI entry point & scan orchestrator
├── crawler.py                       # BFS web spider
├── sqli_exploit.py                  # SQLi exploitation (UNION + blind)
├── subdomain_enum.py                # DNS subdomain brute-forcing
├── port_scanner.py                  # Multi-threaded TCP port scanner
├── html_report.py                   # Styled HTML report generator
├── report.py                        # JSON report with risk scoring
├── requirements.txt
├── scanners/
│   ├── __init__.py                  # BaseScanner class
│   ├── header_scanner.py            # HTTP security headers
│   ├── sqli_scanner.py              # SQL injection (error-based)
│   ├── blind_sqli_scanner.py        # Blind SQLi (time-based)
│   ├── xss_scanner.py               # Reflected XSS
│   ├── cmdi_scanner.py              # OS command injection
│   ├── form_scanner.py              # Form injection + CSRF
│   ├── ssl_scanner.py               # SSL/TLS analysis
│   ├── directory_scanner.py         # File/directory probing
│   └── info_disclosure_scanner.py   # Data leak detection
├── screenshots/
├── examples/
│   └── sample_report.json
├── docs/
│   └── EXTENDING.md
├── .gitignore
├── LICENSE
└── README.md
```

### How It Works

1. **Recon** (optional) — Subdomain enumeration and port scanning map the attack surface
2. **Crawl** (optional) — BFS spider discovers pages, links, and forms
3. **Scan** — 9 modules run independently against each target
4. **Exploit** (optional) — Confirmed SQLi is exploited to extract database contents
5. **Report** — Results are deduplicated, scored, and output as terminal/JSON/HTML

### SQLi Exploitation Chain

1. UNION SELECT with increasing NULLs → finds column count
2. Hex-encoded markers in each column → finds injectable position
3. `version()` → identifies database type
4. `information_schema.tables` → lists all tables
5. `information_schema.columns` → lists columns per table
6. Row-by-row extraction → dumps data
7. Blind boolean fallback if UNION fails → binary search per character

---

## Practice Targets

| App | Install | What to Test |
|-----|---------|--------------|
| [DVWA](https://github.com/digininja/DVWA) | `docker run --rm -p 8080:80 vulnerables/web-dvwa` | SQLi, XSS, command injection, exploitation |
| [Juice Shop](https://owasp.org/www-project-juice-shop/) | `docker run --rm -p 3000:3000 bkimminich/juice-shop` | Modern web vulns, API issues |
| [WebGoat](https://owasp.org/www-project-webgoat/) | `docker run --rm -p 8080:8080 webgoat/webgoat` | Guided vulnerability lessons |

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-scanner`
3. Test against DVWA or Juice Shop
4. Submit a pull request

See [docs/EXTENDING.md](docs/EXTENDING.md) for writing custom modules.

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [TryHackMe](https://tryhackme.com/)
- [CrackStation](https://crackstation.net/) — Hash lookup for cracking extracted passwords

---

## License

MIT License. See [LICENSE](LICENSE) for details.

**Built for learning. Scan responsibly.**
