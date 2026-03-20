#!/usr/bin/env python3
"""WebVulnScan v1.2 — Web Application Vulnerability Scanner + Exploiter"""
import argparse, json, sys
from datetime import datetime
from urllib.parse import urlparse
from scanners.header_scanner import HeaderScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.directory_scanner import DirectoryScanner
from scanners.info_disclosure_scanner import InfoDisclosureScanner
from scanners.cmdi_scanner import CommandInjectionScanner
from scanners.blind_sqli_scanner import BlindSQLiScanner
from report import generate_report
from html_report import generate_html_report

RED="\033[91m";YELLOW="\033[93m";BLUE="\033[94m";GRAY="\033[90m";GREEN="\033[92m";CYAN="\033[96m";RESET="\033[0m";BOLD="\033[1m"
SEV_COLORS={"HIGH":RED,"MEDIUM":YELLOW,"LOW":BLUE,"INFO":GRAY}

def validate_url(url):
    if not url.startswith(("http://","https://")): url="http://"+url
    if not urlparse(url).netloc: raise ValueError(f"Invalid URL: {url}")
    return url.rstrip("/")

def banner():
    print(f"\n{BOLD}  ╦ ╦┌─┐┌┐ ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐┌┐┌\n  ║║║├┤ ├┴┐╚╗╔╝│ ││  │││╚═╗│  ├─┤│││\n  ╚╩╝└─┘└─┘ ╚╝ └─┘┴─┘┘└┘╚═╝└─┘┴ ┴┘└┘{RESET}\n  Web Application Vulnerability Scanner v1.2\n")

def run_scanners(target, args):
    findings = []
    scanners = [HeaderScanner(target), SQLiScanner(target), XSSScanner(target),
        DirectoryScanner(target), InfoDisclosureScanner(target), CommandInjectionScanner(target)]
    if args.blind:
        scanners.append(BlindSQLiScanner(target))
    for s in scanners:
        if args.cookie: s.session.headers["Cookie"] = args.cookie
        print(f"\n  {BOLD}[*] {s.name}{RESET}\n      {GRAY}{s.description}{RESET}")
        try:
            for f in s.scan():
                findings.append(f)
                c = SEV_COLORS.get(f["severity"], "")
                print(f"      {c}[{f['severity']}]{RESET} {f['title']}")
        except Exception as e:
            print(f"      {RED}[!] Error: {e}{RESET}")
    return findings

def main():
    banner()
    p = argparse.ArgumentParser(description="WebVulnScan v1.2")
    p.add_argument("url", help="Target URL")
    p.add_argument("-o","--output", default=None, help="JSON report file")
    p.add_argument("--html", default=None, help="HTML report file")
    p.add_argument("-c","--cookie", default=None, help="Cookie string")
    p.add_argument("--crawl", action="store_true", help="Crawl site before scanning")
    p.add_argument("--max-pages", type=int, default=30, help="Max pages to crawl")
    p.add_argument("--blind", action="store_true", help="Enable blind SQLi testing")
    p.add_argument("--exploit", action="store_true", help="Exploit confirmed SQLi to extract data")
    p.add_argument("--dump", default=None, help="Table name to dump (use with --exploit)")
    args = p.parse_args()

    try: target = validate_url(args.url)
    except ValueError as e: print(f"  {RED}[!] {e}{RESET}"); sys.exit(1)

    print(f"  {BOLD}Target:{RESET}  {target}\n  {BOLD}Started:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.crawl: print(f"  {BOLD}Mode:{RESET}   Crawl + Scan (max {args.max_pages} pages)")
    if args.blind: print(f"  {BOLD}Blind:{RESET}  Time-based SQLi enabled")
    if args.exploit: print(f"  {BOLD}Exploit:{RESET} SQLi data extraction enabled")

    results = {"target": target, "scan_start": datetime.now().isoformat(), "findings": []}

    if args.crawl:
        from crawler import Crawler
        import requests as req
        print(f"\n  {BOLD}{CYAN}[PHASE 1] CRAWLING{RESET}")
        session = None
        if args.cookie:
            session = req.Session()
            session.headers["Cookie"] = args.cookie
            session.headers["User-Agent"] = "WebVulnScan/1.0"
        crawler = Crawler(target, max_pages=args.max_pages, session=session)
        cr = crawler.crawl()
        if cr.get("error"): print(f"      {RED}[!] {cr['error']}{RESET}"); sys.exit(1)
        print(f"\n      {GREEN}Done:{RESET} {cr['pages_crawled']} pages, {len(cr['urls_with_params'])} with params, {len(cr['forms'])} forms")
        scan_targets = [target] + [e["url"] for e in cr["urls_with_params"] if e["url"] != target]
        print(f"\n  {BOLD}{CYAN}[PHASE 2] SCANNING {len(scan_targets)} TARGETS{RESET}")
        for i, url in enumerate(scan_targets):
            print(f"\n  {BOLD}-- Target {i+1}/{len(scan_targets)}: {url[:70]}{RESET}")
            results["findings"].extend(run_scanners(url, args))
    else:
        results["findings"] = run_scanners(target, args)

    # Exploit phase
    if args.exploit:
        from sqli_exploit import SQLiExploiter
        import requests as req
        sqli_findings = [f for f in results["findings"] if "SQLi" in f["title"] and f["severity"] == "HIGH"]
        if sqli_findings:
            for sf in sqli_findings:
                try:
                    param = sf["title"].split("'")[1]
                except (IndexError, KeyError):
                    continue
                print(f"\n  {BOLD}{CYAN}[EXPLOIT] Extracting data via '{param}'{RESET}")
                session = req.Session()
                if args.cookie: session.headers["Cookie"] = args.cookie
                exploiter = SQLiExploiter(target, param, session)
                exploit_results = exploiter.run(dump_table_name=args.dump)
                if exploit_results.get("dumped_data"):
                    for tbl, data in exploit_results["dumped_data"].items():
                        results["findings"].append({
                            "scanner": "SQLi Exploiter",
                            "title": f"Data Extracted from '{tbl}'",
                            "severity": "HIGH",
                            "description": f"Successfully dumped {len(data['rows'])} rows from table '{tbl}'.",
                            "evidence": f"Columns: {', '.join(data['columns'])}\nRows: {len(data['rows'])}",
                            "remediation": "Use parameterized queries. Sensitive data was fully accessible.",
                        })
        else:
            print(f"\n  {YELLOW}[*] No confirmed SQLi found to exploit.{RESET}")

    results["scan_end"] = datetime.now().isoformat()

    # Deduplicate
    seen = set()
    unique = []
    for f in results["findings"]:
        key = (f["scanner"], f["title"], f.get("evidence",""))
        if key not in seen: seen.add(key); unique.append(f)
    results["findings"] = unique

    h=sum(1 for f in unique if f["severity"]=="HIGH")
    m=sum(1 for f in unique if f["severity"]=="MEDIUM")
    l=sum(1 for f in unique if f["severity"]=="LOW")
    print(f"\n  {'='*50}\n  {BOLD}SCAN COMPLETE — {len(unique)} unique findings{RESET}")
    print(f"  {RED}HIGH: {h}{RESET}  {YELLOW}MEDIUM: {m}{RESET}  {BLUE}LOW: {l}{RESET}\n  {'='*50}")

    if args.output:
        with open(args.output,"w") as f: json.dump(generate_report(results),f,indent=2)
        print(f"\n  {BOLD}[*] JSON:{RESET} {args.output}")
    if args.html:
        with open(args.html,"w") as f: f.write(generate_html_report(results))
        print(f"  {BOLD}[*] HTML:{RESET} {args.html}")
    print()

if __name__ == "__main__":
    main()
