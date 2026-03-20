#!/usr/bin/env python3
import argparse, json, sys
from datetime import datetime
from urllib.parse import urlparse
from scanners.header_scanner import HeaderScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.directory_scanner import DirectoryScanner
from scanners.info_disclosure_scanner import InfoDisclosureScanner
from report import generate_report

def validate_url(url):
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    if not urlparse(url).netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url.rstrip("/")

def main():
    print("\n  WebVulnScanner — Web Application Vulnerability Scanner\n")
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--output", "-o", default=None, help="Save JSON report")
    parser.add_argument("--cookie", "-c", default=None, help="Cookie string")
    args = parser.parse_args()
    try:
        target = validate_url(args.url)
    except ValueError as e:
        print(f"[!] {e}"); sys.exit(1)
    print(f"[*] Target: {target}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    results = {"target": target, "scan_start": datetime.now().isoformat(), "findings": []}
    scanners = [HeaderScanner(target), SQLiScanner(target), XSSScanner(target), DirectoryScanner(target), InfoDisclosureScanner(target)]
    for s in scanners:
        if args.cookie:
            s.session.headers["Cookie"] = args.cookie
        print(f"\n[*] Running: {s.name}")
        try:
            for f in s.scan():
                results["findings"].append(f)
                colors = {"HIGH":"\033[91m","MEDIUM":"\033[93m","LOW":"\033[94m","INFO":"\033[90m"}
                print(f"    {colors.get(f['severity'],'')}{f['severity']}\033[0m — {f['title']}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    results["scan_end"] = datetime.now().isoformat()
    h = sum(1 for f in results["findings"] if f["severity"]=="HIGH")
    m = sum(1 for f in results["findings"] if f["severity"]=="MEDIUM")
    l = sum(1 for f in results["findings"] if f["severity"]=="LOW")
    print(f"\n{'='*50}\n  SUMMARY: {len(results['findings'])} findings")
    print(f"  \033[91mHIGH: {h}\033[0m | \033[93mMEDIUM: {m}\033[0m | \033[94mLOW: {l}\033[0m\n{'='*50}")
    if args.output:
        with open(args.output,"w") as f:
            json.dump(generate_report(results), f, indent=2)
        print(f"[*] Report saved to {args.output}")
    print("[*] Done.")

if __name__ == "__main__":
    main()
