#!/usr/bin/env python3
"""WebVulnScan v2.0 — Vulnerability Scanner & Exploitation Framework"""
import argparse,json,sys
from datetime import datetime
from urllib.parse import urlparse
from scanners.header_scanner import HeaderScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.directory_scanner import DirectoryScanner
from scanners.info_disclosure_scanner import InfoDisclosureScanner
from scanners.cmdi_scanner import CommandInjectionScanner
from scanners.blind_sqli_scanner import BlindSQLiScanner
from scanners.form_scanner import FormScanner
from scanners.ssl_scanner import SSLScanner
from report import generate_report
from html_report import generate_html_report

RED="\033[91m";YELLOW="\033[93m";BLUE="\033[94m";GRAY="\033[90m";GREEN="\033[92m";CYAN="\033[96m";RESET="\033[0m";BOLD="\033[1m"
SEV={"HIGH":RED,"MEDIUM":YELLOW,"LOW":BLUE,"INFO":GRAY}

def validate_url(url):
    if not url.startswith(("http://","https://")): url="http://"+url
    if not urlparse(url).netloc: raise ValueError(f"Invalid URL: {url}")
    return url.rstrip("/")

def banner():
    print(f"\n{BOLD}  ╦ ╦┌─┐┌┐ ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐┌┐┌\n  ║║║├┤ ├┴┐╚╗╔╝│ ││  │││╚═╗│  ├─┤│││\n  ╚╩╝└─┘└─┘ ╚╝ └─┘┴─┘┘└┘╚═╝└─┘┴ ┴┘└┘{RESET}\n  Vulnerability Scanner & Exploitation Framework v2.0\n")

def run_scanners(target, args):
    findings=[]
    scanners=[HeaderScanner(target),SQLiScanner(target),XSSScanner(target),DirectoryScanner(target),
        InfoDisclosureScanner(target),CommandInjectionScanner(target),FormScanner(target),SSLScanner(target)]
    if args.blind: scanners.append(BlindSQLiScanner(target))
    for s in scanners:
        if args.cookie: s.session.headers["Cookie"]=args.cookie
        print(f"\n  {BOLD}[*] {s.name}{RESET}\n      {GRAY}{s.description}{RESET}")
        try:
            for f in s.scan():
                findings.append(f)
                print(f"      {SEV.get(f['severity'],'')}{f['severity']}{RESET} — {f['title']}")
        except Exception as e:
            print(f"      {RED}[!] {e}{RESET}")
    return findings

def main():
    banner()
    p=argparse.ArgumentParser(description="WebVulnScan v2.0")
    p.add_argument("url",help="Target URL")
    p.add_argument("-o","--output",default=None,help="JSON report")
    p.add_argument("--html",default=None,help="HTML report")
    p.add_argument("-c","--cookie",default=None,help="Cookie string")
    p.add_argument("--crawl",action="store_true",help="Crawl site first")
    p.add_argument("--max-pages",type=int,default=30,help="Max crawl pages")
    p.add_argument("--blind",action="store_true",help="Blind SQLi testing")
    p.add_argument("--exploit",action="store_true",help="Exploit SQLi")
    p.add_argument("--dump",default=None,help="Table to dump")
    p.add_argument("--subdomains",action="store_true",help="Enumerate subdomains")
    p.add_argument("--ports",action="store_true",help="Port scan")
    p.add_argument("--full",action="store_true",help="Enable everything")
    args=p.parse_args()
    if args.full: args.crawl=True;args.blind=True;args.subdomains=True;args.ports=True
    try: target=validate_url(args.url)
    except ValueError as e: print(f"  {RED}[!] {e}{RESET}");sys.exit(1)
    print(f"  {BOLD}Target:{RESET}  {target}\n  {BOLD}Started:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    modes=[n for n,v in [("Crawl",args.crawl),("Blind",args.blind),("Exploit",args.exploit),("Subdomains",args.subdomains),("Ports",args.ports)] if v]
    if modes: print(f"  {BOLD}Modes:{RESET}   {', '.join(modes)}")
    results={"target":target,"scan_start":datetime.now().isoformat(),"findings":[]}

    if args.subdomains:
        from subdomain_enum import SubdomainEnumerator
        print(f"\n  {BOLD}{CYAN}[RECON] SUBDOMAIN ENUMERATION{RESET}\n  {'─'*44}")
        for s in SubdomainEnumerator(target).enumerate()["subdomains"]:
            results["findings"].append({"scanner":"Subdomain Enumeration","title":f"Subdomain: {s['subdomain']}","severity":"INFO","description":f"Active subdomain found.","evidence":f"IPs: {', '.join(s['ips'])}","remediation":"Ensure all subdomains are secured."})

    if args.ports:
        from port_scanner import PortScanner
        print(f"\n  {BOLD}{CYAN}[RECON] PORT SCANNING{RESET}\n  {'─'*44}")
        for pr in PortScanner(target).scan()["open_ports"]:
            sev="MEDIUM" if pr.get("risk") else "INFO"
            results["findings"].append({"scanner":"Port Scanner","title":f"Open: {pr['port']}/{pr['service']}","severity":sev,"description":pr.get("risk",f"Port {pr['port']} open."),"evidence":f"Port {pr['port']} ({pr['service']})","remediation":"Close unnecessary ports."})

    if args.crawl:
        from crawler import Crawler
        import requests as req
        print(f"\n  {BOLD}{CYAN}[PHASE 1] CRAWLING{RESET}\n  {'─'*44}")
        session=None
        if args.cookie: session=req.Session();session.headers["Cookie"]=args.cookie;session.headers["User-Agent"]="WebVulnScan/2.0"
        cr=Crawler(target,max_pages=args.max_pages,session=session).crawl()
        if cr.get("error"): print(f"      {RED}[!] {cr['error']}{RESET}")
        else:
            print(f"\n      {GREEN}Done:{RESET} {cr['pages_crawled']} pages, {len(cr['urls_with_params'])} params, {len(cr['forms'])} forms")
            targets=[target]+[e["url"] for e in cr["urls_with_params"] if e["url"]!=target]
            print(f"\n  {BOLD}{CYAN}[PHASE 2] SCANNING {len(targets)} TARGETS{RESET}\n  {'─'*44}")
            for i,u in enumerate(targets):
                print(f"\n  {BOLD}── Target {i+1}/{len(targets)}: {u[:70]}{RESET}")
                results["findings"].extend(run_scanners(u,args))
    else:
        print(f"\n  {BOLD}{CYAN}[SCANNING]{RESET}\n  {'─'*44}")
        results["findings"]=run_scanners(target,args)

    if args.exploit:
        from sqli_exploit import SQLiExploiter
        import requests as req
        sqli=[f for f in results["findings"] if "SQLi" in f["title"] and f["severity"]=="HIGH"]
        if sqli:
            for sf in sqli:
                try: param=sf["title"].split("'")[1]
                except: continue
                print(f"\n  {BOLD}{CYAN}[EXPLOIT] Extracting via '{param}'{RESET}\n  {'─'*44}")
                session=req.Session()
                if args.cookie: session.headers["Cookie"]=args.cookie
                er=SQLiExploiter(target,param,session).run(dump_table_name=args.dump)
                if er.get("dumped_data"):
                    for t,d in er["dumped_data"].items():
                        results["findings"].append({"scanner":"SQLi Exploiter","title":f"Data from '{t}'","severity":"HIGH","description":f"Dumped {len(d['rows'])} rows.","evidence":f"Columns: {', '.join(d['columns'])}","remediation":"Use parameterized queries."})
        else: print(f"\n  {YELLOW}[*] No SQLi to exploit.{RESET}")

    results["scan_end"]=datetime.now().isoformat()
    seen=set();unique=[]
    for f in results["findings"]:
        k=(f["scanner"],f["title"],f.get("evidence",""))
        if k not in seen: seen.add(k);unique.append(f)
    results["findings"]=unique
    h=sum(1 for f in unique if f["severity"]=="HIGH")
    m=sum(1 for f in unique if f["severity"]=="MEDIUM")
    l=sum(1 for f in unique if f["severity"]=="LOW")
    i=sum(1 for f in unique if f["severity"]=="INFO")
    print(f"\n  {'═'*50}\n  {BOLD}SCAN COMPLETE — {len(unique)} findings{RESET}")
    print(f"  {RED}HIGH: {h}{RESET}  {YELLOW}MEDIUM: {m}{RESET}  {BLUE}LOW: {l}{RESET}  {GRAY}INFO: {i}{RESET}\n  {'═'*50}")
    if args.output:
        with open(args.output,"w") as f: json.dump(generate_report(results),f,indent=2)
        print(f"\n  {BOLD}[*] JSON:{RESET} {args.output}")
    if args.html:
        with open(args.html,"w") as f: f.write(generate_html_report(results))
        print(f"  {BOLD}[*] HTML:{RESET} {args.html}")
    print()

if __name__=="__main__": main()
