"""Subdomain Enumeration via DNS brute-forcing."""
import socket
from urllib.parse import urlparse

class SubdomainEnumerator:
    WORDLIST = ["www","mail","ftp","admin","dev","staging","test","api","app","blog","shop","store",
        "portal","vpn","remote","webmail","email","smtp","cdn","media","static","assets",
        "db","database","mysql","postgres","redis","mongo","git","gitlab","jenkins","ci",
        "docker","registry","dashboard","monitor","grafana","kibana","elastic",
        "backup","old","new","beta","alpha","demo","sandbox","qa","uat","preprod",
        "internal","intranet","auth","login","sso","payment","billing",
        "support","help","docs","wiki","forum","m","mobile",
        "v1","v2","api-v1","api-v2","proxy","gateway","s3","storage",
        "status","health","cpanel","phpmyadmin","adminer"]

    def __init__(self, target_url):
        parsed = urlparse(target_url)
        parts = parsed.hostname.split(".")
        self.base_domain = ".".join(parts[-2:]) if len(parts) > 2 else parsed.hostname

    def enumerate(self):
        print(f"      Enumerating subdomains for {self.base_domain} ({len(self.WORDLIST)} words)...")
        found = []
        for i, word in enumerate(self.WORDLIST):
            fqdn = f"{word}.{self.base_domain}"
            try:
                ips = list(set(r[4][0] for r in socket.getaddrinfo(fqdn, None, socket.AF_INET)))
                if ips:
                    found.append({"subdomain": fqdn, "ips": ips})
                    print(f"      [+] {fqdn} -> {', '.join(ips)}")
            except (socket.gaierror, socket.timeout, OSError):
                pass
            if (i+1) % 20 == 0:
                print(f"      [{i+1}/{len(self.WORDLIST)}] checked...")
        print(f"      Found {len(found)} subdomains")
        return {"base_domain": self.base_domain, "subdomains": found}
