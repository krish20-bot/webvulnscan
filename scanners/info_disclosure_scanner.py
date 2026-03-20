import re
from scanners import BaseScanner

class InfoDisclosureScanner(BaseScanner):
    name = "Information Disclosure"
    description = "Looks for leaked sensitive data in responses."
    PATTERNS = [
        {"name": "Internal IP", "regex": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "severity": "MEDIUM", "desc": "Internal IP address found."},
        {"name": "Email Address", "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "severity": "LOW", "desc": "Email exposed — can be used for phishing."},
        {"name": "Stack Trace", "regex": r"(Traceback \(most recent call last\)|Fatal error:|Exception in thread)", "severity": "MEDIUM", "desc": "Error details reveal internal code structure."},
        {"name": "Sensitive HTML Comment", "regex": r"<!--[\s\S]*?(TODO|FIXME|password|secret|key|token)[\s\S]*?-->", "severity": "LOW", "desc": "HTML comment contains sensitive keywords."},
        {"name": "Directory Listing", "regex": r"<title>Index of /|Directory listing for", "severity": "MEDIUM", "desc": "Directory listing enabled."},
        {"name": "Version Number", "regex": r"(Apache|Nginx|PHP|WordPress|Django|Rails|Express|Laravel)[/ ]\d+\.\d+", "severity": "LOW", "desc": "Software version exposed."},
    ]

    def scan(self):
        findings = []
        try:
            resp = self.get()
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]
        for p in self.PATTERNS:
            matches = re.findall(p["regex"], resp.text, re.IGNORECASE)
            if matches:
                unique = list(set(str(m) for m in matches))[:5]
                findings.append(self.finding(p["name"], p["severity"], p["desc"],
                    f"Found {len(matches)}: {', '.join(unique)}", "Remove sensitive info from public responses."))
        if self.parsed_url.scheme == "http":
            findings.append(self.finding("HTTP (not HTTPS)", "MEDIUM", "Data transmitted in cleartext.", f"Scheme: http", "Enable HTTPS."))
        return findings or [self.finding("No Info Disclosure", "INFO", "No obvious leaks found.")]
