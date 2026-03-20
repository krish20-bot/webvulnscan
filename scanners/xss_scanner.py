from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseScanner

class XSSScanner(BaseScanner):
    name = "Cross-Site Scripting (XSS)"
    description = "Tests URL parameters for reflected XSS vulnerabilities."
    PAYLOADS = [
        {"payload": '<script>alert("xSs")</script>', "check": '<script>alert("xSs")</script>'},
        {"payload": '"><img src=x onerror=alert("xSs")>', "check": 'onerror=alert("xSs")'},
        {"payload": "<svg/onload=alert('xSs')>", "check": "<svg/onload=alert('xSs')>"},
    ]

    def scan(self):
        findings = []
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [self.finding("No URL Parameters", "INFO", "No query parameters to test for XSS.")]
        for param_name in params:
            for entry in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [entry["payload"]]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = self.get(test_url)
                except Exception:
                    continue
                if entry["check"] in resp.text:
                    findings.append(self.finding(
                        f"Reflected XSS in '{param_name}'", "HIGH",
                        f"'{param_name}' is echoed unescaped into the response.",
                        f"Payload: {entry['payload']}", "HTML-encode all user input. Use CSP headers."))
                    break
        return findings or [self.finding("No Reflected XSS Detected", "INFO", "Payloads were not reflected unescaped.")]
