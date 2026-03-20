from scanners import BaseScanner

class HeaderScanner(BaseScanner):
    name = "Security Headers"
    description = "Checks for missing or misconfigured HTTP security headers."

    EXPECTED_HEADERS = [
        ("Strict-Transport-Security", "HIGH", "HSTS missing — vulnerable to SSL-stripping.", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "MEDIUM", "Missing — browser may MIME-sniff responses.", "Add X-Content-Type-Options: nosniff"),
        ("X-Frame-Options", "MEDIUM", "Missing — site can be embedded in iframes (clickjacking).", "Add X-Frame-Options: DENY"),
        ("Content-Security-Policy", "MEDIUM", "No CSP — XSS attacks are easier to exploit.", "Define a Content-Security-Policy header."),
        ("X-XSS-Protection", "LOW", "Legacy XSS filter header missing.", "Add X-XSS-Protection: 1; mode=block"),
        ("Referrer-Policy", "LOW", "May leak sensitive URLs to other sites.", "Add Referrer-Policy: strict-origin-when-cross-origin"),
        ("Permissions-Policy", "LOW", "No restrictions on browser features.", "Add Permissions-Policy header."),
    ]

    def scan(self):
        findings = []
        try:
            resp = self.get()
        except Exception as e:
            return [self.finding("Connection Failed", "HIGH", str(e))]
        headers = resp.headers
        for name, sev, desc, fix in self.EXPECTED_HEADERS:
            if name.lower() not in {k.lower() for k in headers}:
                findings.append(self.finding(f"Missing {name}", sev, desc, f"'{name}' not in response.", fix))
        for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            val = headers.get(h)
            if val:
                findings.append(self.finding(f"Info Disclosure: {h}", "LOW", f"'{h}' reveals server technology.", f"{h}: {val}", f"Remove the '{h}' header."))
        return findings or [self.finding("All security headers present", "INFO", "Expected headers found.")]
