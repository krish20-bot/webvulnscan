from scanners import BaseScanner

class DirectoryScanner(BaseScanner):
    name = "Directory Enumeration"
    description = "Probes for exposed sensitive files and directories."
    PATHS = [
        ("/admin", "Admin panel"), ("/administrator", "Admin panel"),
        ("/wp-admin", "WordPress admin"), ("/wp-login.php", "WordPress login"),
        ("/phpmyadmin", "phpMyAdmin"), ("/.env", "Environment config"),
        ("/.git/HEAD", "Git repository"), ("/robots.txt", "Robots file"),
        ("/sitemap.xml", "Sitemap"), ("/phpinfo.php", "PHP info"),
        ("/server-status", "Apache status"), ("/swagger.json", "API docs"),
        ("/backup.sql", "Database backup"), ("/config.php", "PHP config"),
        ("/crossdomain.xml", "Flash policy"), ("/graphql", "GraphQL endpoint"),
    ]
    SEVERITY_MAP = {"/.env": "HIGH", "/.git/HEAD": "HIGH", "/backup.sql": "HIGH", "/phpinfo.php": "MEDIUM", "/phpmyadmin": "MEDIUM"}

    def scan(self):
        findings = []
        for path, label in self.PATHS:
            url = self.build_url(path)
            try:
                resp = self.get(url, allow_redirects=False)
            except Exception:
                continue
            if resp.status_code == 200:
                if path == "/.git/HEAD" and not resp.text.strip().startswith("ref:"):
                    continue
                findings.append(self.finding(
                    f"Exposed: {path}", self.SEVERITY_MAP.get(path, "LOW"),
                    f"'{label}' is publicly accessible.", f"HTTP 200 — {url} ({len(resp.content)} bytes)",
                    "Restrict access or move out of web root."))
            elif resp.status_code == 403:
                findings.append(self.finding(f"Forbidden: {path}", "INFO", f"'{label}' exists but is blocked.", f"HTTP 403 — {url}"))
        return findings or [self.finding("No Exposed Directories", "INFO", "No sensitive paths found.")]
