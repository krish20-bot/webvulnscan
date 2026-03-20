import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseScanner

class SQLiScanner(BaseScanner):
    name = "SQL Injection"
    description = "Tests URL parameters for basic SQL injection vulnerabilities."
    PAYLOADS = ["'", "''", "1' OR '1'='1", "1 OR 1=1", "' OR ''='", "1' AND '1'='2", "' UNION SELECT NULL--"]
    ERROR_PATTERNS = [
        r"you have an error in your sql syntax", r"warning.*?\bmysql", r"unclosed quotation mark",
        r"pg_query\(\)", r"valid PostgreSQL result", r"microsoft.*?odbc.*?driver",
        r"incorrect syntax near", r"ORA-\d{5}", r"sqlite3\.OperationalError",
        r"quoted string not properly terminated", r"sql syntax.*?error",
    ]

    def scan(self):
        findings = []
        try:
            baseline = self.get()
            baseline_text = baseline.text.lower()
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [self.finding("No URL Parameters", "INFO", "No query parameters to test. Try a URL like: ?id=1")]
        for param_name in params:
            for payload in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = self.get(test_url)
                except Exception:
                    continue
                for pattern in self.ERROR_PATTERNS:
                    match = re.search(pattern, resp.text.lower(), re.IGNORECASE)
                    if match and not re.search(pattern, baseline_text, re.IGNORECASE):
                        findings.append(self.finding(
                            f"Possible SQLi in '{param_name}'", "HIGH",
                            f"Parameter '{param_name}' triggered a DB error.",
                            f"Payload: {payload}\nMatched: {match.group()}",
                            "Use parameterized queries / prepared statements."))
                        break
                else:
                    continue
                break
        return findings or [self.finding("No SQLi Detected", "INFO", "No DB errors triggered. Blind SQLi not tested.")]
