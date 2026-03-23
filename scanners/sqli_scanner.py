"""Scanner: SQL Injection (Error-Based)"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseScanner

class SQLiScanner(BaseScanner):
    name = "SQL Injection"
    description = "Tests URL parameters for error-based SQL injection vulnerabilities."
    PAYLOADS = ["'", "''", "1' OR '1'='1", "1 OR 1=1", "' OR ''='", "' UNION SELECT NULL--"]
    ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning.*?\bmysql", r"unclosed quotation mark",
        r"pg_query\(\)", r"valid PostgreSQL result",
        r"microsoft.*?odbc.*?driver", r"incorrect syntax near",
        r"ORA-\d{5}", r"sqlite3\.OperationalError",
        r"sql syntax.*?error", r"quoted string not properly terminated",
    ]

    def scan(self):
        findings = []
        try:
            baseline_text = self.get().text
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [self.finding("No URL Parameters", "INFO", "No query parameters to test.")]
        for param_name in params:
            found = False
            for payload in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp_text = self.get(test_url).text
                except Exception:
                    continue
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, resp_text, re.IGNORECASE) and not re.search(pattern, baseline_text, re.IGNORECASE):
                        findings.append(self.finding(
                            f"Possible SQLi in '{param_name}'", "HIGH",
                            f"Parameter '{param_name}' triggered a DB error.",
                            f"Payload: {payload}\nPattern: {pattern}",
                            "Use parameterized queries / prepared statements."))
                        found = True; break
                if found: break
        return findings or [self.finding("No SQLi Detected", "INFO", "No DB errors triggered.")]
