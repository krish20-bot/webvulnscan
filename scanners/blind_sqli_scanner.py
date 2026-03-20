"""Scanner: Blind SQL Injection (Time-Based)"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseScanner

class BlindSQLiScanner(BaseScanner):
    name = "Blind SQL Injection"
    description = "Tests URL parameters for time-based blind SQL injection."
    SLEEP_TIME = 3
    THRESHOLD = 2.5
    CONFIRM_ROUNDS = 2
    PAYLOADS = [
        {"payload": "' AND SLEEP({sleep})--", "db": "MySQL"},
        {"payload": "' OR SLEEP({sleep})--", "db": "MySQL"},
        {"payload": "1' AND (SELECT SLEEP({sleep}))--", "db": "MySQL"},
        {"payload": "'; SELECT pg_sleep({sleep})--", "db": "PostgreSQL"},
        {"payload": "' AND (SELECT pg_sleep({sleep}))--", "db": "PostgreSQL"},
        {"payload": "'; WAITFOR DELAY '0:0:{sleep}'--", "db": "SQL Server"},
        {"payload": "1 AND SLEEP({sleep})", "db": "MySQL (numeric)"},
    ]

    def measure_response_time(self, url):
        start = time.time()
        try:
            self.get(url, timeout=self.SLEEP_TIME + 10)
        except Exception:
            pass
        return time.time() - start

    def scan(self):
        findings = []
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [self.finding("No URL Parameters", "INFO", "No parameters to test.")]
        print(f"      Measuring baseline response time...")
        baseline_times = [self.measure_response_time(self.target_url) for _ in range(3)]
        baseline_avg = sum(baseline_times) / len(baseline_times)
        print(f"      Baseline: {baseline_avg:.2f}s average")
        for param_name in params:
            found = False
            orig = params[param_name][0]
            for entry in self.PAYLOADS:
                payload = entry["payload"].replace("{sleep}", str(self.SLEEP_TIME))
                test_params = dict(params)
                test_params[param_name] = [orig + payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                response_time = self.measure_response_time(test_url)
                delay = response_time - baseline_avg
                if delay < self.THRESHOLD:
                    continue
                confirmed = sum(1 for _ in range(self.CONFIRM_ROUNDS)
                    if self.measure_response_time(test_url) - baseline_avg >= self.THRESHOLD)
                if confirmed >= self.CONFIRM_ROUNDS:
                    findings.append(self.finding(
                        f"Blind SQLi in '{param_name}' ({entry['db']})", "HIGH",
                        f"Time-based blind SQLi detected. SLEEP caused {delay:.1f}s delay vs {baseline_avg:.2f}s baseline.",
                        f"Payload: {payload}\nBaseline: {baseline_avg:.2f}s\nWith payload: {response_time:.2f}s\nConfirmed: {confirmed}/{self.CONFIRM_ROUNDS}",
                        "Use parameterized queries. This vulnerability exists even without visible error messages."))
                    found = True
                    break
            if found:
                continue
        return findings or [self.finding("No Blind SQLi Detected", "INFO", "No time-based delays observed.")]
