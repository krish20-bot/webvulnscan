"""Scanner: OS Command Injection"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseScanner

class CommandInjectionScanner(BaseScanner):
    name = "Command Injection"
    description = "Tests URL parameters for OS command injection vulnerabilities."
    MARKER = "WVSCMD7392"
    PAYLOADS = [
        {"inject": f"; echo WVSCMD7392", "os": "Linux"},
        {"inject": f"| echo WVSCMD7392", "os": "Linux"},
        {"inject": f"& echo WVSCMD7392", "os": "Linux"},
        {"inject": f"&& echo WVSCMD7392", "os": "Linux"},
        {"inject": f"|| echo WVSCMD7392", "os": "Linux"},
        {"inject": f"`echo WVSCMD7392`", "os": "Linux"},
        {"inject": f"$(echo WVSCMD7392)", "os": "Linux"},
    ]
    RECON_PAYLOADS = [
        {"inject": "; id", "patterns": ["uid=", "gid="], "os": "Linux"},
        {"inject": "| cat /etc/passwd", "patterns": ["root:x:", "root:*:"], "os": "Linux"},
        {"inject": "& whoami", "patterns": ["www-data", "root", "apache"], "os": "Linux"},
    ]

    def scan(self):
        findings = []
        try:
            baseline = self.get()
            baseline_text = baseline.text
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [self.finding("No URL Parameters", "INFO", "No parameters to test.")]
        for param_name in params:
            found = False
            orig = params[param_name][0]
            for p in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [orig + p["inject"]]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = self.get(test_url)
                except Exception:
                    continue
                if self.MARKER in resp.text and self.MARKER not in baseline_text:
                    findings.append(self.finding(f"Command Injection in '{param_name}'", "HIGH",
                        f"Parameter '{param_name}' executes OS commands ({p['os']}).",
                        f"Payload: {p['inject']}\nMarker found in response.",
                        "Never pass user input to OS commands. Use language-native APIs."))
                    found = True
                    break
            if found:
                continue
            for p in self.RECON_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [orig + p["inject"]]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = self.get(test_url)
                except Exception:
                    continue
                for pattern in p["patterns"]:
                    if pattern in resp.text and pattern not in baseline_text:
                        findings.append(self.finding(f"Possible Command Injection in '{param_name}'", "HIGH",
                            f"System command output detected in response.",
                            f"Payload: {p['inject']}\nPattern: {pattern}",
                            "Never pass user input to OS commands."))
                        found = True
                        break
                if found:
                    break
        return findings or [self.finding("No Command Injection", "INFO", "No command execution detected.")]
