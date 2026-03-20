# Writing Custom Scanner Modules

Every scanner inherits from `BaseScanner` and implements one method: `scan()`.

## Quick Template

Create `scanners/my_scanner.py`:
```python
from scanners import BaseScanner


class MyScanner(BaseScanner):
    name = "My Custom Scanner"
    description = "Checks for [what it checks for]."

    def scan(self):
        findings = []
        try:
            resp = self.get()
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]

        if "DEBUG = True" in resp.text:
            findings.append(self.finding(
                title="Debug Mode Enabled",
                severity="HIGH",
                description="Application is running in debug mode.",
                evidence="Found 'DEBUG = True' in response.",
                remediation="Disable debug mode in production.",
            ))

        return findings or [self.finding("No Issues", "INFO", "All checks passed.")]
```

Then add to `main.py`:
```python
from scanners.my_scanner import MyScanner

scanners = [
    # ... existing scanners ...
    MyScanner(target),
]
```

## Severity Levels

| Level | Use For |
|-------|---------|
| HIGH | Direct exploitation (SQLi, XSS, RCE, exposed secrets) |
| MEDIUM | Increases attack surface (missing CSP, HTTP, info leaks) |
| LOW | Best-practice violations (optional headers, version disclosure) |
| INFO | Informational, no direct risk |

## Available Methods

| Method | Description |
|--------|-------------|
| `self.get(url)` | GET request with timeout |
| `self.build_url(path)` | Join path onto target base URL |
| `self.finding(...)` | Create standardized finding dict |
| `self.session` | Shared requests.Session |
| `self.target_url` | Full target URL |
| `self.parsed_url` | Parsed URL object |

## Tips

- Always compare against a baseline response
- One finding per parameter is enough
- Wrap `self.get()` in try/except
- Use unique markers instead of destructive payloads
