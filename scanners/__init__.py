"""Base class for all vulnerability scanners."""

import requests
from urllib.parse import urlparse, urljoin


class BaseScanner:
    name = "Base Scanner"
    description = "Override this in your scanner module."
    TIMEOUT = 10
    USER_AGENT = "WebVulnScanner/1.0 (Educational Project)"

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        self.session.verify = True

    def scan(self) -> list[dict]:
        raise NotImplementedError

    def finding(self, title, severity, description, evidence="", remediation=""):
        return {
            "scanner": self.name, "title": title, "severity": severity,
            "description": description, "evidence": evidence, "remediation": remediation,
        }

    def get(self, url=None, **kwargs):
        url = url or self.target_url
        kwargs.setdefault("timeout", self.TIMEOUT)
        return self.session.get(url, **kwargs)

    def build_url(self, path):
        return urljoin(self.target_url + "/", path.lstrip("/"))
