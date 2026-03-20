"""Web Crawler — Discovers endpoints across a target site."""
import re
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None
import requests

class Crawler:
    def __init__(self, base_url, max_pages=50, session=None):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "WebVulnScan/1.0 Crawler")
        self.visited = set()
        self.urls_with_params = []
        self.forms = []
        self.all_urls = set()

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def normalize_url(self, url):
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl().rstrip("/")

    def extract_links(self, soup, page_url):
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = self.normalize_url(urljoin(page_url, href))
            if self.is_same_domain(full_url):
                links.append(full_url)
        return links

    def extract_forms(self, soup, page_url):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(page_url, action) if action else page_url
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    fields.append({"name": name, "type": inp.get("type", "text"), "value": inp.get("value", "")})
            if fields:
                forms.append({"action": form_url, "method": method, "fields": fields, "source_page": page_url})
        return forms

    def crawl(self):
        if BeautifulSoup is None:
            return {"error": "beautifulsoup4 required. Install: pip install beautifulsoup4", "urls": [], "urls_with_params": [], "forms": []}
        queue = deque([self.base_url])
        self.visited.add(self.normalize_url(self.base_url))
        print(f"      Crawling {self.base_url} (max {self.max_pages} pages)...")
        while queue and len(self.visited) < self.max_pages:
            current_url = queue.popleft()
            try:
                resp = self.session.get(current_url, timeout=10, allow_redirects=True)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
            except Exception:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            parsed = urlparse(current_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                if params and current_url not in [u["url"] for u in self.urls_with_params]:
                    self.urls_with_params.append({"url": current_url, "params": list(params.keys())})
            self.forms.extend(self.extract_forms(soup, current_url))
            for link in self.extract_links(soup, current_url):
                normalized = self.normalize_url(link)
                self.all_urls.add(normalized)
                if normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append(link)
            print(f"      [{len(self.visited)}/{self.max_pages}] {current_url[:80]}")
        return {"urls": sorted(self.all_urls), "urls_with_params": self.urls_with_params, "forms": self.forms, "pages_crawled": len(self.visited)}
