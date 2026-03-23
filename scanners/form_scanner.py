"""Scanner: Form-Based Injection Testing + CSRF Detection"""
import re
from urllib.parse import urljoin
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None
from scanners import BaseScanner

class FormScanner(BaseScanner):
    name = "Form-Based Injection"
    description = "Tests HTML forms for SQLi, XSS, command injection, and missing CSRF tokens."
    SQLI_PAYLOADS = [
        {"payload": "'", "patterns": [r"you have an error in your sql syntax", r"warning.*?\bmysql", r"unclosed quotation mark", r"ORA-\d{5}", r"sqlite3\.OperationalError", r"sql syntax.*?error"]},
    ]
    XSS_PAYLOADS = [
        {"payload": '<script>alert("xSsF")</script>', "check": '<script>alert("xSsF")</script>'},
        {"payload": '"><img src=x onerror=alert("xSsF")>', "check": 'onerror=alert("xSsF")'},
    ]
    CMDI_PAYLOADS = [
        {"payload": "; echo FORMCMD9182", "marker": "FORMCMD9182"},
        {"payload": "| echo FORMCMD9182", "marker": "FORMCMD9182"},
    ]

    def extract_forms(self, url):
        if not BeautifulSoup: return []
        try:
            resp = self.get(url)
        except Exception:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url
            fields = {}
            testable = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name: continue
                itype = inp.get("type", "text").lower()
                fields[name] = inp.get("value", "")
                if itype not in ["hidden", "submit", "button", "image"]:
                    testable.append(name)
            if fields:
                forms.append({"action": form_url, "method": method, "fields": fields, "testable": testable})
        return forms

    def submit_form(self, form, values):
        try:
            if form["method"] == "POST":
                return self.session.post(form["action"], data=values, timeout=self.TIMEOUT).text
            return self.session.get(form["action"], params=values, timeout=self.TIMEOUT).text
        except Exception:
            return ""

    def scan(self):
        findings = []
        if not BeautifulSoup:
            return [self.finding("BeautifulSoup Required", "INFO", "pip install beautifulsoup4")]
        try:
            baseline = self.get().text
        except Exception as e:
            return [self.finding("Connection Failed", "INFO", str(e))]
        forms = self.extract_forms(self.target_url)
        if not forms:
            return [self.finding("No Forms Found", "INFO", "No HTML forms on this page.")]
        print(f"      Found {len(forms)} form(s)")
        for form in forms:
            testable = form["testable"] or list(form["fields"].keys())
            for field in testable:
                for sqli in self.SQLI_PAYLOADS:
                    vals = dict(form["fields"]); vals[field] = sqli["payload"]
                    resp = self.submit_form(form, vals)
                    for pat in sqli["patterns"]:
                        if re.search(pat, resp, re.IGNORECASE) and not re.search(pat, baseline, re.IGNORECASE):
                            findings.append(self.finding(f"Form SQLi in '{field}' ({form['method']} {form['action'][:50]})", "HIGH",
                                f"Form field '{field}' triggered DB error via {form['method']}.",
                                f"Action: {form['action']}\nField: {field}\nPayload: {sqli['payload']}",
                                "Use parameterized queries.")); break
                    else: continue
                    break
                for xss in self.XSS_PAYLOADS:
                    vals = dict(form["fields"]); vals[field] = xss["payload"]
                    resp = self.submit_form(form, vals)
                    if xss["check"] in resp:
                        findings.append(self.finding(f"Form XSS in '{field}' ({form['method']} {form['action'][:50]})", "HIGH",
                            f"Form field '{field}' reflects input unescaped via {form['method']}.",
                            f"Action: {form['action']}\nField: {field}\nPayload: {xss['payload']}",
                            "HTML-encode all form input.")); break
                for cmdi in self.CMDI_PAYLOADS:
                    vals = dict(form["fields"]); vals[field] = vals.get(field, "") + cmdi["payload"]
                    resp = self.submit_form(form, vals)
                    if cmdi["marker"] in resp and cmdi["marker"] not in baseline:
                        findings.append(self.finding(f"Form CmdI in '{field}' ({form['method']} {form['action'][:50]})", "HIGH",
                            f"Form field '{field}' executes OS commands via {form['method']}.",
                            f"Action: {form['action']}\nField: {field}\nPayload: {cmdi['payload']}",
                            "Never pass form input to OS commands.")); break
            if form["method"] == "POST":
                has_csrf = any(n.lower() in ["csrf_token","csrf","token","nonce","_token","csrfmiddlewaretoken","authenticity_token"] for n in form["fields"])
                if not has_csrf:
                    findings.append(self.finding(f"Missing CSRF Token ({form['action'][:50]})", "MEDIUM",
                        "POST form has no anti-CSRF token.",
                        f"Action: {form['action']}\nFields: {', '.join(form['fields'].keys())}",
                        "Add CSRF tokens to all state-changing forms."))
        return findings or [self.finding("No Form Vulnerabilities", "INFO", "Forms tested, no issues found.")]
