"""Scanner: SSL/TLS Security Analysis"""
import ssl, socket
from datetime import datetime
from scanners import BaseScanner

class SSLScanner(BaseScanner):
    name = "SSL/TLS Security"
    description = "Analyzes SSL/TLS certificate validity, protocols, and cipher strength."

    def scan(self):
        findings = []
        hostname = self.parsed_url.hostname
        port = self.parsed_url.port or (443 if self.parsed_url.scheme == "https" else 80)
        if self.parsed_url.scheme != "https":
            return [self.finding("Not HTTPS", "INFO", "Target uses HTTP. SSL analysis skipped.")]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(self.finding("Certificate Expired", "HIGH", f"Expired {abs(days_left)} days ago.", f"Expired: {cert['notAfter']}", "Renew immediately."))
                    elif days_left < 30:
                        findings.append(self.finding(f"Certificate Expiring ({days_left}d)", "MEDIUM", f"Expires in {days_left} days.", f"Expires: {cert['notAfter']}", "Renew soon."))
                    else:
                        findings.append(self.finding(f"Certificate Valid ({days_left}d)", "INFO", f"Valid until {cert['notAfter']}.", f"Days left: {days_left}"))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    if issuer == subject:
                        findings.append(self.finding("Self-Signed Certificate", "HIGH", "Not trusted by browsers.", f"Issuer: {issuer.get('commonName','?')}", "Use a trusted CA."))
                    findings.append(self.finding(f"Protocol: {proto}", "INFO", f"Negotiated {proto}.", f"Protocol: {proto}"))
                    cipher = ssock.cipher()
                    if cipher:
                        name, _, bits = cipher
                        if bits < 128:
                            findings.append(self.finding(f"Weak Cipher: {name} ({bits}-bit)", "HIGH", f"Only {bits}-bit encryption.", f"Cipher: {name}", "Use 128-bit+ ciphers."))
                        else:
                            findings.append(self.finding(f"Cipher: {name} ({bits}-bit)", "INFO", f"{bits}-bit encryption.", f"Cipher: {name}"))
        except ssl.SSLCertVerificationError as e:
            findings.append(self.finding("Certificate Verification Failed", "HIGH", str(e)[:200]))
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append(self.finding("SSL Connection Error", "MEDIUM", str(e)[:200]))
        # Test insecure protocols
        for proto_name, opts in [("TLSv1.0", ssl.OP_NO_SSLv2|ssl.OP_NO_SSLv3|ssl.OP_NO_TLSv1_1|ssl.OP_NO_TLSv1_2|ssl.OP_NO_TLSv1_3),
                                  ("TLSv1.1", ssl.OP_NO_SSLv2|ssl.OP_NO_SSLv3|ssl.OP_NO_TLSv1|ssl.OP_NO_TLSv1_2|ssl.OP_NO_TLSv1_3)]:
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS)
                ctx2.options |= opts; ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as s:
                    with ctx2.wrap_socket(s, server_hostname=hostname):
                        findings.append(self.finding(f"Insecure Protocol: {proto_name}", "MEDIUM", f"Server accepts {proto_name} (vulnerable to BEAST/POODLE).", f"Protocol: {proto_name}", f"Disable {proto_name}."))
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                pass
        return findings or [self.finding("SSL/TLS OK", "INFO", "No issues detected.")]
