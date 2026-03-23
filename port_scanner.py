"""TCP Port Scanner with service identification."""
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
        135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
        1433:"MSSQL",1521:"Oracle",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",
        6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",11211:"Memcached",27017:"MongoDB"}
    RISKY_PORTS = {21:"FTP plaintext creds",23:"Telnet plaintext",445:"SMB (EternalBlue)",
        1433:"DB exposed",3306:"DB exposed",3389:"RDP brute force target",5432:"DB exposed",
        5900:"VNC weak auth",6379:"Redis no auth",9200:"Elastic no auth",27017:"MongoDB no auth"}

    def __init__(self, target_url, timeout=2.0, threads=20):
        self.hostname = urlparse(target_url).hostname
        self.timeout = timeout
        self.threads = threads

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.hostname, port)) == 0:
                sock.close()
                return {"port": port, "service": self.COMMON_PORTS.get(port, "Unknown"), "risk": self.RISKY_PORTS.get(port)}
            sock.close()
        except (socket.timeout, OSError):
            pass
        return None

    def scan(self):
        print(f"      Scanning {self.hostname} — {len(self.COMMON_PORTS)} ports...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.scan_port, p): p for p in self.COMMON_PORTS}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    open_ports.append(r)
                    tag = f" ⚠ {r['risk']}" if r.get("risk") else ""
                    print(f"      [+] {r['port']}/{r['service']} OPEN{tag}")
        open_ports.sort(key=lambda x: x["port"])
        print(f"      {len(open_ports)} open ports")
        return {"hostname": self.hostname, "open_ports": open_ports}
