class Exploit(Exploit):
    """Monitor mode manager for 802.11 wireless interfaces."""

    __info__ = {
        "name": "Monitor Mode Manager",
        "description": (
            "Enables and disables 802.11 monitor mode without airmon-ng by "
            "using iw, ip link, and rfkill directly. Supports channel hopping "
            "in a daemon thread, injection capability testing via Scapy, "
            "and context manager usage. Uses 'nmcli device set managed no' to "
            "release only the target interface from NetworkManager (safe for "
            "multi-interface setups where other interfaces must stay connected)."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://wireless.wiki.kernel.org/en/users/documentation/iw",
            "https://scapy.net/",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString(
        "status",
        "Mode: enable, disable, status, hop",
    )
    interface = OptString("wlan0", "Wireless interface to manage")
    kill_processes = OptBool(
        True,
        "Kill NetworkManager/wpa_supplicant before enabling monitor mode",
    )
    hop_channels = OptString(
        "",
        "Comma-separated channel list for hop mode (empty = 2.4 GHz default)",
    )
    hop_interval = OptFloat(0.5, "Channel dwell time in seconds for hop mode")
    check_injection_opt = OptBool(
        False,
        "Run injection test after enabling monitor mode",
    )
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _status(self) -> None:
        ifaces = MonitorModeManager.get_interfaces()
        if not ifaces:
            print_info("No wireless interfaces found (iw not available or no interfaces).")
            return

        print_info("Wireless interfaces:")
        print_info("{:<16} {:<10} {:<10} {}".format("Interface", "Mode", "PHY", "MAC"))
        print_info("-" * 56)
        for entry in ifaces:
            print_info("{:<16} {:<10} {:<10} {}".format(
                entry.get("interface", ""),
                entry.get("type", ""),
                entry.get("phy", ""),
                entry.get("addr", ""),
            ))

    def _enable(self) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface before running.")
            return

        mgr = MonitorModeManager(
            interface=iface,
            kill_processes=bool(self.kill_processes),
        )
        try:
            mon = mgr.enable()
        except RuntimeError as exc:
            print_error(f"Failed to enable monitor mode: {exc}")
            return

        print_success(f"Monitor mode enabled: {mon}")

        if bool(self.check_injection_opt):
            result = mgr.check_injection()
            if result:
                print_success("Injection test passed - driver supports frame injection.")
            else:
                print_error("Injection test failed - driver may not support injection.")

    def _disable(self) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface before running.")
            return

        mgr = MonitorModeManager(interface=iface, kill_processes=False)
        mgr._monitor_iface = iface
        mgr._enabled = True
        mgr.disable()
        print_success(f"Managed mode restored on {iface}.")

    def _hop(self) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface before running.")
            return

        raw_channels = str(self.hop_channels).strip()
        if raw_channels:
            try:
                channels = [int(c.strip()) for c in raw_channels.split(",") if c.strip()]
            except ValueError:
                print_error("hop_channels must be comma-separated integers (e.g. 1,6,11).")
                return
        else:
            channels = CHANNELS_2GHZ

        interval = float(self.hop_interval)
        if interval <= 0:
            print_error("hop_interval must be a positive number.")
            return

        mgr = MonitorModeManager(interface=iface, kill_processes=False)
        mgr._monitor_iface = iface
        mgr._enabled = True

        mgr.start_hop(channels=channels, interval_s=interval)
        print_success(f"Channel hopper started on {iface} ({len(channels)} channels, {interval:.1f}s dwell).")
        print_info("Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_status("Stopping channel hopper...")
        finally:
            mgr.stop_hop()

        print_info("Channel hopper stopped.")

    def check(self) -> str:
        """Verify that iw is installed and a wireless interface is present."""
        iw = shutil.which("iw")
        if not iw:
            return "iw not found - install with: apt install iw"
        ifaces = MonitorModeManager.get_interfaces()
        if not ifaces:
            return "iw found but no wireless interfaces detected"
        names = [e["interface"] for e in ifaces]
        return "iw found; wireless interfaces: {}".format(", ".join(names))

    def run(self) -> None:
        """Dispatch to the selected operational mode."""
        op = str(self.mode).strip().lower()

        if op == "status":
            self._status()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab environment.")
            return
        require_authorised_lab()

        if op == "enable":
            self._enable()
        elif op == "disable":
            self._disable()
        elif op == "hop":
            self._hop()
        else:
            print_error(
                f"Unknown mode: {op}. Valid: enable, disable, status, hop"
            )
