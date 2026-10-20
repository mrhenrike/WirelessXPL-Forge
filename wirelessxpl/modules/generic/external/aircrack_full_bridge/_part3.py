        iface = self._iface()
        bssid = str(self.bssid).strip()
        sta = str(self.station).strip()
        if not iface or not bssid:
            print_error("Set interface and bssid.")
            return

        cmd = [b, "-a", bssid]
        if sta:
            cmd.extend(["-h", sta])
        cmd.extend(self._extra())
        cmd.append(iface)

        t = int(self.timeout)
        _run(cmd, timeout=t if t > 0 else 0, dry_run=bool(self.dry_run), capture=True)

    # -- Main dispatch --

    def check(self) -> str:
        """Verify external tool dependencies are installed."""
        import shutil
        tools: list[str] = []
        src = getattr(self.__class__, "__doc__", "") or ""
        for t in ("aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                   "hashcat", "hcxdumptool", "hcxtools", "wifite", "bettercap",
                   "kismet", "hostapd", "dnsmasq", "mdk4", "mdk3",
                   "hostapd-wpe", "hostapd-mana", "eaphammer"):
            if t.replace("-ng", "").replace("-", "") in (src + self.__class__.__name__).lower():
                tools.append(t)
        if not tools:
            tools = ["aircrack-ng"]
        missing = [t for t in tools if not shutil.which(t.rstrip("_"))]
        if missing:
            return f"Missing tools: {', '.join(missing)} - install before use"
        return f"Tool dependencies found: {', '.join(tools)} - prerequisites OK"

    def run(self) -> None:
        op = str(self.mode).strip().lower()
        dispatch = {
            "check": self._check_suite,
            "airmon_start": self._airmon_start,
            "airmon_stop": self._airmon_stop,
            "airodump_scan": lambda: self._airodump(capture_mode=False),
            "airodump_capture": lambda: self._airodump(capture_mode=True),
            "aireplay": self._aireplay,
            "aircrack_wep": self._aircrack_wep,
            "aircrack_wpa": self._aircrack_wpa,
            "airdecap": self._airdecap,
            "airolib_import": self._airolib_import,
            "airolib_batch": self._airolib_batch,
            "airolib_crack": self._airolib_crack,
            "besside": self._besside,
            "packetforge": self._packetforge,
            "airbase": self._airbase,
            "airtun": self._airtun,
            "airdecloak": self._airdecloak,
            "tkiptun": self._tkiptun,
        }

        handler = dispatch.get(op)
        if not handler:
            print_error(
                f"Unknown mode: {op}. Valid modes: {', '.join(sorted(dispatch.keys()))}"
            )
            return

        if op not in ("check",) and not bool(self.i_know_scope):
            print_error(
                "Set i_know_scope = true to confirm authorized lab environment."
            )
            return

        handler()
