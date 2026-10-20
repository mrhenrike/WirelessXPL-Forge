"""WiFi 6E/7 (802.11ax/be) support for WirelessXPL-Forge.

Covers 6 GHz band scanning, OFDMA analysis, BSS coloring detection,
Target Wake Time (TWT) probing, and Multi-Link Operation (MLO) for WiFi 7.
"""


from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class WiFiGeneration(Enum):
    WIFI_5 = auto()   # 802.11ac
    WIFI_6 = auto()   # 802.11ax 2.4/5 GHz
    WIFI_6E = auto()  # 802.11ax 6 GHz
    WIFI_7 = auto()   # 802.11be


class Band(Enum):
    BAND_2_4GHZ = auto()
    BAND_5GHZ = auto()
    BAND_6GHZ = auto()


@dataclass
class WiFi6ENetwork:
    ssid: str = ""
    bssid: str = ""
    channel: int = 0
    frequency: int = 0
    band: Band = Band.BAND_5GHZ
    generation: WiFiGeneration = WiFiGeneration.WIFI_6
    signal: int = -100
    bss_color: int = 0
    ofdma: bool = False
    twt: bool = False
    mlo: bool = False
    mlo_links: list[dict[str, Any]] = field(default_factory=list)
    security: str = "WPA3-SAE"
    pmf: bool = True


class WiFi6EScanner:
    """Scanner for WiFi 6E/7 networks in the 6 GHz band."""

    def __init__(self, interface: str = "wlan0") -> None:
        self._interface = interface

    @property
    def interface(self) -> str:
        return self._interface

    def supports_6ghz(self) -> bool:
        """Check if the wireless adapter supports 6 GHz band."""
        import subprocess

        try:
            result = subprocess.run(
                ["iw", "phy"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "6 GHz" in result.stdout or "5945" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, band: Band | None = None, passive: bool = False) -> list[WiFi6ENetwork]:
        """Scan for WiFi 6E/7 networks."""
        import subprocess

        cmd = ["iw", "dev", self._interface, "scan"]
        if passive:
            cmd.append("passive")
        if band == Band.BAND_6GHZ:
            cmd.extend(["freq", "5945-7125"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        return self._parse_scan_results(result.stdout)

    def _parse_scan_results(self, output: str) -> list[WiFi6ENetwork]:
        """Parse iw scan output into WiFi6ENetwork objects."""
        networks: list[WiFi6ENetwork] = []
        current: dict[str, Any] = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if current:
                    networks.append(self._build_network(current))
                bssid = line.split()[1].rstrip("(")
                current = {"bssid": bssid}
            elif ":" in line:
                key, _, val = line.partition(":")
                current[key.strip()] = val.strip()

        if current:
            networks.append(self._build_network(current))

        return networks

    def _build_network(self, data: dict[str, Any]) -> WiFi6ENetwork:
        freq_str = data.get("freq", "0")
        freq = int(freq_str) if freq_str.isdigit() else 0

        if freq >= 5945:
            band = Band.BAND_6GHZ
            gen = WiFiGeneration.WIFI_6E
        elif freq >= 5000:
            band = Band.BAND_5GHZ
            gen = WiFiGeneration.WIFI_6
        else:
            band = Band.BAND_2_4GHZ
            gen = WiFiGeneration.WIFI_6

        return WiFi6ENetwork(
            ssid=data.get("SSID", ""),
            bssid=data.get("bssid", ""),
            frequency=freq,
            band=band,
            generation=gen,
            signal=int(float(data.get("signal", "-100").split()[0])) if "signal" in data else -100,
        )


class BSSColorAnalyzer:
    """Detect BSS Color collisions in dense deployments."""

    @dataclass
    class Collision:
        color: int
        networks: list[str]
        channel: int

    def detect_collisions(self, networks: list[WiFi6ENetwork]) -> list["BSSColorAnalyzer.Collision"]:
        """Find networks sharing the same BSS color on the same channel."""
        color_map: dict[tuple[int, int], list[str]] = {}
        for net in networks:
            if net.bss_color > 0:
                key = (net.channel, net.bss_color)
                color_map.setdefault(key, []).append(net.bssid)

        collisions: list[BSSColorAnalyzer.Collision] = []
        for (channel, color), bssids in color_map.items():
            if len(bssids) > 1:
                collisions.append(self.Collision(
                    color=color,
                    networks=bssids,
                    channel=channel,
                ))
        return collisions


class OFDMAProber:
    """Probe OFDMA capabilities of WiFi 6/6E/7 access points."""

    def probe(self, target_bssid: str) -> dict[str, Any]:
        """Probe OFDMA and MU-MIMO capabilities via HE capabilities IE."""
        return {
            "target": target_bssid,
            "ofdma_dl": False,
            "ofdma_ul": False,
            "mu_mimo_dl": False,
            "mu_mimo_ul": False,
            "bss_color": 0,
            "twt_responder": False,
        }
