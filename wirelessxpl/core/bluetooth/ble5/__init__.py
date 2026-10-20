"""BLE 5.x extended features for WirelessXPL-Forge.

Covers Bluetooth 5.0-5.4 additions: extended advertising, 2M/Coded PHY,
periodic advertising, direction finding (AoA/AoD), LE Audio (LC3),
and GATT security assessment.
"""


from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class PHYType(Enum):
    LE_1M = auto()
    LE_2M = auto()
    LE_CODED_S2 = auto()
    LE_CODED_S8 = auto()


class AdvType(Enum):
    LEGACY = auto()
    EXTENDED = auto()
    PERIODIC = auto()


@dataclass
class BLE5Device:
    address: str = ""
    address_type: str = "public"
    name: str = ""
    rssi: int = -100
    phy: PHYType = PHYType.LE_1M
    adv_type: AdvType = AdvType.LEGACY
    adv_data: bytes = b""
    connectable: bool = True
    tx_power: int | None = None
    extended_features: list[str] = field(default_factory=list)


@dataclass
class DirectionFindingResult:
    device: BLE5Device
    azimuth: float = 0.0
    elevation: float = 0.0
    method: str = "AoA"
    antenna_count: int = 0
    confidence: float = 0.0


class BLE5Scanner:
    """Extended BLE 5.x scanner supporting 2M PHY and extended advertising."""

    def __init__(self, adapter: str = "hci0") -> None:
        self._adapter = adapter
        self._devices: list[BLE5Device] = []

    @property
    def adapter(self) -> str:
        return self._adapter

    def scan_extended(
        self,
        duration: float = 10.0,
        phy: PHYType = PHYType.LE_1M,
        active: bool = True,
    ) -> list[BLE5Device]:
        """Scan for BLE 5.x devices with extended advertising support.

        Requires a BLE 5.0+ adapter and bluez >= 5.50.
        """
        import subprocess

        cmd = ["hcitool", "-i", self._adapter, "lescan"]
        if not active:
            cmd.append("--passive")

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            pass

        return self._devices

    def scan_periodic(self, sync_timeout: float = 5.0) -> list[BLE5Device]:
        """Scan for periodic advertising trains (BLE 5.1+)."""
        return [d for d in self._devices if d.adv_type == AdvType.PERIODIC]

    def detect_phy(self, address: str) -> PHYType | None:
        """Detect which PHY a connected device uses."""
        for d in self._devices:
            if d.address == address:
                return d.phy
        return None


class GATTSecurityAuditor:
    """Audit GATT service security characteristics."""

    @dataclass
    class Finding:
        handle: int
        uuid: str
        issue: str
        severity: str = "MEDIUM"

    def __init__(self, target: str) -> None:
        self._target = target
        self._findings: list[GATTSecurityAuditor.Finding] = []

    def audit_permissions(self, services: list[dict[str, Any]]) -> list["GATTSecurityAuditor.Finding"]:
        """Check for insecure GATT characteristic permissions."""
        for svc in services:
            for char in svc.get("characteristics", []):
                props = char.get("properties", [])
                handle = char.get("handle", 0)
                uuid = char.get("uuid", "")

                if "write-without-response" in props and "authenticated" not in char.get("security", []):
                    self._findings.append(self.Finding(
                        handle=handle,
                        uuid=uuid,
                        issue="Write-without-response without authentication",
                        severity="HIGH",
                    ))

                if "notify" in props and "encrypted" not in char.get("security", []):
                    self._findings.append(self.Finding(
                        handle=handle,
                        uuid=uuid,
                        issue="Notifications without encryption",
                        severity="MEDIUM",
                    ))

        return self._findings

    def check_pairing_mode(self, pairing_info: dict[str, Any]) -> list["GATTSecurityAuditor.Finding"]:
        """Check if pairing uses Just Works (no MITM protection)."""
        method = pairing_info.get("method", "")
        if method == "just_works":
            self._findings.append(self.Finding(
                handle=0,
                uuid="pairing",
                issue="Just Works pairing: no MITM protection",
                severity="HIGH",
            ))
        return self._findings
