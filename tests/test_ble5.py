"""Tests for wirelessxpl.core.bluetooth.ble5."""

from __future__ import annotations

from wirelessxpl.core.bluetooth.ble5 import (
    AdvType,
    BLE5Device,
    BLE5Scanner,
    DirectionFindingResult,
    GATTSecurityAuditor,
    PHYType,
)


class TestPHYType:
    def test_values(self) -> None:
        assert PHYType.LE_1M is not PHYType.LE_2M
        assert PHYType.LE_CODED_S2 is not PHYType.LE_CODED_S8


class TestBLE5Device:
    def test_defaults(self) -> None:
        dev = BLE5Device()
        assert dev.address == ""
        assert dev.phy == PHYType.LE_1M
        assert dev.adv_type == AdvType.LEGACY
        assert dev.connectable is True
        assert dev.extended_features == []

    def test_custom(self) -> None:
        dev = BLE5Device(
            address="AA:BB:CC:DD:EE:FF",
            phy=PHYType.LE_2M,
            adv_type=AdvType.EXTENDED,
            rssi=-45,
        )
        assert dev.address == "AA:BB:CC:DD:EE:FF"
        assert dev.phy == PHYType.LE_2M
        assert dev.rssi == -45


class TestDirectionFinding:
    def test_defaults(self) -> None:
        df = DirectionFindingResult(device=BLE5Device())
        assert df.method == "AoA"
        assert df.confidence == 0.0


class TestBLE5Scanner:
    def test_init(self) -> None:
        scanner = BLE5Scanner("hci1")
        assert scanner.adapter == "hci1"

    def test_scan_periodic_empty(self) -> None:
        scanner = BLE5Scanner()
        assert scanner.scan_periodic() == []

    def test_detect_phy_not_found(self) -> None:
        scanner = BLE5Scanner()
        assert scanner.detect_phy("00:11:22:33:44:55") is None


class TestGATTSecurityAuditor:
    def test_insecure_write(self) -> None:
        auditor = GATTSecurityAuditor("AA:BB:CC:DD:EE:FF")
        services = [{
            "characteristics": [{
                "handle": 0x0012,
                "uuid": "00002a00-0000-1000-8000-00805f9b34fb",
                "properties": ["write-without-response"],
                "security": [],
            }],
        }]
        findings = auditor.audit_permissions(services)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_insecure_notify(self) -> None:
        auditor = GATTSecurityAuditor("target")
        services = [{
            "characteristics": [{
                "handle": 0x0020,
                "uuid": "custom",
                "properties": ["notify"],
                "security": [],
            }],
        }]
        findings = auditor.audit_permissions(services)
        assert len(findings) == 1
        assert "Notifications" in findings[0].issue

    def test_secure_char(self) -> None:
        auditor = GATTSecurityAuditor("target")
        services = [{
            "characteristics": [{
                "handle": 0x0030,
                "uuid": "secure",
                "properties": ["read", "write"],
                "security": ["authenticated", "encrypted"],
            }],
        }]
        findings = auditor.audit_permissions(services)
        assert len(findings) == 0

    def test_just_works_pairing(self) -> None:
        auditor = GATTSecurityAuditor("target")
        findings = auditor.check_pairing_mode({"method": "just_works"})
        assert len(findings) == 1
        assert "Just Works" in findings[0].issue

    def test_secure_pairing(self) -> None:
        auditor = GATTSecurityAuditor("target")
        findings = auditor.check_pairing_mode({"method": "passkey"})
        assert len(findings) == 0
