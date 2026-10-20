"""Tests for wirelessxpl.core.phase_gateway - PhaseGateway, quick_gate."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wirelessxpl.core.phase_gateway import (
    GatewayReport,
    PhaseGateway,
    PhaseResult,
    quick_gate,
)

# ---------------------------------------------------------------------------
# PhaseResult
# ---------------------------------------------------------------------------

def test_phase_result_pass() -> None:
    r = PhaseResult(name="Check", passed=True, elapsed_ms=1.5)
    assert r.status_icon == "OK  "


def test_phase_result_fail() -> None:
    r = PhaseResult(name="Check", passed=False, elapsed_ms=0.0)
    assert r.status_icon == "FAIL"


# ---------------------------------------------------------------------------
# GatewayReport
# ---------------------------------------------------------------------------

def test_gateway_report_all_passed() -> None:
    report = GatewayReport(
        module_name="Test",
        results=[
            PhaseResult("A", True, 1.0),
            PhaseResult("B", True, 2.0),
        ],
    )
    assert report.all_passed is True
    assert report.first_failure is None


def test_gateway_report_with_failure() -> None:
    report = GatewayReport(
        module_name="Test",
        results=[
            PhaseResult("A", True, 1.0),
            PhaseResult("B", False, 0.5, detail="bad"),
        ],
    )
    assert report.all_passed is False
    assert report.first_failure is not None
    assert report.first_failure.name == "B"


# ---------------------------------------------------------------------------
# PhaseGateway
# ---------------------------------------------------------------------------

def test_gateway_all_pass() -> None:
    gw = PhaseGateway("Test Module", silent=True)
    gw.phase("One", lambda: True)
    gw.phase("Two", lambda: True)
    gw.phase("Three", lambda: True)
    assert gw.run() is True


def test_gateway_stop_on_first_failure() -> None:
    call_log = []

    def phase_a():
        call_log.append("A")
        return True

    def phase_b():
        call_log.append("B")
        return False

    def phase_c():
        call_log.append("C")
        return True

    gw = PhaseGateway("Test", stop_on_first_failure=True, silent=True)
    gw.phase("A", phase_a)
    gw.phase("B", phase_b)
    gw.phase("C", phase_c)
    assert gw.run() is False
    assert "C" not in call_log


def test_gateway_run_all_phases() -> None:
    call_log = []

    def phase_a():
        call_log.append("A")
        return True

    def phase_b():
        call_log.append("B")
        return False

    def phase_c():
        call_log.append("C")
        return True

    gw = PhaseGateway("Test", stop_on_first_failure=False, silent=True)
    gw.phase("A", phase_a)
    gw.phase("B", phase_b)
    gw.phase("C", phase_c)
    assert gw.run() is False
    assert call_log == ["A", "B", "C"]


def test_gateway_exception_treated_as_failure() -> None:
    gw = PhaseGateway("Test", silent=True)
    gw.phase("Boom", lambda: 1 / 0)
    assert gw.run() is False


def test_gateway_fluent_chaining() -> None:
    gw = PhaseGateway("Test", silent=True)
    result = gw.phase("A", lambda: True).phase("B", lambda: True)
    assert result is gw
    assert len(gw) == 2


def test_gateway_reset() -> None:
    gw = PhaseGateway("Test", silent=True)
    gw.phase("A", lambda: True)
    gw.phase("B", lambda: True)
    assert len(gw) == 2
    gw.reset()
    assert len(gw) == 0


def test_gateway_repr() -> None:
    gw = PhaseGateway("BLE Scan")
    gw.phase("HW", lambda: True)
    r = repr(gw)
    assert "BLE Scan" in r
    assert "1" in r


def test_gateway_empty_passes() -> None:
    gw = PhaseGateway("Empty", silent=True)
    assert gw.run() is True


# ---------------------------------------------------------------------------
# quick_gate
# ---------------------------------------------------------------------------

def test_quick_gate_all_pass(capsys) -> None:
    result = quick_gate("Quick", Alpha=lambda: True, Beta=lambda: True)
    assert result is True


def test_quick_gate_with_failure(capsys) -> None:
    result = quick_gate("Quick", Alpha=lambda: True, Beta=lambda: False)
    assert result is False
