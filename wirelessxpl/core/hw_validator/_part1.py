#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Wireless Hardware Validator — verifica pré-requisitos de hardware e bibliotecas.

Cada módulo de ataque wireless pode exigir hardware ou bibliotecas específicas.
Este módulo fornece verificações estruturadas para:

  - Adaptadores Wi-Fi com suporte a monitor mode e packet injection
  - Dongles Bluetooth (hci*, CSR, nRF52, Ubertooth, etc.)
  - SDR (HackRF, RTL-SDR, USRP, LimeSDR, PlutoSDR)
  - Hardware Z-Wave (ZWave.me, UZB, Sigma Designs)
  - Leitores NFC/RFID (Proxmark, ACR122U, PN532)
  - Hardware especializado (Proxmark3, YARD Stick One, etc.)
  - Bibliotecas Python necessárias
  - Ferramentas de sistema (aircrack-ng, hcxtools, etc.)

Uso típico:

    from wirelessxpl.core.hw_validator import HWValidator, Requirement

    validator = HWValidator()
    ok = validator.require(
        Requirement.WIFI_MONITOR_MODE,
        Requirement.PACKET_INJECTION,
    )
    if not ok:
        return  # mensagens de erro já impressas

Version: 1.0.0
"""


import importlib
import logging
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class Requirement(Enum):
    """Requisitos de hardware/software verificáveis."""

    # Wi-Fi
    WIFI_ADAPTER = auto()
    WIFI_MONITOR_MODE = auto()
    PACKET_INJECTION = auto()
    WIFI_5GHZ = auto()
    WIFI_6GHZ = auto()

    # Bluetooth
    BLUETOOTH_ADAPTER = auto()
    BLUETOOTH_LE = auto()
    BLUETOOTH_CLASSIC = auto()
    NRF52_DONGLE = auto()
    UBERTOOTH = auto()
    CSR_DONGLE = auto()

    # SDR
    SDR_ANY = auto()
    HACKRF = auto()
    RTL_SDR = auto()
    USRP = auto()
    LIMESDR = auto()
    PLUTOSDR = auto()
    YARD_STICK = auto()

    # Z-Wave
    ZWAVE_DONGLE = auto()

    # NFC/RFID
    NFC_READER = auto()
    PROXMARK3 = auto()
    ACR122U = auto()
    PN532 = auto()

    # SIM
    SIM_READER = auto()

    # Cellular
    OSMOCOM_SDR = auto()
    RTLSDR_CELLULAR = auto()

    # Python libs
    SCAPY = auto()
    BLUEPY = auto()
    BLEAK = auto()
    PYSCARD = auto()
    PYRTLSDR = auto()
    PYSDR = auto()
    PYSERIAL = auto()
    PYZWAVE = auto()
    NFCPY = auto()
    USRP_PYTHON = auto()

    # Ferramentas de sistema
    AIRCRACK_NG = auto()
    AIRODUMP_NG = auto()
    AIREPLAY_NG = auto()
    HCXDUMPTOOL = auto()
    HCXTOOLS = auto()
    HASHCAT = auto()
    JOHN = auto()
    MDK4 = auto()
    HOSTAPD = auto()
    HOSTAPD_MANA = auto()
    EAPHAMMER = auto()
    REAVER = auto()
    BULLY = auto()
    PIXIEWPS = auto()
    WIFIPHISHER = auto()
    KISMET = auto()
    BETTERCAP = auto()
    GNURADIO = auto()
    URH = auto()
    GQRX = auto()
    BLUETOOTHCTL = auto()
    HCITOOL = auto()
    BTLEJACK_CLI = auto()
    SS7_SIGPLOIT = auto()
    UERANSIM = auto()
    PYSIM = auto()
    OSMOCOM = auto()

    # Suporte de OS
    LINUX_REQUIRED = auto()
    ROOT_REQUIRED = auto()
    KERNEL_6_PLUS = auto()


@dataclass
class CheckResult:
    """Resultado de uma verificação de requisito individual."""

    requirement: Requirement
    satisfied: bool
    detail: str = ""
    install_hint: str = ""


@dataclass
class ValidationReport:
    """Relatório consolidado de validação de requisitos."""

    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_satisfied(self) -> bool:
        """True se todos os requisitos foram satisfeitos."""
        return all(r.satisfied for r in self.results)

    @property
    def missing(self) -> list[CheckResult]:
        """Lista de requisitos não satisfeitos."""
        return [r for r in self.results if not r.satisfied]

    def print_report(self, verbose: bool = False) -> None:
        """Imprime relatório formatado."""
        for result in self.results:
            if result.satisfied:
                if verbose:
                    print(f"  [+] {result.requirement.name}: {result.detail}")
            else:
                print(f"  [-] {result.requirement.name}: {result.detail}")
                if result.install_hint:
                    print(f"       Dica: {result.install_hint}")

    def print_missing(self) -> None:
        """Imprime apenas os requisitos ausentes."""
        for result in self.missing:
            print(f"  [!] REQUISITO AUSENTE — {result.requirement.name}: {result.detail}")
            if result.install_hint:
                print(f"       Como instalar: {result.install_hint}")


def _check_binary(name: str) -> str | None:
    return shutil.which(name)


def _check_python_lib(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


def _run_silent(cmd: list[str]) -> str | None:
    """Executa comando e retorna stdout, ou None em caso de erro."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=5
        )
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


def _wifi_interfaces_linux() -> list[str]:
    """Retorna lista de interfaces wireless no Linux."""
    out = _run_silent(["iw", "dev"])
    if not out:
        return []
    return re.findall(r"Interface\s+(\S+)", out)


def _wifi_has_monitor_linux(iface: str) -> bool:
    """Verifica se a interface suporta monitor mode."""
    out = _run_silent(["iw", iface, "info"])
    if not out:
        # Tenta listar phy
        out = _run_silent(["iw", "list"])
    return out is not None and "monitor" in out.lower()


def _bluetooth_adapters_linux() -> list[str]:
    """Retorna lista de adaptadores HCI no Linux."""
    out = _run_silent(["hciconfig"])
    if not out:
        return []
    return re.findall(r"(hci\d+)", out)


def _usb_devices() -> str:
    """Retorna listagem USB bruta (Linux/Windows)."""
    if platform.system() == "Linux":
        return _run_silent(["lsusb"]) or ""
    elif platform.system() == "Windows":
        out = _run_silent(
            ["powershell", "-Command", "Get-PnpDevice -Class USB | Select-Object FriendlyName"]
        )
        return out or ""
    return ""


# ------------------------------------------------------------------ #
# Mapa de verificadores por requisito
# ------------------------------------------------------------------ #

