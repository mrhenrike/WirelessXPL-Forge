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

from __future__ import annotations

import importlib
import logging
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Sequence

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

    results: List[CheckResult] = field(default_factory=list)

    @property
    def all_satisfied(self) -> bool:
        """True se todos os requisitos foram satisfeitos."""
        return all(r.satisfied for r in self.results)

    @property
    def missing(self) -> List[CheckResult]:
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


def _check_binary(name: str) -> Optional[str]:
    return shutil.which(name)


def _check_python_lib(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


def _run_silent(cmd: List[str]) -> Optional[str]:
    """Executa comando e retorna stdout, ou None em caso de erro."""
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


def _wifi_interfaces_linux() -> List[str]:
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


def _bluetooth_adapters_linux() -> List[str]:
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

def _make_checkers() -> Dict[Requirement, Callable[[], CheckResult]]:
    """Cria o dicionário de funções de verificação."""

    def wifi_adapter() -> CheckResult:
        req = Requirement.WIFI_ADAPTER
        if platform.system() == "Linux":
            ifaces = _wifi_interfaces_linux()
            if ifaces:
                return CheckResult(req, True, f"Interfaces: {', '.join(ifaces)}")
            return CheckResult(req, False, "Nenhuma interface wireless detectada.",
                               "Conecte um adaptador Wi-Fi USB (ex.: Alfa AWUS036ACH).")
        return CheckResult(req, True, "Verificação de adaptador não implementada nesta OS.")

    def wifi_monitor() -> CheckResult:
        req = Requirement.WIFI_MONITOR_MODE
        if platform.system() == "Linux":
            ifaces = _wifi_interfaces_linux()
            for iface in ifaces:
                if _wifi_has_monitor_linux(iface):
                    return CheckResult(req, True, f"Monitor mode disponível: {iface}")
            if not ifaces:
                return CheckResult(req, False, "Nenhuma interface wireless.",
                                   "Use: airmon-ng start <iface> | iw <iface> set monitor none")
            return CheckResult(
                req, False,
                f"Interfaces detectadas ({', '.join(ifaces)}) mas nenhuma com monitor mode.",
                "Execute: sudo airmon-ng start <iface> ou sudo iw <iface> set monitor none",
            )
        return CheckResult(req, True, "Verificação parcial (não Linux).")

    def packet_injection() -> CheckResult:
        req = Requirement.PACKET_INJECTION
        if platform.system() == "Linux" and shutil.which("aireplay-ng"):
            return CheckResult(req, True, "aireplay-ng disponível para injection test.")
        if not shutil.which("aireplay-ng"):
            return CheckResult(req, False, "aireplay-ng não encontrado.",
                               "apt install aircrack-ng | pacman -S aircrack-ng")
        return CheckResult(req, True, "aireplay-ng presente.")

    def bluetooth_adapter() -> CheckResult:
        req = Requirement.BLUETOOTH_ADAPTER
        if platform.system() == "Linux":
            adapters = _bluetooth_adapters_linux()
            if adapters:
                return CheckResult(req, True, f"Adaptadores: {', '.join(adapters)}")
            return CheckResult(req, False, "Nenhum adaptador Bluetooth HCI detectado.",
                               "Conecte um dongle BT USB ou ative o BT interno.")
        return CheckResult(req, True, "Verificação parcial (não Linux).")

    def bluetooth_le() -> CheckResult:
        req = Requirement.BLUETOOTH_LE
        ok_lib = _check_python_lib("bleak") or _check_python_lib("bluepy")
        ok_bin = bool(shutil.which("hciconfig") or shutil.which("bluetoothctl"))
        if ok_lib or ok_bin:
            return CheckResult(req, True, "BLE library/tools disponíveis.")
        return CheckResult(req, False, "Sem suporte BLE.",
                           "pip install bleak | pip install bluepy")

    def nrf52_dongle() -> CheckResult:
        req = Requirement.NRF52_DONGLE
        usb = _usb_devices()
        if "Nordic" in usb or "nRF" in usb or "Sniffer" in usb:
            return CheckResult(req, True, "Dongle Nordic Semiconductor detectado via USB.")
        # Verifica porta serial
        for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
            import os
            if os.path.exists(candidate):
                return CheckResult(req, True, f"Porta serial detectada: {candidate} (provável nRF52).")
        return CheckResult(
            req, False,
            "Dongle nRF52 não detectado (necessário para SweynTooth, BrakTooth).",
            "Use nRF52840 Dongle flashed com firmware de ataque.",
        )

    def ubertooth() -> CheckResult:
        req = Requirement.UBERTOOTH
        bin_ok = bool(shutil.which("ubertooth-scan") or shutil.which("ubertooth-rx"))
        usb = _usb_devices()
        usb_ok = "Ubertooth" in usb or "Great Scott" in usb
        if bin_ok or usb_ok:
            return CheckResult(req, True, "Ubertooth detectado.")
        return CheckResult(req, False, "Ubertooth não encontrado.",
                           "apt install ubertooth | https://github.com/greatscottgadgets/ubertooth")

    def hackrf() -> CheckResult:
        req = Requirement.HACKRF
        if shutil.which("hackrf_info"):
            out = _run_silent(["hackrf_info"])
            if out and "Found HackRF" in out:
                return CheckResult(req, True, "HackRF conectado e detectado.")
            return CheckResult(req, True, "hackrf_info encontrado (dispositivo pode estar desconectado).")
        return CheckResult(req, False, "HackRF não encontrado.",
                           "apt install hackrf | https://github.com/greatscottgadgets/hackrf")

    def rtl_sdr() -> CheckResult:
        req = Requirement.RTL_SDR
        if shutil.which("rtl_test") or shutil.which("rtl_sdr"):
            return CheckResult(req, True, "RTL-SDR tools encontrados.")
        return CheckResult(req, False, "RTL-SDR não encontrado.",
                           "apt install rtl-sdr | https://osmocom.org/projects/rtl-sdr")

    def sdr_any() -> CheckResult:
        req = Requirement.SDR_ANY
        found = []
        for tool in ("hackrf_info", "rtl_test", "uhd_find_devices", "SoapySDRUtil", "limemini"):
            if shutil.which(tool):
                found.append(tool.split("_")[0])
        if found:
            return CheckResult(req, True, f"SDR tools: {', '.join(found)}")
        return CheckResult(req, False, "Nenhum SDR detectado.",
                           "Instale HackRF, RTL-SDR, USRP (UHD) ou LimeSDR.")

    def zwave_dongle() -> CheckResult:
        req = Requirement.ZWAVE_DONGLE
        usb = _usb_devices()
        zwave_hints = ["ZWave.me", "Sigma Designs", "0658", "CP2102", "CH340", "Silicon Labs"]
        if any(h in usb for h in zwave_hints):
            return CheckResult(req, True, "Possível dongle Z-Wave detectado via USB.")
        for candidate in ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0"]:
            import os
            if os.path.exists(candidate):
                return CheckResult(req, True, f"Porta serial {candidate} detectada (possível Z-Wave).")
        return CheckResult(
            req, False,
            "Dongle Z-Wave não detectado (necessário para ataques Z-Wave).",
            "Use UZB, ZWave.me Stick, ou Aeotec Z-Stick Gen5.",
        )

    def proxmark3() -> CheckResult:
        req = Requirement.PROXMARK3
        if shutil.which("proxmark3") or shutil.which("pm3"):
            return CheckResult(req, True, "Proxmark3 client detectado.")
        usb = _usb_devices()
        if "Proxmark" in usb or "9AC4" in usb:
            return CheckResult(req, True, "Proxmark3 USB detectado (cliente não no PATH).")
        return CheckResult(req, False, "Proxmark3 não detectado.",
                           "https://github.com/RfidResearchGroup/proxmark3")

    def nfc_reader() -> CheckResult:
        req = Requirement.NFC_READER
        if _check_python_lib("nfc"):
            return CheckResult(req, True, "nfcpy presente.")
        usb = _usb_devices()
        nfc_hints = ["ACR122", "PN532", "SCL3711", "NFC"]
        if any(h in usb for h in nfc_hints):
            return CheckResult(req, True, "Leitor NFC detectado via USB.")
        return CheckResult(req, False, "Leitor NFC não detectado.",
                           "pip install nfcpy | Conecte ACR122U ou PN532")

    def sim_reader() -> CheckResult:
        req = Requirement.SIM_READER
        if _check_python_lib("smartcard") or _check_python_lib("pyscard"):
            return CheckResult(req, True, "pyscard/smartcard presente.")
        usb = _usb_devices()
        if "Smart Card" in usb or "OMNIKEY" in usb or "ACS" in usb:
            return CheckResult(req, True, "Leitor de cartão inteligente detectado via USB.")
        return CheckResult(req, False, "Leitor SIM não detectado.",
                           "pip install pyscard | Conecte um reader PC/SC (ex.: ACR38)")

    def root_required() -> CheckResult:
        req = Requirement.ROOT_REQUIRED
        import os
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    return CheckResult(req, True, "Executando como Administrador.")
                return CheckResult(req, False, "Requer privilégios de Administrador.",
                                   "Execute o terminal como Administrador.")
            except Exception:
                return CheckResult(req, True, "Verificação de admin não disponível.")
        else:
            if os.geteuid() == 0:
                return CheckResult(req, True, "Executando como root (uid=0).")
            return CheckResult(req, False, "Requer root/sudo.",
                               "Execute com: sudo python3 wxf.py")

    def linux_required() -> CheckResult:
        req = Requirement.LINUX_REQUIRED
        if platform.system() == "Linux":
            return CheckResult(req, True, "Linux detectado.")
        return CheckResult(
            req, False,
            f"Este módulo requer Linux. OS atual: {platform.system()}",
            "Use uma distribuição Linux ou WSL2 com suporte USB (usbipd-win).",
        )

    def _make_binary_checker(r: Requirement, *binaries: str, hint: str = "") -> Callable[[], CheckResult]:
        def checker() -> CheckResult:
            for b in binaries:
                if shutil.which(b):
                    return CheckResult(r, True, f"{b} encontrado.")
            return CheckResult(r, False, f"Nenhum encontrado: {', '.join(binaries)}", hint)
        return checker

    def _make_lib_checker(r: Requirement, module: str, hint: str = "") -> Callable[[], CheckResult]:
        def checker() -> CheckResult:
            if _check_python_lib(module):
                return CheckResult(r, True, f"lib '{module}' disponível.")
            return CheckResult(r, False, f"Python lib '{module}' não instalada.", hint or f"pip install {module}")
        return checker

    checkers: Dict[Requirement, Callable[[], CheckResult]] = {
        Requirement.WIFI_ADAPTER: wifi_adapter,
        Requirement.WIFI_MONITOR_MODE: wifi_monitor,
        Requirement.PACKET_INJECTION: packet_injection,
        Requirement.BLUETOOTH_ADAPTER: bluetooth_adapter,
        Requirement.BLUETOOTH_LE: bluetooth_le,
        Requirement.NRF52_DONGLE: nrf52_dongle,
        Requirement.UBERTOOTH: ubertooth,
        Requirement.SDR_ANY: sdr_any,
        Requirement.HACKRF: hackrf,
        Requirement.RTL_SDR: rtl_sdr,
        Requirement.ZWAVE_DONGLE: zwave_dongle,
        Requirement.PROXMARK3: proxmark3,
        Requirement.NFC_READER: nfc_reader,
        Requirement.SIM_READER: sim_reader,
        Requirement.ROOT_REQUIRED: root_required,
        Requirement.LINUX_REQUIRED: linux_required,
        # Bibliotecas Python
        Requirement.SCAPY: _make_lib_checker(Requirement.SCAPY, "scapy", "pip install scapy"),
        Requirement.BLUEPY: _make_lib_checker(Requirement.BLUEPY, "bluepy", "pip install bluepy"),
        Requirement.BLEAK: _make_lib_checker(Requirement.BLEAK, "bleak", "pip install bleak"),
        Requirement.PYSCARD: _make_lib_checker(Requirement.PYSCARD, "smartcard", "pip install pyscard"),
        Requirement.PYRTLSDR: _make_lib_checker(Requirement.PYRTLSDR, "rtlsdr", "pip install pyrtlsdr"),
        Requirement.PYSERIAL: _make_lib_checker(Requirement.PYSERIAL, "serial", "pip install pyserial"),
        Requirement.PYZWAVE: _make_lib_checker(Requirement.PYZWAVE, "pyzwave", "pip install pyzwave"),
        Requirement.NFCPY: _make_lib_checker(Requirement.NFCPY, "nfc", "pip install nfcpy"),
        # Ferramentas de sistema
        Requirement.AIRCRACK_NG: _make_binary_checker(
            Requirement.AIRCRACK_NG, "aircrack-ng",
            hint="apt install aircrack-ng | pacman -S aircrack-ng"),
        Requirement.AIRODUMP_NG: _make_binary_checker(
            Requirement.AIRODUMP_NG, "airodump-ng",
            hint="apt install aircrack-ng"),
        Requirement.AIREPLAY_NG: _make_binary_checker(
            Requirement.AIREPLAY_NG, "aireplay-ng",
            hint="apt install aircrack-ng"),
        Requirement.HCXDUMPTOOL: _make_binary_checker(
            Requirement.HCXDUMPTOOL, "hcxdumptool",
            hint="apt install hcxdumptool | https://github.com/ZerBea/hcxdumptool"),
        Requirement.HCXTOOLS: _make_binary_checker(
            Requirement.HCXTOOLS, "hcxpcapngtool", "hcxpcapdumptool",
            hint="apt install hcxtools | https://github.com/ZerBea/hcxtools"),
        Requirement.HASHCAT: _make_binary_checker(
            Requirement.HASHCAT, "hashcat",
            hint="apt install hashcat | https://hashcat.net"),
        Requirement.JOHN: _make_binary_checker(
            Requirement.JOHN, "john",
            hint="apt install john"),
        Requirement.MDK4: _make_binary_checker(
            Requirement.MDK4, "mdk4",
            hint="apt install mdk4 | https://github.com/aircrack-ng/mdk4"),
        Requirement.HOSTAPD: _make_binary_checker(
            Requirement.HOSTAPD, "hostapd",
            hint="apt install hostapd"),
        Requirement.HOSTAPD_MANA: _make_binary_checker(
            Requirement.HOSTAPD_MANA, "hostapd-mana",
            hint="https://github.com/sensepost/hostapd-mana"),
        Requirement.EAPHAMMER: _make_binary_checker(
            Requirement.EAPHAMMER, "eaphammer",
            hint="https://github.com/s0lst1c3/eaphammer"),
        Requirement.REAVER: _make_binary_checker(
            Requirement.REAVER, "reaver",
            hint="apt install reaver"),
        Requirement.BULLY: _make_binary_checker(
            Requirement.BULLY, "bully",
            hint="apt install bully | https://github.com/nicowillis/bully"),
        Requirement.PIXIEWPS: _make_binary_checker(
            Requirement.PIXIEWPS, "pixiewps",
            hint="apt install pixiewps"),
        Requirement.WIFIPHISHER: _make_binary_checker(
            Requirement.WIFIPHISHER, "wifiphisher",
            hint="pip install wifiphisher | https://github.com/wifiphisher/wifiphisher"),
        Requirement.KISMET: _make_binary_checker(
            Requirement.KISMET, "kismet",
            hint="apt install kismet | https://www.kismetwireless.net"),
        Requirement.BETTERCAP: _make_binary_checker(
            Requirement.BETTERCAP, "bettercap",
            hint="apt install bettercap | https://www.bettercap.org"),
        Requirement.GNURADIO: _make_binary_checker(
            Requirement.GNURADIO, "gnuradio-companion", "grcc",
            hint="apt install gnuradio | https://www.gnuradio.org"),
        Requirement.URH: _make_binary_checker(
            Requirement.URH, "urh",
            hint="pip install urh | https://github.com/jopohl/urh"),
        Requirement.BLUETOOTHCTL: _make_binary_checker(
            Requirement.BLUETOOTHCTL, "bluetoothctl",
            hint="apt install bluez"),
        Requirement.HCITOOL: _make_binary_checker(
            Requirement.HCITOOL, "hcitool",
            hint="apt install bluez"),
        Requirement.BTLEJACK_CLI: _make_binary_checker(
            Requirement.BTLEJACK_CLI, "btlejack",
            hint="pip install btlejack"),
        Requirement.SS7_SIGPLOIT: _make_binary_checker(
            Requirement.SS7_SIGPLOIT, "sigploit",
            hint="https://github.com/SigPloiter/SigPloit"),
        Requirement.UERANSIM: _make_binary_checker(
            Requirement.UERANSIM, "nr-ue", "nr-gnb",
            hint="https://github.com/aligungr/UERANSIM"),
        Requirement.PYSIM: _make_binary_checker(
            Requirement.PYSIM, "pySim-read.py", "pySim-prog.py",
            hint="https://github.com/osmocom/pysim"),
        Requirement.OSMOCOM: _make_binary_checker(
            Requirement.OSMOCOM, "osmo-trx", "osmo-bts-trx",
            hint="https://osmocom.org"),
    }

    return checkers


_CHECKERS: Optional[Dict[Requirement, Callable[[], CheckResult]]] = None


def _get_checkers() -> Dict[Requirement, Callable[[], CheckResult]]:
    global _CHECKERS
    if _CHECKERS is None:
        _CHECKERS = _make_checkers()
    return _CHECKERS


class HWValidator:
    """Valida pré-requisitos de hardware e software para módulos wireless.

    Example:
        validator = HWValidator()
        report = validator.validate(Requirement.WIFI_MONITOR_MODE, Requirement.SCAPY)
        if not report.all_satisfied:
            report.print_missing()
            return
    """

    def check(self, requirement: Requirement) -> CheckResult:
        """Verifica um requisito individual.

        Args:
            requirement: Requisito a verificar.

        Returns:
            CheckResult com status e detalhes.
        """
        checkers = _get_checkers()
        checker = checkers.get(requirement)
        if checker:
            try:
                return checker()
            except Exception as exc:
                logger.debug("Checker error for %s: %s", requirement, exc)
                return CheckResult(requirement, True, f"Verificação falhou (assumindo ok): {exc}")
        return CheckResult(requirement, True, "Verificação não implementada (assumindo ok).")

    def validate(self, *requirements: Requirement) -> ValidationReport:
        """Valida múltiplos requisitos e retorna um relatório.

        Args:
            *requirements: Requisitos a verificar.

        Returns:
            ValidationReport consolidado.
        """
        report = ValidationReport()
        for req in requirements:
            report.results.append(self.check(req))
        return report

    def require(
        self,
        *requirements: Requirement,
        silent: bool = False,
    ) -> bool:
        """Verifica requisitos e imprime mensagem de erro se algum falhar.

        Args:
            *requirements: Requisitos necessários.
            silent: Se True, não imprime nada (apenas retorna bool).

        Returns:
            True se todos satisfeitos, False caso contrário.
        """
        report = self.validate(*requirements)
        if not report.all_satisfied and not silent:
            print("\n  [!] Pré-requisitos não satisfeitos para este módulo:")
            report.print_missing()
            print("  [!] Resolva os pré-requisitos acima antes de continuar.\n")
        return report.all_satisfied

    def print_full_report(self, *requirements: Requirement) -> None:
        """Imprime relatório completo (satisfeitos e ausentes).

        Args:
            *requirements: Requisitos a verificar (todos se omitido).
        """
        if not requirements:
            requirements = tuple(Requirement)
        report = self.validate(*requirements)
        report.print_report(verbose=True)


# Instância global de conveniência
_default_validator: Optional[HWValidator] = None


def get_validator() -> HWValidator:
    """Retorna a instância global do HWValidator."""
    global _default_validator
    if _default_validator is None:
        _default_validator = HWValidator()
    return _default_validator


def require(*requirements: Requirement, silent: bool = False) -> bool:
    """Atalho global para HWValidator.require().

    Args:
        *requirements: Requisitos necessários.
        silent: Se True, não imprime nada.

    Returns:
        True se todos satisfeitos, False caso contrário.
    """
    return get_validator().require(*requirements, silent=silent)
