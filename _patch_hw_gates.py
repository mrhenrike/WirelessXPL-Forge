#!/usr/bin/env python3
"""Aplica HWValidator + PhaseGateway nos módulos existentes que não têm gate de hardware."""

import re
from pathlib import Path

BASE = Path(__file__).parent / "wirelessxpl" / "modules" / "generic"

HW_IMPORT = (
    "\nfrom wirelessxpl.core.hw_validator import HWValidator, Requirement"
    "\nfrom wirelessxpl.core.phase_gateway import PhaseGateway"
)

PATCHES = [
    {
        "file": BASE / "bluetooth" / "ble_sweyntooth_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        require_authorised_lab(self.i_know_scope)\n        mode = str(self.mode).strip().lower()\n        if mode == \"info\":\n            self._info_mode()\n        elif mode == \"list\":\n            self._list_mode()\n        else:\n            self._run_attack(mode)",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        require_authorised_lab(self.i_know_scope)\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"SweynTooth BLE\")\n"
            "        _gw.phase(\n"
            "            \"nRF52 Dongle\",\n"
            "            lambda: _validator.require(Requirement.NRF52_DONGLE, silent=True),\n"
            "            fix_hint=\"Conecte um dongle nRF52 com firmware SweynTooth.\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n"
            "        mode = str(self.mode).strip().lower()\n"
            "        if mode == \"info\":\n"
            "            self._info_mode()\n"
            "        elif mode == \"list\":\n"
            "            self._list_mode()\n"
            "        else:\n"
            "            self._run_attack(mode)"
        ),
    },
    {
        "file": BASE / "bluetooth" / "braktooth_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        require_authorised_lab(self.i_know_scope)\n        mode = str(self.mode).strip().lower()\n        if mode == \"info\":\n            self._info_mode()\n        elif mode == \"list\":\n            self._list_mode()\n        else:\n            self._run_attack(mode)",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        require_authorised_lab(self.i_know_scope)\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"BrakTooth BLE\")\n"
            "        _gw.phase(\n"
            "            \"nRF52 Dongle\",\n"
            "            lambda: _validator.require(Requirement.NRF52_DONGLE, silent=True),\n"
            "            fix_hint=\"Conecte um dongle nRF52 com firmware BrakTooth.\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n"
            "        mode = str(self.mode).strip().lower()\n"
            "        if mode == \"info\":\n"
            "            self._info_mode()\n"
            "        elif mode == \"list\":\n"
            "            self._list_mode()\n"
            "        else:\n"
            "            self._run_attack(mode)"
        ),
    },
    {
        "file": BASE / "bluetooth" / "knob_attack_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        require_authorised_lab(self.i_know_scope)\n        mode = str(self.mode).strip().lower()\n        if mode not in self._VALID_MODES:",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        require_authorised_lab(self.i_know_scope)\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"KNOB Attack\")\n"
            "        _gw.phase(\n"
            "            \"Bluetooth Adapter\",\n"
            "            lambda: _validator.require(Requirement.BLUETOOTH_ADAPTER, silent=True),\n"
            "            fix_hint=\"Conecte um adaptador Bluetooth. hciconfig hci0 up\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n"
            "        mode = str(self.mode).strip().lower()\n"
            "        if mode not in self._VALID_MODES:"
        ),
    },
    {
        "file": BASE / "cellular" / "ueransim_5g_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        \"\"\"Execute the selected UERANSIM 5G mode.\"\"\"\n        mode = str(self.mode).strip().lower()\n\n        if mode == \"info\":\n            self._info_mode()\n            return\n        if mode == \"cve_check\":\n            self._cve_check()\n            return\n\n        if not self.i_know_scope:",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        \"\"\"Execute the selected UERANSIM 5G mode.\"\"\"\n"
            "        mode = str(self.mode).strip().lower()\n\n"
            "        if mode in (\"info\", \"cve_check\"):\n"
            "            if mode == \"info\": self._info_mode()\n"
            "            else: self._cve_check()\n"
            "            return\n\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"UERANSIM 5G Bridge\")\n"
            "        _gw.phase(\n"
            "            \"UERANSIM binary\",\n"
            "            lambda: _validator.require(Requirement.UERANSIM, silent=True),\n"
            "            fix_hint=\"apt install ueransim  ou  https://github.com/aligungr/UERANSIM\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n\n"
            "        if not self.i_know_scope:"
        ),
    },
    {
        "file": BASE / "cellular" / "ss7_sigploit_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        \"\"\"Execute the selected SS7/Diameter/GTP attack mode.\"\"\"\n        mode = str(self.mode).strip().lower()\n\n        if mode == \"info\":\n            self._info_mode()\n            return\n        if mode == \"cve_database\":\n            self._cve_database()\n            return\n\n        if not self.i_know_scope:",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        \"\"\"Execute the selected SS7/Diameter/GTP attack mode.\"\"\"\n"
            "        mode = str(self.mode).strip().lower()\n\n"
            "        if mode in (\"info\", \"cve_database\"):\n"
            "            if mode == \"info\": self._info_mode()\n"
            "            else: self._cve_database()\n"
            "            return\n\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"SS7/SigPloit Bridge\")\n"
            "        _gw.phase(\n"
            "            \"SigPloit / SS7 toolset\",\n"
            "            lambda: _validator.require(Requirement.SS7_SIGPLOIT, silent=True),\n"
            "            fix_hint=\"git clone https://github.com/SigPloiter/SigPloit\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n\n"
            "        if not self.i_know_scope:"
        ),
    },
    {
        "file": BASE / "external" / "proxmark_rfid_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:\n        op = str(self.mode).strip().lower()\n\n        if op == \"info\":\n            self._info()\n            return\n\n        if not bool(self.i_know_scope):",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        op = str(self.mode).strip().lower()\n\n"
            "        if op == \"info\":\n"
            "            self._info()\n"
            "            return\n\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"Proxmark3 RFID Bridge\")\n"
            "        _gw.phase(\n"
            "            \"Proxmark3\",\n"
            "            lambda: _validator.require(Requirement.PROXMARK3, silent=True),\n"
            "            fix_hint=\"Conecte um Proxmark3. https://github.com/RfidResearchGroup/proxmark3\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return\n\n"
            "        if not bool(self.i_know_scope):"
        ),
    },
    {
        "file": BASE / "external" / "sigfox_lorawan_bridge.py",
        "import_after": "from wirelessxpl.core.exploit import *\nfrom wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab",
        "run_search": "    def run(self) -> None:\n        require_authorised_lab(self.i_know_scope)",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        require_authorised_lab(self.i_know_scope)\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"SigFox/LoRaWAN Bridge\")\n"
            "        _gw.phase(\n"
            "            \"SDR Hardware\",\n"
            "            lambda: _validator.require(Requirement.SDR_ANY, silent=True),\n"
            "            fix_hint=\"Conecte um SDR (HackRF, RTL-SDR, USRP).\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return"
        ),
    },
    {
        "file": BASE / "sim" / "sim_cloner.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"SIM Cloner\")\n"
            "        _gw.phase(\n"
            "            \"SIM Card Reader\",\n"
            "            lambda: _validator.require(Requirement.SIM_READER, silent=True),\n"
            "            fix_hint=\"Conecte um leitor SIM (ACR38U, ACS ACR38, ou similar).\",\n"
            "        )\n"
            "        _gw.phase(\n"
            "            \"pyscard\",\n"
            "            lambda: _validator.require(Requirement.PYSCARD, silent=True),\n"
            "            fix_hint=\"pip install pyscard\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return"
        ),
    },
    {
        "file": BASE / "wifi_lab" / "selective_jammer.py",
        "import_after": "from wirelessxpl.core.exploit import *\n\nfrom wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab",
        "run_search": "    def run(self) -> None:\n        require_authorised_lab(self.i_know_scope)",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        require_authorised_lab(self.i_know_scope)\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"Selective Jammer\")\n"
            "        _gw.phase(\n"
            "            \"HackRF One (TX para jamming)\",\n"
            "            lambda: _validator.require(Requirement.HACKRF, silent=True),\n"
            "            fix_hint=\"Jamming requer HackRF One. RTL-SDR é somente RX.\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return"
        ),
    },
    {
        "file": BASE / "wifi_lab" / "hashcat_gpu_orchestrator.py",
        "import_after": "from wirelessxpl.core.exploit import *",
        "run_search": "    def run(self) -> None:",
        "run_replace": (
            "    def run(self) -> None:\n"
            "        _validator = HWValidator()\n"
            "        _gw = PhaseGateway(\"Hashcat GPU Orchestrator\")\n"
            "        _gw.phase(\n"
            "            \"Hashcat\",\n"
            "            lambda: _validator.require(Requirement.HASHCAT, silent=True),\n"
            "            fix_hint=\"apt install hashcat  ou  https://hashcat.net/hashcat/\",\n"
            "        )\n"
            "        if not _gw.run():\n"
            "            return"
        ),
    },
]


def patch_file(info: dict) -> str:
    filepath: Path = info["file"]
    if not filepath.exists():
        return f"SKIP (não existe): {filepath.name}"

    src = filepath.read_text(encoding="utf-8")

    # Adiciona imports se não existirem
    if "from wirelessxpl.core.hw_validator import" not in src:
        anchor = info["import_after"]
        if anchor in src:
            src = src.replace(anchor, anchor + HW_IMPORT, 1)
        else:
            # Insere no topo logo após 'from __future__ import annotations'
            src = src.replace(
                "from __future__ import annotations",
                "from __future__ import annotations" + HW_IMPORT,
                1,
            )

    # Aplica substituição no run()
    if info["run_search"] in src:
        src = src.replace(info["run_search"], info["run_replace"], 1)
        filepath.write_text(src, encoding="utf-8")
        return f"OK: {filepath.name}"
    else:
        # Tenta sem whitespace exato — busca apenas a primeira linha do run
        first_line = info["run_search"].split("\n")[0]
        if first_line in src:
            filepath.write_text(src, encoding="utf-8")  # Salva pelo menos os imports
            return f"PARTIAL (imports adicionados, run() não encontrado exatamente): {filepath.name}"
        return f"SKIP (padrão run() não encontrado): {filepath.name}"


if __name__ == "__main__":
    for patch in PATCHES:
        result = patch_file(patch)
        print(result)
    print("\nPatch concluído.")
