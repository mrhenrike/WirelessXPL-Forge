# Introduction, scope, and installation

**Language:** English (en-US). **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

## What WirelessXPL-Forge is

A **modular Python framework** for **authorised** wireless security research: **802.11**, **Bluetooth / BLE**, **Zigbee**, **RFID**, **PCAP pipelines**, **ESP32 / Bruce** serial workflows, and bridges to common offensive wireless tools.

**Full attack-surface map (MikrotikAPI-BF style — device-class gallery in [wiki hub README](../README.md)):**

![WirelessXPL — full attack surface & coverage](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png)

**Example (SOHO router device-class map, shared lab vocabulary with RouterXPL-Forge):**

![SOHO router — attack surface & tool coverage](../../img/architecture/rxf_arch_router_soho.png)

## Legal and ethical use

**Use only on networks and devices you own or have explicit written permission to test.** Maintainers are not responsible for misuse. Follow your contract and rules of engagement.

## Requirements

- **Python 3.8–3.13**
- Core dependencies install with **`pip install wirelessxpl`** (see below) or `pip install -r requirements.txt` from a source checkout
- **Python 3.13+:** `telnetlib3` replaces removed stdlib `telnetlib`
- **PCAP modules** need **Scapy**; live capture on Windows may need Npcap — offline `.pcap` analysis often works with Python only

## Install from PyPI (recommended)

```bash
python3 -m pip install -U pip
pip install wirelessxpl
# optional extras:
pip install "wirelessxpl[serial]"    # pyserial / Bruce ESP32
pip install "wirelessxpl[ml-lite]"   # lightweight ML stack
```

After install, the entry points **`wxf`** / **`python -m wirelessxpl`** are available on your `PATH` (see [PyPI project](https://pypi.org/project/wirelessxpl/)).

## Install from source

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
python3 -m pip install -r requirements.txt
# editable install (optional):
pip install -e .
```

## Diagnostics

```bash
python tools/env_doctor.py
```

Checks core imports. Scapy is not in the doctor today; fix Scapy manually if `generic/pcap/*` imports fail.

## Start the app

```bash
wxf
# or
python wxf.py
# or
python -m wirelessxpl
```

Interactive mode needs a **TTY**. For automation use `-m` / `-s` (see [04-non-interactive-mode.md](04-non-interactive-mode.md)).

## Log file

**`wirelessxpl.log`** in the current working directory receives bootstrap logging.

## Command history

Readline history is typically **`~/.wxf_history`**.

---

[Wiki hub](../README.md)
