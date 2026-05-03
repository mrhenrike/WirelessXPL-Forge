# Prerequisites - Hardware and Software Requirements

**Author:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **Uniao Geek** - [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** English (en-US)

This document lists all hardware and software prerequisites for WirelessXPL-Forge modules. Most modules provide an `info` mode that works without any extra dependencies, allowing you to explore capabilities before investing in hardware.

---

## Quick Install

```bash
# Core framework (Wi-Fi, BLE, Zigbee, PCAP modules)
pip install wirelessxpl

# SIM/eSIM modules (PC/SC smart card)
pip install wirelessxpl[sim]

# SIM modules with full tooling (pySim, cryptography)
pip install wirelessxpl[sim-full]

# Cellular/Radio modules (SDR support)
pip install wirelessxpl[cellular]

# Everything
pip install wirelessxpl[all-modules]
```

---

## Software Dependencies by Module Category

### Core Framework

Installed automatically with `pip install wirelessxpl`:

- `scapy` - packet crafting and sniffing
- `pycryptodome` - cryptographic operations
- `requests` - HTTP client
- `qrcode[pil]` - QR code generation

### SIM/eSIM Modules (`wirelessxpl/modules/generic/sim/`)

Install with: `pip install wirelessxpl[sim]` or `pip install wirelessxpl[sim-full]`

| Package | Install | Required By | Purpose |
|---------|---------|-------------|---------|
| `pyscard` | `pip install wirelessxpl[sim]` | pysim_reader, sim_apdu_lab, sim_adm_brute, esim_rsp_bridge, simjacker_info | PC/SC smart card communication (ISO 7816) |
| `pySim` | `pip install wirelessxpl[sim-full]` | sim_cloner (native mode) | SIM provisioning and programming |
| `cryptography` | `pip install wirelessxpl[sim-full]` | esim_rsp_bridge (certificate analysis) | X.509 certificate parsing |

**System-level requirement:** PC/SC middleware

- **Windows:** WinSCard (built-in, no action needed)
- **Linux:** `sudo apt install pcscd pcsc-tools libpcsclite-dev`
- **macOS:** CCID driver (built-in since macOS 10.x)

### Cellular/Radio Modules (`wirelessxpl/modules/generic/cellular/`)

Install with: `pip install wirelessxpl[cellular]`

| Package | Install | Required By | Purpose |
|---------|---------|-------------|---------|
| `pyrtlsdr` | `pip install wirelessxpl[cellular]` | imsi_catcher_passive, gsm_freq_scanner | RTL-SDR device control from Python |

### External Tools (system-level, not pip)

These tools must be installed separately on the host system. WXF bridge modules call them via subprocess:

| Tool | Install (Debian/Ubuntu) | Required By | Purpose |
|------|------------------------|-------------|---------|
| `gr-gsm` | `apt install gr-gsm` or build from source | imsi_catcher_passive, gsm_freq_scanner, gsm_a51_crack | GSM signal decoding |
| `kalibrate-rtl` | `apt install kalibrate-rtl` | gsm_freq_scanner | GSM frequency scanning |
| `srsRAN 4G` | Build from [srsran.com](https://github.com/srsran/srsRAN_4G) | lte_imsi_catcher | LTE eNodeB/UE simulation |
| `UERANSIM` | Build from [github.com/aligungr/UERANSIM](https://github.com/aligungr/UERANSIM) | ueransim_5g_bridge, lte_imsi_catcher | 5G NR gNB/UE simulation |
| `SiGploit` | Clone from [github.com/SigPloiter/SigPloit](https://github.com/SigPloiter/SigPloit) | ss7_sigploit_bridge | SS7/Diameter/GTP testing |
| `Kraken` | Build from source + rainbow tables (~2 TB) | gsm_a51_crack | A5/1 cipher cracking |
| `simple_IMSI-catcher` | Clone from [github.com/Oros42/IMSI-catcher](https://github.com/Oros42/IMSI-catcher) | imsi_catcher_passive | Passive IMSI capture |
| `pySim-shell` / `pySim-prog` | `pip install pysim` or clone [github.com/osmocom/pysim](https://github.com/osmocom/pysim) | sim_cloner | SIM programming CLI |
| `tshark` | `apt install wireshark-common` | lte_imsi_catcher (parse_pcap) | PCAP parsing for NAS messages |

---

## Hardware Requirements

### IMPORTANT: Modules That Require Specific Hardware

Some modules will NOT function without the corresponding hardware. The `info` and `cve_database` modes always work without hardware, but operational modes require the devices listed below.

### PC/SC Smart Card Reader (SIM/eSIM Modules)

**Required for:** All SIM/eSIM modules (operational modes)

| Device | Approximate Cost | Notes |
|--------|-----------------|-------|
| ACS ACR38U | $10-15 | Basic SIM reader, widely available |
| ACS ACR122U | $25-35 | SIM + NFC/RFID combo reader |
| Omnikey 3121 | $20-30 | Enterprise-grade PC/SC reader |
| Gemalto IDBridge CT30 | $15-25 | Compact USB reader |

**Also required:** SIM/USIM card (your own). For cloning: programmable SIM cards (sysmocom sysmoUSIM-SJS1, Magic SIM, Osiris).

### SDR (Software Defined Radio) for Cellular Modules

**Required for:** GSM capture, frequency scanning, IMSI catching, A5/1 cracking

| Device | Approximate Cost | TX | RX | Best For |
|--------|-----------------|----|----|----------|
| **RTL-SDR v3/v4** | $15-25 | No | Yes | Passive GSM capture, frequency scanning (entry level) |
| **HackRF One** | $300-350 | Yes | Yes | TX+RX, wider bandwidth, GSM/LTE passive |
| **BladeRF x40/xA4** | $400-500 | Yes | Yes | Full-duplex, LTE capable |
| **USRP B200** | $700-1000 | Yes | Yes | LTE eNodeB (active IMSI catcher), research grade |
| **USRP B210** | $1200-1500 | Yes | Yes | 2x2 MIMO, dual-band LTE, best for srsRAN |

### Hardware Requirements by Module

| Module | Minimum Hardware | Recommended | Cost Entry |
|--------|-----------------|-------------|------------|
| **pysim_reader** | PC/SC reader + SIM card | Any USB reader | ~$15 |
| **sim_apdu_lab** | PC/SC reader + SIM card | Any USB reader | ~$15 |
| **sim_adm_brute** | PC/SC reader + SIM card | Any USB reader | ~$15 |
| **sim_cloner** | 2x PC/SC readers + programmable SIM | 2x readers + sysmoUSIM | ~$40 |
| **esim_rsp_bridge** | PC/SC reader + eUICC card | Reader + eSIM dev kit | ~$30 |
| **simjacker_info** | PC/SC reader (detect/scan modes only) | Any USB reader | ~$15 |
| **imsi_catcher_passive** | RTL-SDR | HackRF One | ~$15 |
| **gsm_freq_scanner** | RTL-SDR | RTL-SDR v4 | ~$15 |
| **lte_imsi_catcher** | RTL-SDR (passive) / USRP B200+ (active) | USRP B210 | $15-$1500 |
| **gsm_a51_crack** | RTL-SDR + 2 TB disk (rainbow tables) | HackRF + fast SSD | ~$15 + storage |
| **ss7_sigploit_bridge** | None (IP network to SS7 lab) | Osmocom core network lab | $0 (software only) |
| **ueransim_5g_bridge** | None (localhost simulation) | Open5GS / free5GC lab | $0 (software only) |

### Modules That Work Without Any Hardware

These modules (or specific modes) function purely in software:

- **ss7_sigploit_bridge** - requires only network connectivity to an SS7/SIGTRAN lab (Osmocom)
- **ueransim_5g_bridge** - runs entirely on localhost with UERANSIM + 5G core (Open5GS, free5GC)
- **All modules, `info` mode** - displays capabilities, CVE databases, and technical references
- **All modules, `cve_database` mode** - offline CVE reference (where available)
- **simjacker_info** (7 of 9 modes) - SIMJacker/WIBattack reference, OTA SMS analysis, mitigation guidance
- **gsm_freq_scanner, `band_info` mode** - ARFCN frequency calculation (no SDR needed)

---

## Recommended Lab Setups

### Budget Lab (~$30)

- 1x RTL-SDR v3/v4 ($15)
- 1x USB PC/SC SIM reader ($15)
- 1x Your own SIM card ($0)
- Software: gr-gsm, kalibrate-rtl, pyscard

**Unlocks:** Passive GSM capture, IMSI catching, frequency scanning, SIM reading/analysis, SIMJacker detection

### Intermediate Lab (~$350)

- 1x HackRF One ($300)
- 1x USB PC/SC reader ($15)
- 1x Programmable SIM (sysmoUSIM, $15-20)
- Software: gr-gsm, Kraken, pySim, SiGploit

**Unlocks:** Everything from Budget + A5/1 cracking, SIM cloning, SS7 testing (with Osmocom lab)

### Full Research Lab (~$1500+)

- 1x USRP B210 ($1200-1500)
- 1x HackRF One ($300, secondary)
- 2x PC/SC readers ($30)
- Programmable SIMs ($20-40)
- Software: srsRAN, UERANSIM, Open5GS, full tool chain

**Unlocks:** Everything, including active LTE IMSI catcher, 5G NR testing, full cellular stack

---

## Shielded Environment Notice

Operating fake base stations (IMSI catchers, rogue eNodeB), transmitting on licensed spectrum, or intercepting cellular communications is **illegal** in most jurisdictions without explicit authorization and spectrum license. These modules are designed for **authorized security research** in **shielded lab environments** only.

Passive reception (RTL-SDR receive-only) may be legal in some jurisdictions for personal research. Check your local telecommunications regulations before use.

---

## Novos Módulos — Requisitos de Hardware e Software (mai/2026)

### Core (todos os novos módulos)

| Componente | Instalação |
|---|---|
| `wirelessxpl/core/phase_gateway.py` | nativo — sem dependências externas |
| `wirelessxpl/core/hw_validator.py` | nativo — sem dependências externas |
| `wirelessxpl/core/polyglot_orchestrator.py` | gcc, rustc, go, ruby, node no PATH |

### Z-Wave (`zwave/zwave_attack_suite.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| Dongle Z-Wave USB (UZB7, Aeotec Z-Stick) | Hardware | Comprar: Aeotec Z-Stick Gen5+ |
| `pyserial` | Python | `pip install pyserial` |
| `pyzwave` | Python | `pip install pyzwave` |
| `gcc` | Sistema | `apt install build-essential` |

### Matter / Thread (`matter/matter_thread_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| `python-matter-server` | Python | `pip install python-matter-server` |
| `zeroconf` | Python | `pip install zeroconf` |
| `chip-tool` | Sistema | Build: github.com/project-chip/connectedhomeip |
| `avahi-browse` | Sistema | `apt install avahi-utils` |

### V2X / DSRC (`v2x/v2x_dsrc_attack.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| USRP B200/B210 ou HackRF One | Hardware | SDR com antena 5.9 GHz |
| `gnuradio` | Sistema | `apt install gnuradio` |
| `hackrf_transfer` | Sistema | `apt install hackrf` |
| `scapy` | Python | `pip install scapy` |

### TPMS (`tpms/tpms_spoof_replay.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| RTL-SDR (RX) | Hardware | RTL-SDR v3 |
| HackRF One (TX para spoof) | Hardware | HackRF One |
| `rtl_433` | Sistema | `apt install rtl-433` |
| `hackrf_transfer` | Sistema | `apt install hackrf` |

### UWB (`uwb/uwb_relay_attack.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| Decawave DWM1001 ou Qorvo DW3120 | Hardware | Kit de desenvolvimento UWB |
| `pyserial` | Python | `pip install pyserial` |
| `pyusb` | Python | `pip install pyusb` |

### DECT (`dect/dect_eavesdrop_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| RTL-SDR (RX @ 1.88-1.90 GHz) | Hardware | RTL-SDR v3 |
| HackRF One (TX para clone) | Hardware | HackRF One |
| `dect-scanner` | Sistema | `git clone https://github.com/znuh/dect-scanner && make` |

### NFC (`nfc/nfc_relay_ndef_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| ACR122U ou PN532 | Hardware | Leitor NFC USB |
| Proxmark3 (para clone Mifare) | Hardware | Proxmark3 RDV4 |
| `nfcpy` | Python | `pip install nfcpy` |
| `pyscard` | Python | `pip install pyscard` |
| `mfoc` + `nfc-mfclassic` | Sistema | `apt install mfoc libnfc-bin` |

### CVE-2025-13834 BT RFCOMM OOB

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador BT BR/EDR | Hardware | Qualquer dongle BT classe 1/2 |
| `socket` + `struct` | Python | stdlib |

### CVE-2021-27289 Zigbee Replay

| Requisito | Tipo | Instalação |
|---|---|---|
| ApiMote ou CC2531 com firmware KillerBee | Hardware | Kit KillerBee |
| `killerbee` | Python | `pip install killerbee` |
| `scapy` | Python | `pip install scapy` |

### CVE-2024-30078 Windows WiFi Driver RCE

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com packet injection | Hardware | Alfa AWUS036ACS |
| `libpcap` + `gcc` | Sistema | `apt install libpcap-dev build-essential` |
| `scapy` | Python | `pip install scapy` |

### CVE-2024-45569 Qualcomm WLAN ML IE

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com beacon injection | Hardware | Alfa AWUS036ACS |
| `libpcap` + `gcc` | Sistema | `apt install libpcap-dev build-essential` |
| `scapy` | Python | `pip install scapy` |

### AirSnitch Client Isolation Bypass

| Requisito | Tipo | Instalação |
|---|---|---|
| 2x adaptadores WiFi monitor mode | Hardware | — |
| `airsnitch` | Python | `git clone https://github.com/vanhoefm/airsnitch /opt/airsnitch` |

### WIFIAIR-C2 Beacon C2 Channel

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com beacon injection | Hardware | Alfa AWUS036ACS |
| `scapy` | Python | `pip install scapy` |
| `pycryptodome` | Python | `pip install pycryptodome` |
