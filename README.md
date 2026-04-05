# WirelessXPL-Forge

Shell and modules for **authorised** lab work on **802.11 (WPA2 / WPA3 / TKIP / WPE / EAPOL)** and **Bluetooth LE**: **offline PCAP analysis** (Scapy), **wordlists**, and **bridges** to system tools. This repo does **not** embed [aircrack-ng](https://www.aircrack-ng.org/), [hcxtools](https://github.com/ZerBea/hcxtools), or [hashcat](https://hashcat.net/hashcat/) — install them on the host (e.g. Kali, Debian, WSL2).

**Siblings:** [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) (routers/switches), [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) (NGFW/UTM lab, private).

**Maintainer:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| [União Geek](https://github.com/Uniao-Geek)  
**Lineage:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → wireless split.

**Language:** **English (en-US)** — default. **Português (pt-BR):** [README.pt-BR.md](README.pt-BR.md)

[![Python 3.8–3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml)

---

## System prerequisites (not bundled)

| Tooling | Role |
|---------|------|
| **aircrack-ng** suite | `aircrack-ng`, `airodump-ng`, `aireplay-ng` — workflows used by PCAP modules |
| **hcxtools** | `hcxpcapngtool` / `hcxdumptool` — PMKID / hash lines for hashcat |
| **hashcat** | WPA modes 22000/22001 — offline cracking |
| **tshark** (optional) | BLE / 802.11 dissection when Scapy layers are thin |
| **mdk4** / **mdk3** (optional) | Advanced frame storms / deauth modes (`wifi_lab` bridges) |
| **hostapd** + **dnsmasq** (optional) | Rogue / evil-twin + DHCP/DNS for captive flows |
| **Bruce ESP32** (optional) | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) — handheld wardriving; export PCAP to `generic/pcap/*` |

Run `use generic/external/wireless_tool_prereq_audit` after install to verify PATH.

---

## What this repository contains

| Type | Role |
|------|------|
| **generic/pcap** | Handshake / PMKID / TKIP / Dragonblood / WPE / credential patterns / **EAPOL 4-way survey** / BLE PCAP survey |
| **generic/bluetooth** | BLE scan / enumerate / write (Linux + bluepy typical) |
| **generic/wordlist** | Parameterised wordlist generator |
| **generic/cve** | Embedded hints (KRACK, FragAttacks, Dragonblood, …) |
| **generic/external** | hcxtools bridge, Bruce lab notes, prerequisite audit |
| **generic/wifi_lab** | Rogue AP (`hostapd`), evil-twin runbook + **6× hostapd templates**, **modern captive portal**, deauth barrage, **mdk4/mdk3**, handshake validator, **hashcat GPU orchestrator**, **PCAP anomaly + optional sklearn**, **GPS NMEA→NDJSON**, **research submodule index**, Evilginx prereq pointer |
| **payloads / encoders** | Inherited minimal set |

**Out of scope:** router exploit trees, IP cameras/DVRs as primary target.

Architecture PNGs under `docs/img/architecture/` are legacy visuals from RouterXPL lineage.

---

## Compatibility

Prefer **Linux** or **WSL2** for capture tools and BLE. **Python:** 3.8–3.13 (`telnetlib3` on 3.13+).

---

## Quick install

### Python

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
# Optional BLE: pip install bluepy
python3 wxf.py
```

### Diagnostics

```bash
python tools/env_doctor.py
```

---

## Usage overview

### Interactive shell

After `python wxf.py`:

```text
help
use generic/pcap/pcap_eapol_survey
set pcap_file /path/to/capture.pcapng
run
search pcap
exit
```

**Prompt:** `WXF_RAW_PROMPT`, `WXF_MODULE_PROMPT` (see `wirelessxpl/interpreter.py`).

### Non-interactive mode

```bash
python wxf.py -m generic/pcap/pcap_ap_station_mapper -s "pcap_file /tmp/lab.cap"
```

### Logs

`wirelessxpl.log` in the current working directory.

---

## Documentation

- [docs/wiki/en-US/README.md](docs/wiki/en-US/README.md) · [docs/wiki/pt-BR/README.md](docs/wiki/pt-BR/README.md) · [docs/wiki/README.md](docs/wiki/README.md)
- [docs/FULL_CATALOG.md](docs/FULL_CATALOG.md), [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) — regenerate with `tools/generate_full_catalog.py` / `generate_coverage_matrix.py` when modules change.

---

## Release notes — 3.5.2

- **wifi_lab:** `research_ecosystem_status` + `resources/catalogs/wireless_research_submodules.json` for superproject trees under `submodules/IoT/wireless-research/` (set `WXF_SUPERPROJECT_ROOT`). **hashcat_gpu_orchestrator** (`-I`, auto `-d`, `-w`, dry-run). **pcap_rf_anomaly_ml** (heuristic score + optional **IsolationForest** via extra `ml-lite`). **gps_wardriving_ndjson** (GGA → NDJSON). **evil_twin_hostapd_templates** (six configs: open, WPA2, SAE, transition, OWE stub, enterprise stub). **evilginx_prereq_pointer**. Extended **wireless_tool_prereq_audit** (wifite, bully, reaver, pixiewps, john, airgeddon, tcpdump, bluetoothctl, gpspipe).

## Release notes — 3.5.1

- **wifi_lab:** rogue AP (`hostapd`), evil-twin dnsmasq snippets, **captive portal** UI (inline modern CSS), aggressive **aireplay-ng** multi-stream deauth, **mdk4/mdk3** bridges, **PCAP handshake validator** (+ hcxtools probe). PMF/802.11w limitations documented for Apple/iOS targets.

## Release notes — 3.5.0

- **WirelessXPL-Forge** split from RouterXPL-Forge: `wirelessxpl` package, `wxf.py`, PCAP/BLE/CVE/wordlist focus.
- **New:** `pcap_eapol_survey` (KRACK-era hints), `pcap_ble_advertising_survey`, `wireless_tool_prereq_audit`, `bruce_esp32_lab_notes`, `hcx_toolchain_bridge`.
- **CVE embed:** KRACK + FragAttacks entries in `core/cve/cve_db.py`.
- **Bootstrap:** `RouterXPL-Forge/tools/bootstrap_wirelessxpl_forge.py`; trim routers with `trim_routerxpl_wireless_scope.py`; Firewall clone: `trim_firewallxpl_wireless_scope.py`.

---

## Tests (contributors)

```bash
python tools/compat_smoke.py
python tools/generate_full_catalog.py
```

---

## Governance

| English (default) | Português (pt-BR) |
|-------------------|---------------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [CODE_OF_CONDUCT.pt-BR.md](CODE_OF_CONDUCT.pt-BR.md) |
| [SECURITY.md](SECURITY.md) | [SECURITY.pt-BR.md](SECURITY.pt-BR.md) |
| [CONTRIBUTORS.md](CONTRIBUTORS.md) | [CONTRIBUTORS.pt-BR.md](CONTRIBUTORS.pt-BR.md) |

---

## License

BSD — see [LICENSE](LICENSE).

---

## Acknowledgments

- [Riposte](https://github.com/fwkz/riposte), [threat9/routersploit](https://github.com/threat9/routersploit), [aircrack-ng](https://www.aircrack-ng.org/), [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
