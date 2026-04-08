# WirelessXPL-Forge

> **Modular wireless security research framework** for 802.11 (WPA2/WPA3/WPE/EAPOL), Bluetooth Classic, BLE, Zigbee, RFID and ESP32 lab workflows — designed for authorised penetration testing, research, and education.

**Version:** 1.1.1 | **License:** BSD-3-Clause | **Python:** 3.8 – 3.13

**Language:** **English (en-US)** — default · **Português (pt-BR):** [README.pt-BR.md](README.pt-BR.md)

[![Python 3.8–3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml)
[![Release](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml)
[![PyPI](https://img.shields.io/pypi/v/wirelessxpl.svg)](https://pypi.org/project/wirelessxpl/)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)

---

## About

**WirelessXPL-Forge (WXF)** is an interactive shell and module framework for wireless security research. It provides:

- A **Metasploit-like CLI** (`use`, `set`, `run`, `search device=wifi`) for wireless attack and analysis workflows
- Native Python modules for **FragAttacks**, **KRACK**, **WPA3/Dragonblood**, **BLE pairing attacks**, **Braktooth**, **BlueBorne**, **AWDL**, **Zigbee/KillerBee**, and more
- **Bridge modules** for external tools: `aircrack-ng`, `hcxdumptool`, `mdk4`, `wifiphisher`, `eaphammer`, `airgeddon`, `bettercap`, `btlejack`, `opendrop`
- **Serial orchestration** for **Bruce firmware** (ESP32 Marauder) with semiautonomous flow profiles
- **Upstream catalogs** tracking incorporation of community issues/PRs across 15+ security research repos
- **PCAP analysis pipelines**: EAPOL 4-way, PMKID, TKIP, Dragonblood, WPE, BLE, PCAP SQL workspace

**Siblings:** [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) (routers/switches) · [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) (NGFW/UTM, private)

**Lineage:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → wireless fork

**Maintainer:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## System Prerequisites (not bundled)

| Tool | Role |
|------|------|
| **aircrack-ng suite** | `aircrack-ng`, `airodump-ng`, `aireplay-ng` — used by PCAP and wifi_lab modules |
| **hcxtools / hcxdumptool** | PMKID capture and hash conversion for hashcat |
| **hashcat** | WPA2/WPA3 offline cracking (modes 22000/22001) |
| **tshark** *(optional)* | BLE / 802.11 dissection when Scapy layers are thin |
| **mdk4 / mdk3** *(optional)* | Deauth storms, beacon floods, mesh flooding |
| **hostapd + dnsmasq** *(optional)* | Rogue AP / evil-twin + DHCP/DNS for captive portal flows |
| **wifiphisher** *(optional)* | Phishing campaigns via bridge module |
| **eaphammer** *(optional)* | EAP/PEAP credential capture |
| **airgeddon** *(optional)* | Multi-attack menu (bridge available) |
| **btlejack** *(optional)* | BLE sniff/jam/hijack |
| **opendrop / owl** *(optional)* | AWDL/AirDrop lab workflows |
| **Bruce ESP32 firmware** *(optional)* | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) — handheld wardriving; export PCAP to `generic/pcap/*` |
| **pyserial** *(optional)* | Serial bridge to Bruce firmware (`pip install wirelessxpl[serial]`) |

Run `use generic/external/wireless_tool_prereq_audit` after install to verify your PATH.

---

## Quick Install

### From PyPI

```bash
pip install wirelessxpl
# with serial support for Bruce/ESP32:
pip install "wirelessxpl[serial]"
# with ML signal classification:
pip install "wirelessxpl[ml-lite]"
```

### From Source

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
pip install -r requirements.txt
python wxf.py
# or
python -m wirelessxpl
# or (after pip install -e .)
wxf
```

### WSL2 / Kali (recommended for capture tools)

```bash
sudo apt install aircrack-ng hcxtools hcxdumptool mdk4 hostapd dnsmasq tshark
pip install wirelessxpl
```

---

## Quick Start

```
$ python wxf.py
wxf > help
wxf > show modules
wxf > search device=wifi
wxf > search device=bluetooth
wxf > use generic/wifi_lab/handshake_snooper
wxf (HandshakeSnooper) > show options
wxf (HandshakeSnooper) > set interface wlan0mon
wxf (HandshakeSnooper) > set target_bssid AA:BB:CC:DD:EE:FF
wxf (HandshakeSnooper) > run
```

### Non-interactive (scripting)

```bash
python wxf.py -m generic/wifi_lab/handshake_snooper \
  interface=wlan0mon target_bssid=AA:BB:CC:DD:EE:FF
```

---

## Module Reference

### Wi-Fi / 802.11 (generic/wifi_lab)

| Module | Description |
|--------|-------------|
| `fragattacks` | FragAttacks (CVE-2020-26140+) — frame injection + 802.11ax detection |
| `handshake_snooper` | PMKID-first + deauth handshake capture pipeline |
| `wpa3_attack_suite` | Dragonblood SAE flood, CSA+harvest, Double SSID, downgrade |
| `auth_flood` | Auth/EAPOL flood, amok mode, mesh flood (mdk4 backend) |
| `beacon_flood` | Beacon spam with custom SSIDs |
| `evil_twin_workflow` | Full evil-twin with verify-on-capture (aircrack-ng) |
| `captive_portal_modern_lab` | Modern captive portal with HTML/JS credential collector |
| `mitm_wifi_bridge` | ARP/DNS spoofing + Ghost combo (bettercap) |
| `adaptive_harvest` | Score-driven channel/PMKID adaptive harvesting |
| `wardriving_deauth_loop` | Automated wardriving scan/deauth/capture cycles |
| `wireless_ids` | Lightweight IDS: BSSID baseline + rogue AP detection |
| `awdl_attack` | AWDL/AirDrop (opendrop + owl) — discover, send, DoS |
| `momo_integrated_attack` | KARMA + PMKID-first + downgrade orchestration |
| `research_ecosystem_status` | Status of all research submodule integrations |
| `gps_wardriving_ndjson` | GPS NMEA → NDJSON wardriving log |
| `wifi_sniffer` | Multi-backend sniffer (tcpdump/scapy/tshark) |

### PCAP Analysis (generic/pcap)

| Module | Description |
|--------|-------------|
| `pcap_handshake_extractor` | Extract WPA2 handshakes from capture |
| `pcap_eapol_survey` | EAPOL 4-way handshake survey and analysis |
| `pcap_pmkid_extractor` | PMKID extraction for offline cracking |
| `pcap_dragonblood` | WPA3 Dragonblood SAE PCAP patterns |
| `pcap_sql_workspace` | SQLite workspace for PCAP ingestion and analyst notes |

### Bluetooth / BLE (generic/bluetooth)

| Module | Description |
|--------|-------------|
| `bt_hid_injection` | Bluetooth HID keyboard injection (Broadcom fallback) |
| `bt_baseband_attack` | BrakTooth / SweynTooth via ESP32 serial |
| `bt_session_attack` | KNOB, BIAS, BLUFFS session-layer attacks |
| `blueborne_attack` | BlueBorne L2CAP overflow (kernel offset profiles) |
| `ble_btlejack` | BTLEJack BLE sniff/jam/hijack |
| `ble_crackle` | BLE Legacy Pairing key recovery |

### CVE / Exploits (generic/cve)

| Module | Description |
|--------|-------------|
| `zigbee_attack` | Zigbee / IEEE 802.15.4 via KillerBee (Sewio driver) |
| `krack_attack` | KRACK (WPA2 4-way replay + msg3 collection) |
| `ssid_confusion` | SSID Confusion attack |
| `pmkid_attack` | PMKID clientless attack |

### External Bridges (generic/external)

| Module | Description |
|--------|-------------|
| `bruce_serial_bridge` | ESP32 Bruce firmware serial flow engine (15+ profiles) |
| `bruce_esp32_lab_notes` | Bruce/Marauder lab operational reference |
| `bruce_upstream_tracker` | Bruce firmware issues/PRs catalog viewer |
| `airgeddon_bridge` | Airgeddon multi-mode subprocess bridge |
| `wifiphisher_bridge` | Wifiphisher bridge with inline sniffer |
| `eaphammer_bridge` | EAPHammer bridge (Win11 PEAP + HTTP coercion) |
| `mdk4_bridge` | mdk4 bridge (all modes including mesh) |
| `wifipumpkin3_bridge` | WifiPumpkin3 bridge (URL sanitization) |
| `wireless_tool_prereq_audit` | Dependency check for all system tools |

---

## Bruce / ESP32 Marauder Integration

WXF includes a full serial flow engine for [BruceDevices/firmware](https://github.com/BruceDevices/firmware):

```
wxf > use generic/external/bruce_serial_bridge
wxf (BruceSerialBridge) > set serial_port /dev/ttyACM0
wxf (BruceSerialBridge) > set flow_profile capture_handshake_flow
wxf (BruceSerialBridge) > run

# Available flow profiles:
#   baseline_status_flow         capture_handshake_flow
#   wifi_menu_navigation_flow    deauth_clone_verify_flow
#   sniffer_capture_flow         evil_portal_karma_flow
#   wifi_attack_lab_flow         raw_sniffer_probe_flow
#   wifi_bruteforce_recon_flow   navigation_recovery_flow
#   captive_portal_endpoint_config_flow
#   repeater_wisp_setup_flow     external_adapter_probe_flow
#   webui_password_flow          target_attack_stability_flow
#   ble_recon_spam_flow          ble_badble_recovery_flow
#   rf_spectrum_scan_flow        rf_jammer_stability_flow
```

Custom declarative flows via `flow_json`:

```
wxf (BruceSerialBridge) > set flow_json [{"command":"wifi scan","expect":"#","wait_ms":1200},{"command":"nav back","repeat":2,"expect":"#"}]
wxf (BruceSerialBridge) > run
```

---

## Documentation & Wiki

Full syntax reference, module usage samples, and configuration guides:

- **[docs/wiki/en-US/](docs/wiki/en-US/)** — English (default)
- **[docs/wiki/pt-BR/](docs/wiki/pt-BR/)** — Português
- **[docs/FULL_CATALOG.md](docs/FULL_CATALOG.md)** — complete module catalog
- **[docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md)** — device coverage matrix

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CONTRIBUTORS.md](CONTRIBUTORS.md).  
Please read our [Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md).

---

## License

BSD 3-Clause License — see [LICENSE](LICENSE) for details.

**WirelessXPL-Forge is intended for authorised security research and education only.**  
Use against systems you do not own or have explicit written permission to test is illegal.

---

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)  
**Lineage:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → WirelessXPL-Forge
