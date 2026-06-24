# About WirelessXPL-Forge

**WirelessXPL-Forge (WXF)** is a modular wireless security research framework built for authorised penetration testing, security research, and education in wireless networks and IoT/embedded devices.

---

## Project Identity

| Attribute | Value |
|-----------|-------|
| **Name** | WirelessXPL-Forge |
| **Short name** | WXF |
| **Version** | 2.0.3 |
| **License** | BSD-3-Clause |
| **Python** | 3.8 – 3.13 |
| **Platform** | Linux (preferred), macOS, WSL2 |
| **Repository** | https://github.com/mrhenrike/WirelessXPL-Forge |
| **Wiki** | https://github.com/mrhenrike/WirelessXPL-Forge/wiki |

---

## Taglines

- *"One shell. Every wireless vector."*
- *"From 802.11ax to BLE — authorised research, one module away."*
- *"Wireless security, modular by design."*
- *"WPA, WPA3, BLE, Zigbee, ESP32 — in one framework."*

---

## Origin and Lineage

WXF is a focused fork of [threat9/routersploit](https://github.com/threat9/routersploit), extracted from [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) to specialise exclusively in **wireless protocols**: 802.11, Bluetooth Classic, BLE, Zigbee, RFID, AWDL, and ESP32-based embedded devices.

```
threat9/routersploit
  └─ RouterXPL-Forge (mrhenrike)
       └─ WirelessXPL-Forge (mrhenrike) ← this project
       └─ FirewallXPL-Forge (mrhenrike, private)
```

---

## Design Philosophy

- **Module-first**: every attack, analysis, or bridge is a self-contained Python class following the `BaseExploit` contract (`__info__`, options, `run()`, `check()`)
- **No lock-in**: bridges invoke system tools (`aircrack-ng`, `mdk4`, `hcxdumptool`) as subprocesses — WXF orchestrates, not replaces
- **Upstream-aware**: all incorporated community issues and PRs are tracked in `wirelessxpl/resources/catalogs/upstream_issues_prs.json` and the Bruce upstream map
- **Research-grade**: modules include CVE references, protocol details, and lab notes — not just "run and pray"
- **ESP32 native**: Bruce/Marauder serial flow engine makes handheld wardriving and menu automation first-class citizens

---

## Architecture Overview

```
WirelessXPL-Forge/
├── wirelessxpl/
│   ├── core/           # interpreter, exploit base, CVE DB, exceptions
│   ├── modules/
│   │   ├── generic/
│   │   │   ├── wifi_lab/      # Wi-Fi attack and lab modules (native Python)
│   │   │   ├── bluetooth/     # BT Classic + BLE modules
│   │   │   ├── pcap/          # PCAP analysis pipelines
│   │   │   ├── cve/           # CVE exploit modules (Zigbee, KRACK, SSID Confusion…)
│   │   │   └── external/      # bridges to external tools + Bruce serial engine
│   │   ├── exploits/          # device-specific exploits (inherited lineage)
│   │   ├── scanners/          # network scanners
│   │   └── creds/             # credential modules
│   ├── resources/
│   │   └── catalogs/          # upstream tracking JSONs, CVE catalog, intel maps
│   └── libs/                  # shared utilities
├── tools/                     # developer and CI tooling
├── docs/                      # documentation, wiki, coverage matrix
└── .github/workflows/         # CI/CD (compat-matrix + release + PyPI publish)
```

---

## Coverage Matrix Highlights

| Device/Protocol | Modules |
|-----------------|---------|
| Wi-Fi 802.11 (WPA2/WPA3) | fragattacks, wpa3_attack_suite, handshake_snooper, evil_twin_workflow, auth_flood, beacon_flood, captive_portal_modern_lab, adaptive_harvest, wardriving_deauth_loop, wireless_ids, momo_integrated_attack |
| BLE / Bluetooth Classic | ble_btlejack, ble_crackle, bt_hid_injection, bt_baseband_attack (BrakTooth), bt_session_attack (KNOB/BIAS/BLUFFS), blueborne_attack |
| Zigbee / IEEE 802.15.4 | zigbee_attack (KillerBee) |
| AWDL / AirDrop | awdl_attack (opendrop + owl) |
| ESP32 / Bruce firmware | bruce_serial_bridge (15+ flow profiles), bruce_upstream_tracker |
| PCAP analysis | pcap_handshake_extractor, pcap_eapol_survey, pcap_pmkid_extractor, pcap_dragonblood, pcap_sql_workspace |
| MITM / Bridging | mitm_wifi_bridge (ghost_combo), rogue_bridge, wifipumpkin3_bridge, eaphammer_bridge, wifiphisher_bridge |
| External tool bridges | airgeddon_bridge, mdk4_bridge, aircrack_bridge, hcxtools_bridge |

---

## Maintainer

**André Henrique** ([@mrhenrike](https://github.com/mrhenrike))  
[União Geek](https://github.com/Uniao-Geek) — https://github.com/Uniao-Geek  
**Support:** [suporte@uniaogeek.com.br](mailto:suporte@uniaogeek.com.br)

---

## Reporting Vulnerabilities

See [SECURITY.md](../../SECURITY.md) for responsible disclosure guidelines.

---

## Disclaimer

WirelessXPL-Forge is designed for **authorised security research and education only**.  
Use against systems you do not own or have explicit written permission to test is illegal and unethical.  
The authors assume no liability for misuse of this software.
