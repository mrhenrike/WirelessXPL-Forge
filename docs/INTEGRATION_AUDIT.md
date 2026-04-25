# WirelessXPL-Forge — Integration Audit

**Author:** André Henrique (@mrhenrike) | União Geek

Audit of all wireless-relevant code across `submodules/IoT/`, `submodules/IoT/wireless-research/`, and `dev/` against the WirelessXPL-Forge module catalog. Lists every item that can be incorporated and the strategy for each.

---

## Current WirelessXPL-Forge module catalog (93 Python modules)

| Area | Count | Coverage |
|------|-------|----------|
| `generic/wifi_lab/` | 44 | Deauth, evil twin, WPA3, KRACK, FragAttacks, KR00K, WPS, wardriving, AWDL, BLE phishing, captive portal, MITM, sniffer, IDS, ML anomaly |
| `generic/external/` | 21 | Bridges: airgeddon, wifiphisher, wifipumpkin3, wifite2, eaphammer, fluxion, bettercap, mdk4, hcxtools, reaver, oneshot, rogue, router-firmware, ot-protocol, social-recon, bruce ESP32 |
| `generic/pcap/` | 13 | PCAP: handshake, PMKID, EAPOL, WEP, TKIP, WPE, Dragonblood, BLE survey, credential sniffer, SQL workspace |
| `generic/bluetooth/` | 10 | BLE scan/enumerate/write, btlejack, crackle, HID injection, baseband, session, BlueBorne |
| `generic/cve/` | 3 | CVE lookup, Zigbee attack (basic), init |
| `generic/wordlist/` | 2 | Wordlist generator |

---

## Audit — what exists vs. what can be added

### 1. `submodules/IoT/wireless-research/` — 27 repos

| Repo | Language | Status | Incorporation strategy | New module |
|------|----------|--------|------------------------|------------|
| `AirBully` | Bash + Python | **GAP** | Port deauth/downgrade logic to native Python | `wpa3_airbully_native.py` |
| `Deauth_Attack` | Python (Scapy) | Already covered (wifi_lab) | Merge unique patterns into `deauth_multimode.py` | merge |
| `Deauther-VRONIN24` | Python (Scapy) | Already covered | Merge channel-hop patterns | merge |
| `DragonShift` | Python | Already covered in `wpa3_attack_suite.py` | Done | - |
| `wifi-deauth` | Python | Already covered | - | - |
| `WiFi-Deauth-Attack-zyphcore` | Python | Already covered | - | - |
| `MoMo` | Python | Partially in `momo_integrated_attack.py` | Extend with MoMo-specific modules | extend |
| `Politician` | C++ / Arduino + Python | **GAP** | Port PMKID/CSA/EAP harvest Python examples; C++ firmware stays on device | `politician_pmkid_csa.py` |
| `Wifi_Security_Analyzer` | Python | **GAP** | Port scanner logic natively | `wifi_security_analyzer.py` |
| `WPA3-Attack-Nuseo1` | Python | Partially in `wpa3_attack_suite.py` | Merge SAE DoS variants | merge/extend |
| `WPA3-Attacks-IDS` | Python (PoCs) + C | **GAP** | Port Python PoC attack scripts; IDS logic | `wpa3_attacks_ids_native.py` |
| `WPA3-SAE-Simulator` | Python | **GAP** | Port SAE state machine to native module | `wpa3_sae_simulator_native.py` |
| `WPA3-Transition-mode-Downgrade-attack` | Python | Already covered in `wpa3_attack_suite.py` | Done | - |
| `WPA3-Attack-Detection-ML` | Python | **GAP** | Port ML detection for downgrade detection | merge into `pcap_rf_anomaly_ml.py` |
| `WPA3-Downgrade-Detection-ML` | (empty clone) | N/A | Skip | - |
| `dragon-drain-wpa3-airgeddon-plugin` | Python + Shell | Already in `wpa3_attack_suite.py` | Done | - |
| `wpa3-sae-flood-anomaly-detection` | Python + notebooks | **GAP** | Port SAE commit flood native Scapy | `wpa3_sae_flood_native.py` |
| `WPA3-SAE-Simulator` | Python | **GAP** | Port SAE simulator | `wpa3_sae_simulator_native.py` |
| `wpa3_sec` | Python + notebooks | Already referenced | Merge timing heuristics | merge |
| `ioc12-wifi-impersonation` | Jupyter + MD | Concepts only | Reference in PCAP module | - |
| `Evil-Twin-Detection-Writeup` | MD only | Docs | - | - |
| `Secure-Wi-Fi-Wireless-Solution` | MD only | Docs | - | - |
| `Wi-Fi-Security` | MD only | Docs | - | - |
| `Wireless-Network-Security-Project-VAPT` | MD only | Docs | - | - |
| `Wireless-Network-Security-Project-VAPT` | MD only | Lab doc | - | - |
| `WirelessPen` | Python | **GAP** | Port Wi-Fi pentest framework recon/enum | `wirelesspen_recon.py` |
| `wifi-attaking-tool-easy-to-use` | Python | Already covered | Merge MxAI scan patterns | merge |

### 2. Direct `submodules/IoT/` repos — wireless tools

| Repo | Language | Already bridged? | Gap? | New module |
|------|----------|-----------------|------|------------|
| **wifiphisher** | Python | YES (`wifiphisher_bridge.py`) | - | - |
| **eaphammer** | Python | YES (`eaphammer_bridge.py`) | - | - |
| **airgeddon** | Bash | YES (`airgeddon_bridge.py`) | - | - |
| **wifite2** | Python | YES (`wifite2_bridge.py`) | - | - |
| **bettercap** | Go | YES (`bettercap_bridge.py`) | - | - |
| **fluxion** | Bash | YES (`fluxion_bridge.py`) | - | - |
| **mdk4** | C | YES (`mdk4_bridge.py` in external + wifi_lab) | - | - |
| **reaver** | C | YES (`reaver_bridge.py` — includes wash + pixiewps) | - | - |
| **hcxtools** | C | YES (`hcx_toolchain_bridge.py`) | Separate live capture | `hcxdumptool_live_bridge.py` |
| **oneshot** | Python | YES (`oneshot_bridge.py`) | - | - |
| **wifipumpkin3** | Python | YES (`wifipumpkin3_bridge.py`) | - | - |
| **roguehostapd** | C | Partial via `rogue_bridge.py` | Native EAP use | `hostapd_wpe_bridge.py` |
| **hostapd-eaphammer** | C | Via eaphammer | - | - |
| **btlejack** | Python | YES (`ble_btlejack.py`) | - | - |
| **crackle** | Python | YES (`ble_crackle.py`) | - | - |
| **blueborne** | Python | YES (`blueborne_attack.py`) | - | - |
| **bluffs** | Python | **GAP** | Add BLUFFS (BLE session downgrade) | `ble_bluffs_native.py` |
| **sweyntooth** | Python | **GAP** | SweynTooth BLE stack vulns | `ble_sweyntooth_bridge.py` |
| **braktooth** | C/ESP-IDF | **GAP** | BrAcketooth BT classic | `braktooth_bridge.py` |
| **knob-attack** | Python (PoC) | **GAP** | KNOB BT key negotiation attack | `knob_attack_bridge.py` |
| **bias-attack** | Python/C | **GAP** | BIAS BT impersonation | `bias_attack_bridge.py` |
| **killerbee** | Python | **GAP (zigbee_attack.py is minimal)** | Full Zigbee/802.15.4 | `killerbee_zigbee_bridge.py` |
| **dragonblood** | Python | Already in `pcap_dragonblood.py` + `wpa3_attack_suite.py` | - | - |
| **krackattacks** | C + Python | Already in `krack_attack.py` | - | - |
| **fragattacks** | C + Python | Already in `fragattacks.py` | - | - |
| **r00kie-kr00kie** | Python | Already in `kr00k_attack.py` | - | - |
| **waidps** | Python | Partially in `wireless_ids.py` | Extend IDS | extend |
| **WiFiBroot** | Python | Partial | Extend scanner | extend |
| **pwnagotchi** | Python | **GAP** | AI-based WPA handshake sniffer | `pwnagotchi_bridge.py` |
| **SniffAir** | Python | **GAP** | Passive Wi-Fi recon + Auto EAP | `sniffair_passive_recon.py` |
| **ghost-phisher** | Python | **GAP** | Phishing AP framework | `ghost_phisher_bridge.py` |
| **hashcatch** | C | **GAP** | Passive WPA handshake harvest | `hashcatch_bridge.py` |
| **wirespy** | Bash | **GAP** | Wi-Fi monitoring (Bash subprocess) | `wirespy_bridge.py` |
| **NetSet** | Bash | **GAP** | Network setup automation | `netset_bridge.py` |
| **rogue** | Python/Bash | Partial via `rogue_bridge.py` | - | - |
| **Responder** | Python | Already in `responder_wifi.py` | - | - |
| **ssid-confusion-hostap** | C | Already in `ssid_confusion.py` | - | - |
| **opendrop / owl** | Python/Go | Already in `awdl_attack.py` | - | - |
| **ESP32Marauder** | C++ | Via `bruce_esp32_lab_notes.py` | - | - |
| **BruceDevices-firmware** | C++ | Via `bruce_serial_bridge.py` | - | - |
| **IoT-PT-v1** | Python | **GAP** | IoT pentest methodology | `iot_pt_methodology.py` |
| **pi-pwnbox-rogueap** | Python/Bash | **GAP** | Pi Pwnbox rogue AP workflow | `pi_pwnbox_bridge.py` |
| **fluxion-sage** | Bash | **GAP** | Fluxion SAGE variant | extend `fluxion_bridge.py` |
| **Broadpwn** | C/research | **GAP** | BCM Wi-Fi chip exploitation | `broadpwn_bridge.py` |
| **bias-attack** | Python/C | **GAP** | BT BIAS impersonation | `bias_attack_bridge.py` |
| **PEGASUS-PRO** | Mixed | **GAP (assess)** | Depends on scope | assess |
| **nullkia** | Unknown | **GAP (assess)** | Depends on scope | assess |
| **hi_my_name_is_keyboard** | Python/Arduino | Partial via `bt_hid_injection.py` | - | - |
| **hcxdumptool** | C | **GAP** | Live PMKID + handshake capture | `hcxdumptool_live_bridge.py` |
| **hardware_hacking** | Mixed | Assess | Lab hardware references | assess |

---

## Implementation priority matrix

| Priority | Module | Wireless vector | Notes |
|----------|--------|-----------------|-------|
| **P1 - High** | `hcxdumptool_live_bridge.py` | PMKID live capture | Heavily used in WPA2/WPA3 audits |
| **P1 - High** | `bully_bridge.py` | WPS brute (C) | Alternative to reaver, often faster |
| **P1 - High** | `hostapd_wpe_bridge.py` | WPE / EAP harvest | Enterprise Wi-Fi capture |
| **P1 - High** | `killerbee_zigbee_bridge.py` | Zigbee / 802.15.4 | Python lib — native integration |
| **P1 - High** | `sniffair_passive_recon.py` | Passive recon + EAP | Python — native integration |
| **P1 - High** | `wpa3_sae_flood_native.py` | WPA3 SAE DoS | Native Scapy |
| **P2 - Medium** | `knob_attack_bridge.py` | BT KNOB | Python PoC |
| **P2 - Medium** | `bias_attack_bridge.py` | BT BIAS | Python/C |
| **P2 - Medium** | `ble_bluffs_native.py` | BLE session downgrade | Python |
| **P2 - Medium** | `ble_sweyntooth_bridge.py` | BLE stack vulns | Python |
| **P2 - Medium** | `braktooth_bridge.py` | BT classic | C/ESP-IDF |
| **P2 - Medium** | `pwnagotchi_bridge.py` | AI WPA handshake | Python |
| **P2 - Medium** | `hashcatch_bridge.py` | Passive WPA | C binary |
| **P2 - Medium** | `ghost_phisher_bridge.py` | Phishing AP | Python |
| **P2 - Medium** | `wifi_security_analyzer.py` | Wi-Fi recon | Python native port |
| **P3 - Low** | `wirespy_bridge.py` | Wi-Fi monitoring | Bash subprocess |
| **P3 - Low** | `netset_bridge.py` | Network setup | Bash subprocess |
| **P3 - Low** | `pi_pwnbox_bridge.py` | Rogue AP workflow | Python/Bash |
| **P3 - Low** | `broadpwn_bridge.py` | BCM chip exploit | Research/C |
| **P3 - Low** | `iot_pt_methodology.py` | IoT pentest methodology | Python guide module |

---

## Language to strategy mapping

| Language | Strategy | Notes |
|----------|----------|-------|
| **Python** | Import natively OR subprocess | Prefer native import if library is well-structured; subprocess if GPL or huge deps |
| **C / C++** | Subprocess bridge | Build and invoke binary; parse stdout; pass all args via CLI |
| **Go** | Subprocess bridge | Same as C; Go binaries are self-contained |
| **Bash / Shell** | Subprocess bridge | `subprocess.run(["bash", script_path, ...])` with arg sanitization |
| **Arduino / ESP-IDF** | Firmware reference bridge | Document flash procedure; serial bridge for interaction |
| **Jupyter notebooks** | Extract Python cells, port to module | Notebooks are not executable in WXF context |

---

*Generated: 2026-04-24 — André Henrique (@mrhenrike) | União Geek*
