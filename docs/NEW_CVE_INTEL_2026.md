# WirelessXPL-Forge: New CVE Intel 2026

> Generated: 2026-09-13 | Scope: Wireless CVEs 2025-2026 not previously covered  
> Covers: WiFi, Bluetooth/BLE, IoT protocols, SubGHz/RF, Drones/UAV, Cellular/5G  
> Status legend: T1=Tier-1 (implement now), T2=Tier-2, T3=Tier-3 (SDR/prereq-heavy)

---

## Methodology

All CVE candidates were cross-checked against:
- `wirelessxpl/resources/catalogs/cve_extended_catalog.json` (167 prior entries)
- All `.py` and `.json` files under `wirelessxpl/` (10 778 unique CVE references found)

Confirmed new (no prior module or catalog entry): **17 CVEs**. Already covered: CVE-2025-27558 (catalog only, no module), CVE-2026-1743 (full module exists).

---

## Domain: WiFi 802.11

### CVE-2025-38512 - Linux kernel A-MSDU mesh mitigation
| Field | Value |
|---|---|
| CVE | CVE-2025-38512 |
| Domain | WiFi / 802.11 mesh |
| Product | Linux kernel mac80211 (net/wireless/util.c) |
| Affected versions | < 6.1.146 / < 6.6.99 / < 6.12.39 / < 6.15.7 / < 6.16 |
| CVSS | N/A (mitigation patch) |
| Technique | Variant of CVE-2020-24588 A-MSDU spoofing bypass in mesh networks; adversary forces A-MSDU frame injection into mesh links where the 802.11 standard ad-hoc fix was not applied |
| Exploitability | Adjacent network, no auth, active injection of crafted frames |
| HW required | Monitor-mode WiFi adapter capable of injection in 802.11s mesh |
| Source repos | `vanhoefm/fragattacks`, WiSec-2025 paper (Vanhoef) |
| Reuse strategy | Informational catalog entry; companion to CVE-2025-27558 mesh scanner |
| Tier | T1 - companion note (module for CVE-2025-27558 covers the attack) |
| References | https://lists.openwall.net/linux-cve-announce/2025/08/16/21 |

### CVE-2025-27558 - FragAttacks A-MSDU mesh bypass (NEW MODULE)
| Field | Value |
|---|---|
| CVE | CVE-2025-27558 |
| Domain | WiFi / 802.11 mesh |
| Product | 802.11 mesh AP/clients (firmware, not yet fully patched) |
| CVSS | ~7.5 High |
| Technique | Bypass of 802.11 FragAttacks A-MSDU ad-hoc mitigation for mesh networks; adversary crafts MSDU that is misidentified as A-MSDU, enabling arbitrary packet injection |
| Exploitability | Adjacent mesh network, no auth, requires 802.11s-capable injection interface |
| HW required | WiFi adapter in monitor+inject mode with 802.11s mesh support |
| Source repos | `vanhoefm/fragattacks` (WiSec-2025 branch), `fragattacks-survey-public` |
| Reuse strategy | Port injection logic to Scapy `Dot11MeshControl` + `AMS_DU` layer; extend existing `fragattacks_scanner.py` to detect mesh-specific flag |
| Tier | T1 |
| Module path | `wirelessxpl/modules/generic/wifi/fragattacks/fragattacks_amsdu_mesh_cve_2025_27558.py` |

---

## Domain: Bluetooth / BLE

### CVE-2025-36911 - WhisperPair: Google Fast Pair pairing-mode bypass
| Field | Value |
|---|---|
| CVE | CVE-2025-36911 |
| Domain | Bluetooth BLE (Google Fast Pair) |
| Product | Bluetooth audio accessories implementing GFPS (headphones, earbuds, speakers) |
| Affected vendors | Google, Jabra, Samsung, JBL, Sony, Bose, and others implementing GFPS |
| CVSS | Critical |
| Technique | Accessor fails to enforce pairing-mode check; attacker sends raw KBP (Key-Based Pairing) write to UUID 0xFE2C/fe2c1234... without the device in pairing mode; device responds and completes bonding. Follow-up: HFP/A2DP audio hijack, Account Key injection (Find Hub tracking), CTKD cross-transport BR/EDR bonding |
| Exploitability | BLE range (~14 m), no auth, no user interaction; completes in seconds |
| HW required | Any BLE 4.0+ adapter (hci0); standard Linux Bluetooth stack |
| Source repos | `pira12/WhisperPair-PoC` (Python CLI + `l2flood.c`), `ap425q/whisper-pair` (scanner) |
| Reuse strategy | Port scanner (bleak, 0xFE2C service UUID scan) and KBP injection (raw GATT write) to native Python; `l2flood.c` referenced as optional external arsenal binary |
| Tier | T1 |
| Module path | `wirelessxpl/modules/generic/bluetooth/whisperpair_fast_pair_cve_2025_36911.py` |
| References | https://mallory.ai/vulnerabilities/CVE-2025-36911, https://whisperpair.eu |

### bluesploit framework (new reusable corpus)
| Field | Value |
|---|---|
| Repo | `V33RU/bluesploit` |
| Description | Bluetooth framework with 160 modules, 40+ CVE PoCs (2010-2026), Metasploit-like REPL; BR/EDR + BLE + Mesh; engagement SQLite store; supports Ubertooth, nRF52840, BTLEJack, HackRF |
| Reuse strategy | Mine individual exploit modules as reference for implementing new WXF bluetooth attacks; add to `external_framework_clones.json` |
| Priority | Ongoing corpus mining |

---

## Domain: IoT Protocols / Zigbee / LoRaWAN

### CVE-2025-8414 - Zigbee EZSP Green Power host buffer overflow (Silicon Labs)
| Field | Value |
|---|---|
| CVE | CVE-2025-8414 |
| Domain | Zigbee / IEEE 802.15.4 |
| Product | Silicon Labs Simplicity SDK (< 2025.6.0), Gecko SDK (< 4.4.6); EZSP host applications |
| CVSS | ~7.5 (AV:A/AC:L) |
| Technique | Improper input validation in EZSP host-side parsing routine; Green Power frames from a Zigbee PAN can overflow a fixed-size stack buffer via the serial interface to the co-processor; requires valid Zigbee network key to reach the host parser |
| Exploitability | Adjacent Zigbee network, network key required (shared among all joined devices), no user interaction |
| HW required | Zigbee sniffer (KillerBee/CC2531/HackRF), knowledge of network key |
| Source repos | No public PoC; Silicon Labs community advisory |
| Reuse strategy | Scanner/fingerprinting module: detect EZSP-based hosts (hub detection via mDNS/Zigbee scan), report unpatched SDK versions; informational + targeted frame probe |
| Tier | T2 |
| Module path | `wirelessxpl/modules/generic/iot_proto/zigbee/zigbee_ezsp_green_power_bof_cve_2025_8414.py` |
| References | https://nvd.nist.gov/vuln/detail/CVE-2025-8414, https://community.silabs.com/068Vm00000WJZED |

### CVE-2026-12363 - LoRaWAN Zephyr frag_transport OOB write (GHSA-fvm7-7whg-8gj6)
| Field | Value |
|---|---|
| CVE | CVE-2026-12363 |
| Advisory | GHSA-fvm7-7whg-8gj6 |
| Domain | LoRaWAN / IoT FUOTA |
| Product | Zephyr RTOS 3.7.0 to 4.4.x; `subsys/lorawan/services/frag_transport.c` |
| Technique | `frag_counter` value of 0 from a crafted DATA_FRAGMENT downlink underflows `frag_counter - 1` in `FragDecoderProcess()`, writing a zero uint16_t out-of-bounds into `MatrixM2B` recovery state (CWE-787). Impacts FUOTA sessions. Requires valid LoRaWAN MAC session keys or compromised network server |
| Exploitability | Downlink-only; requires active fragmentation session and MAC session key; DoS of firmware update session |
| HW required | LoRaWAN gateway + SDR or compromised network server |
| Source repos | `zephyrproject-rtos/zephyr` commit `452c704a` (fix), advisory GHSA-fvm7-7whg-8gj6 |
| Reuse strategy | Native Python module: craft DATA_FRAGMENT frame with frag_index_n=0, simulate downlink injection against a local Zephyr FUOTA session for PoC demonstration |
| Tier | T3 |
| Module path | `wirelessxpl/modules/generic/iot_proto/lorawan/lorawan_frag_transport_oob_cve_2026_12363.py` |
| References | https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-fvm7-7whg-8gj6 |

---

## Domain: SubGHz / RF / Automotive

### CVE-2026-49319 - Suzuki Swift 2024 RKES rollback-replay (Alps Alpine R53R0)
| Field | Value |
|---|---|
| CVE | CVE-2026-49319 |
| Domain | SubGHz / RF / Automotive RKE |
| Product | Alps Alpine R53R0 RKES module (FCC ID CWTR53R0); confirmed on 2024 Suzuki Swift |
| CVSS | 6.5 Medium (AV:A/AC:L) |
| Technique | Rolling-code module fails to invalidate captured codes after use; recording two consecutive lock/unlock transmissions allows replay of the pair later to lock/unlock the vehicle. Attack: jam+capture code A, jam+capture code B, replay A (car opens), B remains valid as spare |
| Exploitability | 433 MHz RF range, no auth; passive capture phase is undetectable |
| HW required | SDR (HackRF One or RTL-SDR), CC1101 module, or Flipper Zero |
| Source repos | `G4MEOVER18/RollJam` (Flipper Zero RollJam PoC), `G4MEOVER18/RollLab`, `G4MEOVER18/ProtoPirate` (27+ keyfob protocol decoder/encoder), `wincr4ck/rf-keyfob-research` |
| Reuse strategy | Extend existing `static_code_replay.py` and `keeloq_replay.py`; port RollJam jam+capture timing from ProtoPirate; add `protocol=ALPS_R53R0` to `ook_encoder.py` |
| Tier | T2 |
| Module path | `wirelessxpl/modules/generic/subghz/rkes_rollback_replay_cve_2026_49319.py` |
| References | https://github.com/advisories/GHSA-2qp5-r5hx-q27p, https://www.asrg.io/security-advisories/cve-2026-49319-suzuki-swift-2024-rkes-rollback-replay |

---

## Domain: Drones / UAV

### CVE-2026-1579 - PX4 Autopilot MAVLink missing authentication (SERIAL_CONTROL shell)
| Field | Value |
|---|---|
| CVE | CVE-2026-1579 |
| Domain | Drones / UAV / MAVLink |
| Product | PX4 Autopilot 1.16.0 and below |
| CVSS | 9.8 Critical |
| Technique | MAVLink 2.0 signing disabled by default; any entity with MAVLink network access can send unsigned SERIAL_CONTROL messages, which provide interactive shell access to the flight controller. No authentication or encryption |
| Exploitability | Adjacent or remote (over WiFi/UDP), no auth, no signing; provides shell RCE on autopilot |
| HW required | Network access to drone on UDP 14550 |
| Source repos | PX4 docs on signing, CISA advisory ICSA-26-090-02 |
| Reuse strategy | Extend existing `mavlink_force_disarm.py` pattern; add SERIAL_CONTROL message type (msg_id=126), build native frame, send shell commands over UDP |
| Tier | T1 |
| Module path | `wirelessxpl/modules/generic/drones/mavlink/mavlink_serial_control_shell_cve_2026_1579.py` |
| References | https://nvd.nist.gov/vuln/detail/CVE-2026-1579, https://www.cisa.gov/news-events/ics-advisories/icsa-26-090-02 |

### CVE-2026-32743 - PX4 MavlinkLogHandler stack-based buffer overflow
| Field | Value |
|---|---|
| CVE | CVE-2026-32743 |
| Domain | Drones / UAV / MAVLink |
| Product | PX4 Autopilot <= 1.17.0-rc2 |
| CVSS | 6.5 Medium |
| Technique | `MavlinkLogHandler::state_listing()` uses `sscanf` with no width specifier to parse paths from the log list file into a 60-byte `LogEntry.filepath` buffer; attacker with MAVLink link access creates deeply nested directories via MAVLink FTP, then requests log list - crashes MAVLink task (DoS: telemetry/command loss) |
| Exploitability | MAVLink access (UDP 14550), no auth if signing disabled; step 1: MAVLink FTP mkdir deep path; step 2: request log list |
| HW required | Network access to drone on UDP 14550 |
| Source repos | PX4-Autopilot commit `616b25a280e` (fix), Dronecode CVE feed |
| Reuse strategy | Native Python: build MAVLink FTP MKDIR frames to create deep path, then send LOG_REQUEST_LIST; uses existing MAVLink v1 CRC implementation from `mavlink_force_disarm.py` |
| Tier | T2 |
| Module path | `wirelessxpl/modules/generic/drones/px4/px4_log_stack_overflow_cve_2026_32743.py` |
| References | https://feedly.com/cve/vendors/dronecode |

### CVE-2026-77812 - DJI BLE DUML cleartext Wi-Fi credential exposure
| Field | Value |
|---|---|
| CVE | CVE-2026-77812 |
| Domain | Drones / DJI / BLE |
| Product | DJI Neo, Neo 2, Flip, Air 3/3S, Avata 2/360, Mavic 3/Classic/Pro/4 Pro, Mini 2/3/4/5 Pro (see NVD for firmware thresholds) |
| Technique | DJI Fly app exchanges DUML messages over BLE including Wi-Fi PSK, SSID, and session UUID in cleartext; fully passive BLE sniff during one normal connection permanently captures credentials (they do not rotate) |
| Exploitability | Passive BLE sniff, no connection needed, ~10 m range, fully undetectable |
| HW required | BLE sniffer (nRF52840, Wireshark/BTLE, or hci0 monitor) |
| Source repos | CVE record at cve.org |
| Reuse strategy | Native Python with bleak in passive scan + HCI monitor mode; parse DUML packet structure to extract PSK/SSID/UUID; extend `dji_quicktransfer_exfil_cve_2023_6951.py` pattern |
| Tier | T1 |
| Module path | `wirelessxpl/modules/generic/drones/dji/dji_ble_duml_cred_sniff_cve_2026_77812.py` |
| References | https://www.cve.org/CVERecord?id=CVE-2026-77812 |

### CVE-2026-78306 - DJI Bluetooth DUML unauthenticated command execution
| Field | Value |
|---|---|
| CVE | CVE-2026-78306 |
| Domain | Drones / DJI / Bluetooth |
| Product | Same DJI fleet as CVE-2026-77812 |
| CVSS | 8.5 High |
| Technique | DJI drones expose unauthenticated DUML command interface over BLE; attacker can modify Wi-Fi SSID/PSK/MAC/country/channel, overwrite PSK with known value, join internal Wi-Fi, issue flight commands, or disable/restart wireless interfaces causing DoS during flight |
| Exploitability | BLE range, no auth, no user interaction; can disable operator's live video+control link |
| HW required | BLE 4.0+ adapter (hci0) |
| Source repos | NVD CVE-2026-78306 (notcve.org) |
| Reuse strategy | Implement DUML frame builder (native Python struct), connect via bleak, send command frames to BT GATT interface; extend CVE-2026-77812 module connection logic |
| Tier | T1 |
| Module path | `wirelessxpl/modules/generic/drones/dji/dji_bt_duml_unauth_cve_2026_78306.py` |
| References | https://notcve.org/cve/CVE-2026-78306 |

---

## Domain: Cellular / 5G

### 5Ghoul family - 5G NR DoS attacks (Qualcomm + MediaTek basebands)
| Field | Value |
|---|---|
| CVEs | CVE-2023-33042, CVE-2023-33043, CVE-2023-33044, CVE-2023-32841 to CVE-2023-32846, CVE-2023-20702, CVE-2024-20003, CVE-2024-20004 |
| Domain | Cellular / 5G NR |
| Product | Qualcomm and MediaTek 5G baseband modems (smartphones, CPE routers, USB modems) |
| Technique | Over-the-air 5G NR protocol implementation flaws in RRC/NAS layers; fuzzer identifies crash-inducing message variants (Invalid RRC Setup, empty NAS, RRC Reconfiguration crash, downgrade); pre-authentication, no SIM info needed |
| Exploitability | 5G NR radio range, no auth; rogue base station (Open Air Interface / srsRAN) + USRP B210 required |
| HW required | USRP B210 or equivalent SDR, srsRAN/OAI, SIM card (Sysmocom programmable) |
| Source repos | `asset-group/5ghoul-5g-nr-attacks` (PoC + fuzzer), `asset-group/Sni5Gect-5GNR-sniffing-and-exploitation` |
| Reuse strategy | Orchestrator module: launch 5Ghoul Python exploit scripts with subprocess (ACCEPTED DEP - SDR toolchain, not prohibited bridge); document USRP prereq in arsenal; add CVE catalog entries |
| Tier | T3 |
| Module path | `wirelessxpl/modules/generic/cellular/fiveghoul_5gnr_dos.py` |
| References | https://asset-group.github.io/disclosures/5ghoul/ |

### LLFuzz baseband CVEs (Qualcomm/MediaTek/Samsung/Google)
| Field | Value |
|---|---|
| CVEs | CVE-2025-21477, CVE-2025-20659, CVE-2025-26780, CVE-2025-26781, CVE-2025-26782, CVE-2024-23385, CVE-2024-20076, CVE-2024-20077 |
| Domain | Cellular / LTE+5G baseband lower layers |
| Product | Qualcomm (90+ chipsets), MediaTek (80+ chipsets), Samsung Exynos 2400/Modem 5400, Google Tensor G4 |
| Technique | LLFuzz OTA fuzzer targets MAC/RLC/PDCP layers (no MAC-I protection); memory corruption bugs (stack/heap overflow, OOB write) in stateful lower-layer protocol implementations |
| Exploitability | OTA LTE/5G range, pre-auth, requires srsRAN + USRP B210 rogue base station |
| HW required | USRP B210 or equivalent SDR + srsRAN, programmable SIM |
| Source repos | `SysSec-KAIST/LLFuzz` |
| Reuse strategy | Scanner module: identify baseband vendor/version from device firmware fingerprint (AT commands via USB modem); catalog CVE coverage; orchestrate LLFuzz if binary prereqs present |
| Tier | T3 |
| Module path | `wirelessxpl/modules/generic/cellular/llfuzz_baseband_cve_scanner.py` |
| References | https://kaist-hacking.github.io/pubs/2025/hoang:llfuzz-slides.pdf, https://github.com/SysSec-KAIST/LLFuzz |

### Sni5Gect - 5G NR sniffing and exploitation framework
| Field | Value |
|---|---|
| Repo | `asset-group/Sni5Gect-5GNR-sniffing-and-exploitation` |
| Domain | Cellular / 5G NR |
| Technique | Sniff unencrypted 5G NR messages, inject custom packets; covers downgrade (auth replay), auth bypass (Registration Accept injection), modem crash (5Ghoul attacks), fingerprinting |
| Reuse strategy | Orchestrator module wrapping Sni5Gect Python scripts; add as external tool intel source |
| Tier | T3 |
| Module path | `wirelessxpl/modules/generic/cellular/sni5gect_5gnr_sniff_inject.py` |

---

## Reusable Repos Summary

| Repo | Domain | Language | Reuse type |
|---|---|---|---|
| `vanhoefm/fragattacks` | WiFi | Python/C | Port mesh module logic |
| `pira12/WhisperPair-PoC` | BLE | Python + C | Port KBP injection to bleak |
| `ap425q/whisper-pair` | BLE | Python | Port scanner logic |
| `V33RU/bluesploit` | BT/BLE | Python | Mine 160 modules for new attack refs |
| `G4MEOVER18/RollJam` | SubGHz | Flipper/C | Port jam+capture timing logic |
| `G4MEOVER18/ProtoPirate` | SubGHz | Flipper/C | Port 27+ keyfob protocol decoders |
| `wincr4ck/rf-keyfob-research` | SubGHz | Python | Port OOK analysis + chip classification |
| `ByteMe1001/DJI-CatNect` | Drones | C | Inform Python DUML frame builder |
| `asset-group/5ghoul-5g-nr-attacks` | Cellular | Python/C++ | Orchestrate exploit scripts |
| `asset-group/Sni5Gect` | Cellular | Python | Orchestrate sniff/inject modules |
| `SysSec-KAIST/LLFuzz` | Cellular | Python | Baseband CVE scanner |

---

## Module Implementation Queue

| Priority | Module file | CVE(s) | Status |
|---|---|---|---|
| T1 | `wifi/fragattacks/fragattacks_amsdu_mesh_cve_2025_27558.py` | CVE-2025-27558 | implement |
| T1 | `bluetooth/whisperpair_fast_pair_cve_2025_36911.py` | CVE-2025-36911 | implement |
| T1 | `drones/mavlink/mavlink_serial_control_shell_cve_2026_1579.py` | CVE-2026-1579 | implement |
| T1 | `drones/dji/dji_ble_duml_cred_sniff_cve_2026_77812.py` | CVE-2026-77812 | implement |
| T1 | `drones/dji/dji_bt_duml_unauth_cve_2026_78306.py` | CVE-2026-78306 | implement |
| T2 | `subghz/rkes_rollback_replay_cve_2026_49319.py` | CVE-2026-49319 | implement |
| T2 | `drones/px4/px4_log_stack_overflow_cve_2026_32743.py` | CVE-2026-32743 | implement |
| T2 | `iot_proto/zigbee/zigbee_ezsp_green_power_bof_cve_2025_8414.py` | CVE-2025-8414 | implement |
| T3 | `cellular/fiveghoul_5gnr_dos.py` | 5Ghoul family | implement |
| T3 | `cellular/llfuzz_baseband_cve_scanner.py` | LLFuzz CVEs | implement |
| T3 | `cellular/sni5gect_5gnr_sniff_inject.py` | Sni5Gect | implement |
| T3 | `iot_proto/lorawan/lorawan_frag_transport_oob_cve_2026_12363.py` | CVE-2026-12363 | implement |
