# wirelessxpl-Forge — Full Module Catalog

> Generated: 2026-04-08T19:57:15-03:00
> Author: Andre Henrique (@mrhenrike) | Uniao Geek

## Summary

| Category | Modules | Vendor / group buckets |
|---|---:|---:|
| Exploits | 0 | 0 |
| Credential Modules | 0 | 0 |
| Scanners | 0 | 0 |
| Generic Modules | 88 | 6 |
| Encoders | 0 | 0 |
| Payloads | 0 | 0 |
| **Total Modules** | **88** | — |
| Distinct CVEs | 29 | — |

## Program footprint

Approximate on-disk size (file bytes only; binary prefixes). Walk skips caches such as ``__pycache__`` and ``.git``.

| Metric | Value |
|---|---|
| Repository root | `WirelessXPL-Forge` |
| Total file bytes | 35.91 MiB |
| Files (repo walk) | 496 |
| Files under ``wirelessxpl/`` | 272 |

### Largest top-level paths (repository)

| Path | Size | Share of total |
|---|---:|---:|
| `wirelessxpl` | 31.28 MiB | 87.1% |
| `docs` | 4.32 MiB | 12.0% |
| `tools` | 254.42 KiB | 0.7% |
| `(repo root files)` | 47.54 KiB | 0.1% |
| `.github` | 9.62 KiB | 0.0% |
| `.travis` | 721 B | 0.0% |

### ``wirelessxpl/`` breakdown (first-level folders)

| Area | Size | Share of total |
|---|---:|---:|
| `resources` | 30.33 MiB | 84.5% |
| `modules` | 669.85 KiB | 1.8% |
| `core` | 263.05 KiB | 0.7% |
| `(wirelessxpl root files)` | 28.32 KiB | 0.1% |
| `libs` | 13.29 KiB | 0.0% |

### ``wirelessxpl/resources/*`` (largest direct children)

| Subfolder | Size | Share of total |
|---|---:|---:|
| `catalogs` | 25.67 MiB | 71.5% |
| `vendors` | 4.44 MiB | 12.4% |
| `phishing_pages` | 144.60 KiB | 0.4% |
| `wordlists` | 41.16 KiB | 0.1% |
| `arsenal` | 29.34 KiB | 0.1% |
| `ssh_keys` | 9.76 KiB | 0.0% |
| `ml` | 1.20 KiB | 0.0% |
| `__init__.py` | 0 B | 0.0% |

### First-party Python files (``.py`` count, excluding ``__pycache__``)

| Tree | Files |
|---|---:|
| `wirelessxpl/core` | 49 |
| `wirelessxpl/modules` | 96 |
| `wirelessxpl/libs` | 5 |
| `tools` | 35 |
| `wxf.py` | 1 |

---

## Exploits (0)

## Credential Modules (0)

## Scanners (0)

## Generic Modules (88)

### bluetooth (10)

1. **BLE Crackle (Legacy Pairing Cracker)**
   - Path: `generic/bluetooth/ble_crackle.py`
   - Pure Python BLE Legacy Pairing cracker. Extracts SMP pairing data from PCAPs, brute-forces the Temporary Key (TK, 0-999999), derives STK and Session Key, decrypts all traffic, and extracts the Long-Te
   - Devices: bluetooth, bluetooth_le

2. **BLE Phishing & Spoof**
   - Path: `generic/bluetooth/ble_phishing.py`
   - BLE-based social engineering: advertisement spam (Apple/Samsung/Google device spoofing), name-based lure for pairing, BLE MITM via btlejuice, iBeacon/Eddystone cloning, and notification spam. Requires
   - Devices: bluetooth

3. **BT Baseband Attacks (BrakTooth + SweynTooth)**
   - Path: `generic/bluetooth/bt_baseband_attack.py`
   - Orchestrates hardware-based BT Classic (BrakTooth/ESP32) and BLE (SweynTooth/nRF52840) baseband-level attacks. Manages attack firmware, serial communication, crash detection, and result analysis. Requ
   - CVEs: CVE-2019-16336, CVE-2019-17060, CVE-2019-17061, CVE-2019-17517, CVE-2019-17518, CVE-2019-17519, CVE-2019-17520, CVE-2019-19194, CVE-2019-19195, CVE-2019-19196, CVE-2021-28139
   - Devices: bluetooth, bluetooth_classic, bluetooth_le

4. **BT HID Injection (CVE-2023-45866 / CVE-2024-23717)**
   - Path: `generic/bluetooth/bt_hid_injection.py`
   - Unauthenticated Bluetooth HID injection. Registers as a keyboard or mouse via SDP, forces Just Works SSP pairing, then injects arbitrary keystrokes and mouse events. CVE-2024-23717 extends the attack 
   - CVEs: CVE-2023-45866, CVE-2024-23717
   - Devices: bluetooth, bluetooth_classic

5. **BT Session Key Attacks (KNOB/BIAS/BLUFFS)**
   - Path: `generic/bluetooth/bt_session_attack.py`
   - Unified Bluetooth BR/EDR session security analysis. KNOB (CVE-2019-9506): entropy reduction to 1 byte + brute force. BIAS (CVE-2020-10135): impersonation via legacy auth downgrade. BLUFFS (CVE-2023-24
   - CVEs: CVE-2019-9506, CVE-2020-10135, CVE-2023-24023
   - Devices: bluetooth, bluetooth_classic

6. **BTLEJack BLE Attack**
   - Path: `generic/bluetooth/ble_btlejack.py`
   - BLE sniff/jam/hijack orchestration using BTLEJack toolchain. Supports passive sniffing, active jamming, and takeover attempts against authorized lab BLE links.
   - Devices: bluetooth, bluetooth_le, ble

7. **BlueBorne Attack (CVE-2017-0781/0785/1000251)**
   - Path: `generic/bluetooth/blueborne_attack.py`
   - Native implementation of BlueBorne Bluetooth attacks. SDP info leak extracts ASLR bases from Android Bluedroid stack. BNEP heap overflow achieves code execution via heap corruption. L2CAP stack overfl
   - CVEs: CVE-2017-0781, CVE-2017-0785, CVE-2017-1000251
   - Devices: bluetooth, bluetooth_classic

8. **Bluetooth LE Enumerate**
   - Path: `generic/bluetooth/btle_enumerate.py`
   - Enumerating services and characteristics of a given Bluetooth Low Energy devices.

9. **Bluetooth LE Scan**
   - Path: `generic/bluetooth/btle_scan.py`
   - Scans for Bluetooth Low Energy devices.

10. **Bluetooth LE Write**
   - Path: `generic/bluetooth/btle_write.py`
   - Writes data to target Bluetooth Low Energy device to given characteristic.

### cve (2)

11. **CVE Lookup by Banner / Vendor / Product**
   - Path: `generic/cve/cve_lookup.py`
   - Queries the embedded CVE database for known vulnerabilities matching a target's vendor, product, version or raw banner. Classifies each CVE as REMOTE (exploitable in-tree via wxf), LOCAL or PHYSICAL. 
   - Devices: Wireless lab — subset emphasises 802.11/WPA/WPA3/BLE-adjacent CVE strings

12. **Zigbee Security Analysis (KillerBee Native)**
   - Path: `generic/cve/zigbee_attack.py`
   - Native Zigbee/IEEE 802.15.4 security toolkit. Protocol parsing, AES-CCM* decryption, network key extraction, beacon crafting, association flood generation, and network reconnaissance. Radio operations
   - Devices: zigbee, ieee802154

### external (19)

13. **Airgeddon Bridge**
   - Path: `generic/external/airgeddon_bridge.py`
   - Subprocess bridge to Airgeddon for handshake/WPS/evil-twin/WPA3 operations in authorized labs.
   - Devices: wifi

14. **Bruce Serial Bridge**
   - Path: `generic/external/bruce_serial_bridge.py`
   - Serial orchestration bridge for Bruce firmware CLI. Sends command profiles (wifi/webui/arp/sniffer/nav/options), captures responses, and persists output logs for lab reproducibility.
   - Devices: esp32, wifi, bluetooth

15. **Bruce Upstream Tracker**
   - Path: `generic/external/bruce_upstream_tracker.py`
   - Shows complete BruceDevices/firmware issues+PRs catalog and a categorized useful subset mapped to WirelessXPL modules.
   - Devices: wifi, bluetooth, esp32

16. **Bruce/ESP32 Marauder firmware (lab notes)**
   - Path: `generic/external/bruce_esp32_lab_notes.py`
   - Pointers to BruceDevices and ESP32 Marauder firmware: wardriving, raw sniffer hooks, deauth/beacon attacks and BLE scans on dedicated hardware. Export PCAP to this framework's ``generic/pcap/*`` modul
   - Devices: ESP32 / Cardputer / M5Stack (user hardware)

17. **EAPHammer Bridge**
   - Path: `generic/external/eaphammer_bridge.py`
   - Evil twin WPA-Enterprise, PMKID, EAP spray e portais via EAPHammer (GPL-3.0 subprocess). PEAP/TTLS/MD5/GTC via --phase-1/2-methods, KARMA, known beacons, cloaking, PMF, OWE transition e cert wizard.
   - Devices: wifi

18. **Fluxion Bridge**
   - Path: `generic/external/fluxion_bridge.py`
   - Evil twin + captive portal with handshake verification via Fluxion (GPL-3.0 subprocess). 54+ vendor-branded templates, OS connectivity detection, auto-mode, and multi-language support.
   - Devices: wifi

19. **OT Protocol Tools Bridge**
   - Path: `generic/external/ot_protocol_bridge.py`
   - Orquestra ferramentas em submodules/OT: isf (Industrial Exploitation Framework / icssploit), ModBusSploit (console e módulos Modbus TCP: scan, read/write, DoS, ARP MITM) e BusPwn (Flask + pymodbus). N
   - Devices: ot, ics, modbus, plc, wifi

20. **OneShot Bridge**
   - Path: `generic/external/oneshot_bridge.py`
   - WPS Pixie Dust, brute force online de PIN e WPS PBC via OneShot (subprocess), usando wpa_supplicant em modo gerenciado — sem monitor mode. Suporta lista vulnwsc.txt, WPSpin e flags -K / -B / --pbc.
   - Devices: wifi, wps

21. **Reaver / Wash / Pixiewps Bridge**
   - Path: `generic/external/reaver_bridge.py`
   - WPS: brute force de PIN e Pixie Dust via reaver (GPL-2.0), varredura WPS via wash, recuperação offline via pixiewps (GPL-3.0). Somente subprocess.
   - Devices: wifi, 802.11 WPS

22. **Rogue Evil Twin Bridge**
   - Path: `generic/external/rogue_bridge.py`
   - Orquestração de evil twin via processo externo (GPL-3.0): open/WEP/WPA/WPA-EAP, hostapd, DHCP, FreeRADIUS, certificados, Responder, sslsplit e Modlishka — invocado somente como subprocess.
   - Devices: wifi, evil_twin

23. **Router Firmware Analysis Bridge**
   - Path: `generic/external/router_firmware_bridge.py`
   - Orquestra ferramentas em submodules/IoT/third-party-router-poc: AESCrypt2 (C) para decrypt de config Huawei, HuaweiPasswordTool (C++) para formato de senha, hwfw-tool (Python 2) unpack/pack de firmwar
   - Devices: router, huawei, firmware, iot

24. **Social / Web OSINT Bridge**
   - Path: `generic/external/social_recon_bridge.py`
   - Reconhecimento OSINT para campanhas Wi‑Fi autorizadas: consulta social via RapidAPI (social-search e similares), extração léxica de site com cewler (subprocess) e geração de wordlist a partir de perfi
   - Devices: osint, wifi_workflow

25. **Wifiphisher Bridge**
   - Path: `generic/external/wifiphisher_bridge.py`
   - Evil twin + credential phishing via Wifiphisher (GPL-3.0 subprocess). Supports deauth, known-beacons, lure10, WPS-PBC, and 4 built-in phishing scenarios (firmware-upgrade, oauth-login, plugin_update, 
   - Devices: wifi

26. **Wifite2 Bridge**
   - Path: `generic/external/wifite2_bridge.py`
   - Orquestração de auditoria Wi‑Fi via Wifite2 (GPL-2.0 subprocess): WPA (handshake + crack), PMKID, WPS Pixie / PIN brute, WEP, filtros de alvo, 5 GHz, --kill, verbose e wordlist customizada.
   - Devices: wifi

27. **Wireless tool prerequisite audit**
   - Path: `generic/external/wireless_tool_prereq_audit.py`
   - Checks PATH for aircrack-ng suite, hcxtools, hashcat, bettercap, tshark. Use before wardriving / lab capture pipelines.
   - Devices: Workstation / Kali / WSL lab host

28. **bettercap Bridge**
   - Path: `generic/external/bettercap_bridge.py`
   - Orquestra bettercap (GPL-3.0 subprocess): wifi.recon, wifi.deauth, wifi.assoc (PMKID), handshake para arquivo, arp.spoof/dns.spoof com net.sniff, http.proxy/https.proxy (via -eval), ble.recon, caplets
   - Devices: wifi, ble, lan

29. **hcxtools PCAP bridge**
   - Path: `generic/external/hcx_toolchain_bridge.py`
   - Invokes hcxpcapngtool (preferred) or hcxpcaptool on a WPA/WPA2/WPA3 capture to emit hashcat-compatible lines (22000 for EAPOL, 22001 for PMKID). Also supports hcxhashtool for format conversion and qua
   - Devices: 802.11 WPA2/WPA3-transition PCAP/PCAPNG

30. **mdk4 Bridge**
   - Path: `generic/external/mdk4_bridge.py`
   - Invoca mdk4 (GPL-3.0) como subprocesso: beacon flood (b), auth DoS (a), probe/SSID bruteforce (p), deauth (d), Michael TKIP shutdown (m), EAPOL start/logoff flood (e), WIDS confusion (w), 802.11 fuzze
   - Devices: wifi

31. **wifipumpkin3 Bridge**
   - Path: `generic/external/wifipumpkin3_bridge.py`
   - Advanced rogue AP framework via wifipumpkin3 (Apache-2.0 subprocess). Supports captiveflask, Phishkin3 (MFA phishing), EvilQR3 (QR phishing), KARMA mode, Responder, Sniffkin3, PumpkinProxy, and REST A
   - Devices: wifi

### pcap (12)

32. **PCAP AP & Station Mapper**
   - Path: `generic/pcap/pcap_ap_station_mapper.py`
   - Offline analysis of PCAP/PCAPNG captures to enumerate access points (BSSID, SSID, channel, encryption) and client stations (probed SSIDs, associated BSSID, data frames). Useful after wardriving captur
   - Devices: Any 802.11 wireless capture

33. **PCAP BLE / HCI advertising survey**
   - Path: `generic/pcap/pcap_ble_advertising_survey.py`
   - Iterates packets counting Scapy BTLE/HCI layer names — useful for Ubertooth, nRF Sniffer, or BlueZ *hcidump* exports. Pair with live `generic/bluetooth/btle_*` modules on Linux.
   - Devices: BLE HCI / sniffer PCAP

34. **PCAP EAPOL 4-way handshake survey**
   - Path: `generic/pcap/pcap_eapol_survey.py`
   - Offline analysis: classify EAPOL-Key frames (M1–M4), track nonces and replay counters, emit KRACK-family hints (CVE-2017-13077 …). Complements hashcat (mode 22000/22001) and aircrack-ng cracking workf
   - CVEs: CVE-2017-13077
   - Devices: 802.11 WPA2/WPA3-transition captures

35. **PCAP Offline Credential Sniffer**
   - Path: `generic/pcap/pcap_credential_sniffer.py`
   - Offline extraction of cleartext credentials from PCAP/PCAPNG captures. Detects HTTP Basic/Form auth, FTP USER/PASS, Telnet logins and SNMP community strings.
   - Devices: Any network capture with cleartext protocols

36. **PCAP Offline EAP/WPE Credential Harvester**
   - Path: `generic/pcap/pcap_wpe_harvest.py`
   - Extracts EAP identities and challenge-response pairs from 802.1X authentication captures (WPA-Enterprise). Supports EAP-MD5, LEAP, MSCHAPv2, PEAP, EAP-TTLS, EAP-FAST. Produces hashcat-ready hashes for
   - Devices: Any WPA-Enterprise / 802.1X network capture

37. **PCAP Offline PMKID Attack (WPA/WPA2 Clientless)**
   - Path: `generic/pcap/pcap_pmkid_attack.py`
   - Extracts PMKID from EAPOL message 1 for clientless WPA/WPA2 offline attacks. No full 4-way handshake required. Outputs hashcat mode 22000 format and optionally runs hashcat.
   - Devices: Any WPA/WPA2-PSK network (most modern APs include PMKID)

38. **PCAP Offline TKIP/Michael Attack Analysis**
   - Path: `generic/pcap/pcap_tkip_downgrade.py`
   - Analyzes PCAP captures for TKIP vulnerabilities including Beck-Tews (QoS injection), Ohigashi-Morii (man-in-the-middle), and ChopChop (frame decryption) attack feasibility. Detects MIC failure deauths
   - Devices: Any WPA-TKIP or WPA2-TKIP mixed-mode network capture

39. **PCAP Offline WEP Key Recovery**
   - Path: `generic/pcap/pcap_wep_crack.py`
   - Extracts WEP IVs from PCAP captures and runs offline statistical key recovery using aircrack-ng (FMS/PTW/KoreK). Reports IV counts, weak IV statistics and crackability assessment.
   - Devices: Any WEP-encrypted 802.11 network capture

40. **PCAP Offline WPA/WPA2 Dictionary Attack**
   - Path: `generic/pcap/pcap_offline_wpa_crack.py`
   - Runs an offline dictionary attack against WPA/WPA2 handshakes captured in PCAP files. Supports aircrack-ng (default) and hashcat. Requires a wordlist and a capture file with a valid handshake.
   - Devices: Any WPA/WPA2 PSK network (captured handshake required)

41. **PCAP Offline WPA3 Dragonblood Analysis**
   - Path: `generic/pcap/pcap_dragonblood.py`
   - Analyzes WPA3 SAE (Dragonfly) handshakes in PCAP captures for Dragonblood vulnerabilities: CVE-2019-9494 (timing side-channel), CVE-2019-9496 (transition mode downgrade), weak group detection, and cac
   - CVEs: CVE-2019-9494, CVE-2019-9496
   - Devices: Any WPA3-SAE or WPA3-Transition mode network capture

42. **PCAP SQL Workspace**
   - Path: `generic/pcap/pcap_sql_workspace.py`
   - Creates and manages a SQLite workspace for PCAP ingestion metadata and analyst notes.
   - Devices: wifi, pcap

43. **PCAP WPA/WPA2 Handshake Extractor**
   - Path: `generic/pcap/pcap_handshake_extractor.py`
   - Offline extraction of EAPOL 4-way handshakes from PCAP/PCAPNG captures. Exports usable handshakes to individual PCAP files ready for cracking with aircrack-ng or hashcat.
   - Devices: Any 802.11 WPA/WPA2 wireless capture

### wifi_lab (44)

44. **AWDL Attack (OpenDrop/Owl)**
   - Path: `generic/wifi_lab/awdl_attack.py`
   - AWDL/AirDrop lab workflows using OpenDrop and Owl as subprocesses. Supports discovery, send-test simulation, and AWDL stress modes in authorized environments.
   - Devices: wifi, awdl

45. **Adaptive Harvest**
   - Path: `generic/wifi_lab/adaptive_harvest.py`
   - Score-driven collection loop for handshake/PMKID captures with adaptive channel selection.
   - Devices: wifi

46. **Auth/Assoc Flood**
   - Path: `generic/wifi_lab/auth_flood.py`
   - Exhaust AP resources via mass authentication/association requests: random MAC auth flood (mdk4), AMOK mode, EAPOL-Start flood, and CTS/NAV reservation attacks.
   - Devices: wifi

47. **Beacon Flood Advanced**
   - Path: `generic/wifi_lab/beacon_flood_advanced.py`
   - Flood the RF spectrum with fake beacon frames: random SSIDs, AP cloning, wordlist-based SSIDs, and channel-targeted floods. Uses Scapy, mdk3, or mdk4 as backend.
   - Devices: wifi

48. **Captive portal (modern lab UI)**
   - Path: `generic/wifi_lab/captive_portal_modern_lab.py`
   - Bindable HTTP portal logging form posts — intended with dnsmasq address=/#/ on a dedicated evil-twin NIC. No TLS (use reverse proxy if needed).
   - Devices: Isolated lab subnet

49. **Connectivity Portal**
   - Path: `generic/wifi_lab/connectivity_portal.py`
   - Smart captive portal with OS connectivity detection and automatic language detection (en, pt-br, pt-pt, es). Triggers native portal popup on Apple, Android, Windows, Firefox, Kindle, Samsung. 16+ vend
   - Devices: wifi

50. **Deauth / CSA Suite**
   - Path: `generic/wifi_lab/deauth_csa_suite.py`
   - Deautenticação e desassociação 802.11 (aireplay-ng, Scapy, mdk4), anúncio de mudança de canal (CSA em beacon) e modos broadcast vs STA alvo, com hopping multi-canal (2.4 / 5 GHz). Exige interface em m
   - Devices: wifi

51. **Deauth Multi-Mode**
   - Path: `generic/wifi_lab/deauth_multimode.py`
   - Multi-strategy deauthentication: targeted, broadcast, multi-AP, channel-hopping, and PMF-aware modes. Uses aireplay-ng, mdk4, or Scapy as backend. All modes require monitor-mode interface in authorize
   - Devices: wifi

52. **Dual-Band Evil Twin**
   - Path: `generic/wifi_lab/dualband_evil_twin.py`
   - Simultaneous 2.4/5 GHz evil twin: rogue AP on one band while deauthing target on both bands. Requires 2 Wi-Fi interfaces. Addresses Fluxion issue #1004 (5GHz deauth + 2.4GHz evil twin).
   - Devices: wifi

53. **Evil QR Attack**
   - Path: `generic/wifi_lab/evil_qr_attack.py`
   - Generate malicious QR codes for phishing: Wi-Fi auto-connect, captive portal redirect, session hijacking (WhatsApp/Discord), and custom URLs. Inspired by wifipumpkin3's EvilQR3.
   - Devices: wifi

54. **Evil Twin Advanced**
   - Path: `generic/wifi_lab/evil_twin_advanced.py`
   - Full evil twin workflow: AP cloning, rogue AP (hostapd), DHCP/DNS (dnsmasq), captive portal with multiple phishing templates (ISP, firmware, OAuth, hotel, VPN, Network Manager), credential capture. Op
   - Devices: wifi

55. **Evil twin lab runbook**
   - Path: `generic/wifi_lab/evil_twin_workflow.py`
   - Prints ordered steps and example hostapd/dnsmasq snippets; optional call into aireplay-ng barrage helper binary.
   - Devices: Authorised isolated RF bench

56. **Evil twin — 6× hostapd templates**
   - Path: `generic/wifi_lab/evil_twin_hostapd_templates.py`
   - Generates configuration stubs including WPA3 transition (mixed) for studying downgrade paths alongside open/WPA2/SAE/OWE sketches.
   - Devices: Authorised RF bench + compatible NIC

57. **Evilginx prerequisite pointer**
   - Path: `generic/wifi_lab/evilginx_prereq_pointer.py`
   - Locates ``evilginx`` on PATH and references the upstream project; use only in isolated phishing/MFA labs with written consent.
   - Devices: Lab attacker host

58. **FragAttacks (CVE-2020-24586..26146)**
   - Path: `generic/wifi_lab/fragattacks.py`
   - 802.11 fragmentation and aggregation attack primitives. Fragment cache poisoning, mixed-key fragment reassembly, A-MSDU injection via EAPOL, broadcast fragment cache attacks, and PN/IV reuse detection
   - CVEs: CVE-2020-24586, CVE-2020-24587, CVE-2020-24588, CVE-2020-26144, CVE-2020-26146
   - Devices: wifi

59. **GPS wardriving NMEA → NDJSON**
   - Path: `generic/wifi_lab/gps_wardriving_ndjson.py`
   - Extracts coarse position rows for correlating with Wi-Fi/BLE logs.
   - Devices: NMEA log file

60. **Handshake Snooper**
   - Path: `generic/wifi_lab/handshake_snooper.py`
   - Automated WPA handshake capture: monitor mode, target scan, deauth to force re-auth, EAPOL capture, and handshake verification via aircrack-ng/cowpatty. Inspired by Fluxion's Handshake Snooper.
   - Devices: wifi

61. **Hashcat GPU/CPU orchestrator (WPA modes)**
   - Path: `generic/wifi_lab/hashcat_gpu_orchestrator.py`
   - Builds a hashcat argv for mode 22000/2500-class WPA material; prints devices (-I) and runs or dry-runs attack.
   - Devices: Cracking workstation

62. **KARMA / MANA Attack**
   - Path: `generic/wifi_lab/karma_mana_attack.py`
   - Rogue AP that responds to all probe requests, impersonating any SSID the client searches for. Supports KARMA basic, MANA loud, targeted KARMA, and MANA-EAP for 802.1X credential capture. Requires host
   - Devices: wifi

63. **KR00K Attack (CVE-2019-15126)**
   - Path: `generic/wifi_lab/kr00k_attack.py`
   - Exploits Broadcom/Cypress Wi-Fi chip flaw: after deauth, buffered frames are transmitted encrypted with an all-zero Temporal Key. Captures CCMP frames and decrypts them without the WPA2 password. Nati
   - CVEs: CVE-2019-15126
   - Devices: wifi

64. **KRACK Attack (CVE-2017-13077..13088)**
   - Path: `generic/wifi_lab/krack_attack.py`
   - Key Reinstallation Attacks on WPA2. Detects and exploits nonce reuse in the 4-way handshake (Message 3 replay), group key handshake (group PN reset), and FT reassociation. Passive monitoring for IV/PN
   - CVEs: CVE-2017-13077
   - Devices: wifi

65. **MFA Phishing Portal**
   - Path: `generic/wifi_lab/mfa_phishing_portal.py`
   - Real-time MFA phishing via captive portal: local HTML clone with MFA field, external proxy (evilginx-style), or cloud redirect (Phishkin3-style). Captures password + MFA token/push approval. Includes 
   - Devices: wifi

66. **MITM Wi-Fi Bridge**
   - Path: `generic/wifi_lab/mitm_wifi_bridge.py`
   - Man-in-the-Middle via rogue AP bridge (NAT), ARP spoofing, DNS spoofing, or SSL stripping. Captures traffic and credentials from Wi-Fi clients. Requires two interfaces or upstream connection + betterc
   - Devices: wifi

67. **MoMo Integrated Attack**
   - Path: `generic/wifi_lab/momo_integrated_attack.py`
   - Integrated KARMA + PMKID-first + downgrade orchestration in a single authorized-lab workflow.
   - Devices: wifi

68. **PCAP RF anomaly scorer (+ optional ML)**
   - Path: `generic/wifi_lab/pcap_rf_anomaly_ml.py`
   - 802.11 management/data counters per file; optional IsolationForest when multiple PCAPs in a directory.
   - Devices: Offline PCAP/PCAPNG

69. **PCAP WPA handshake & PMKID validator**
   - Path: `generic/wifi_lab/pcap_wpa_handshake_validate.py`
   - Reports 4-way EAPOL progress per STA/BSSID, PMKID availability, and optional hc22000 export probe via hcxpcapngtool.
   - Devices: 802.11 WPA2 PCAP/PCAPNG

70. **Responder Wi-Fi**
   - Path: `generic/wifi_lab/responder_wifi.py`
   - LLMNR/NBT-NS/mDNS poisoning via Responder on rogue AP interface. Captures NTLM hashes, HTTP credentials, and auth tokens from clients connected to evil twin. Requires Responder.py.
   - Devices: wifi

71. **SSID Confusion Attack (CVE-2023-52424)**
   - Path: `generic/wifi_lab/ssid_confusion.py`
   - Multi-Channel Man-in-the-Middle with SSID rewriting. Clones target AP beacon with a trusted SSID, injects CSA to force client migration, then relays traffic while maintaining the SSID illusion. Client
   - CVEs: CVE-2023-52424
   - Devices: wifi

72. **Selective Jammer**
   - Path: `generic/wifi_lab/selective_jammer.py`
   - Surgical deauthentication: target specific clients by MAC instead of broadcast. Whitelist, blacklist, or auto-new modes. Addresses Fluxion issue #329 (jam specific clients).
   - Devices: wifi

73. **Transparent Proxy**
   - Path: `generic/wifi_lab/transparent_proxy.py`
   - Transparent proxy on rogue AP: HTTP inspection, JS/HTML injection, download spoofing, credential sniffing. Backends: mitmproxy, bettercap, or lightweight built-in. Inspired by wifipumpkin3's PumpkinPr
   - Devices: wifi

74. **WPA3 Attack Suite**
   - Path: `generic/wifi_lab/wpa3_attack_suite.py`
   - Authorised-lab bridge: WPA3 transition downgrade (DragonShift / WPA3-Transition-mode-Downgrade-attack), SAE commit flood (dragon-drain, Nuseo1, sae_clogging_attack), CSA injection (Politician-style), 
   - Devices: wifi

75. **WPS Multi-Mode Attack**
   - Path: `generic/wifi_lab/wps_multimode.py`
   - WPS attack suite: pixie-dust offline PIN recovery (pixiewps), online PIN brute-force (reaver/bully), PBC window exploit, and null/empty PIN attacks. Includes WPS AP scanner (wash).
   - Devices: wifi

76. **Wardriving Deauth Loop**
   - Path: `generic/wifi_lab/wardriving_deauth_loop.py`
   - Automated wardriving pipeline with scan/deauth/capture rotations. Designed for authorized roaming assessments and handshake collection.
   - Devices: wifi

77. **Wi-Fi Frame Replay**
   - Path: `generic/wifi_lab/replay_attack.py`
   - Replay captured 802.11 frames: EAPOL (force re-auth), beacons (SSID spoof), authentication, probe responses, or arbitrary frames from PCAP. Uses Scapy for frame injection.
   - Devices: wifi

78. **WiFi Sniffer**
   - Path: `generic/wifi_lab/wifi_sniffer.py`
   - Traffic sniffer for rogue AP: captures HTTP forms, Basic Auth, FTP/POP3/IMAP cleartext creds, DNS queries, cookies, and EAPOL. Backends: scapy, tcpdump, tshark. Inspired by wifipumpkin3's Sniffkin3.
   - Devices: wifi

79. **Wireless IDS (Baseline/Anomaly)**
   - Path: `generic/wifi_lab/wireless_ids.py`
   - Passive IDS helper that learns AP baseline from CSV scans and flags rogue/new BSSIDs for analyst review.
   - Devices: wifi

80. **Wireless research ecosystem (submodule) status**
   - Path: `generic/wifi_lab/research_ecosystem_status.py`
   - Maps GitHub WPA3/Wi-Fi research submodules to on-disk paths under the SafeLabs-style superproject layout.
   - Devices: Workstation with superproject checkout

81. **Wordlist orchestrator (Wi‑Fi / WPA lab)**
   - Path: `generic/wifi_lab/wordlist_orchestrator.py`
   - Modos static | osint | pattern | isp | combined | auto: localiza wordlists em submodules/Wordlists, invoca cewler/CeWL/wfh/pnwgen/crunch/BruteForge/Xfinity via subprocess, faz merge opcional com dedup
   - Devices: wifi, wpa_lab

82. **_disclaimer**
   - Path: `generic/wifi_lab/_disclaimer.py`

83. **_i18n_service**
   - Path: `generic/wifi_lab/_i18n_service.py`

84. **aireplay-ng deauth / disassoc barrage**
   - Path: `generic/wifi_lab/aireplay_deauth_barrage.py`
   - Runs repeated aireplay-ng -0 bursts; optional dual-target alternation (BSSID + STA) and parallel streams for stubborn clients. Requires monitor-mode interface + injection-capable driver.
   - Devices: Linux lab interface (monitor mode)

85. **hostapd rogue AP bridge**
   - Path: `generic/wifi_lab/rogue_ap_hostapd_bridge.py`
   - Writes hostapd.conf for AP mode (nl80211) and execs hostapd. Requires ap-mode capable NIC + correct driver.
   - Devices: Linux AP-capable WLAN

86. **mdk3 legacy bridge**
   - Path: `generic/wifi_lab/mdk3_bridge.py`
   - Invokes mdk3 <iface> <mode> [options]. Modes include b, a, p, d, m, x, w, f.
   - Devices: Linux monitor interface (legacy stacks)

87. **mdk4 attack bridge**
   - Path: `generic/wifi_lab/mdk4_bridge.py`
   - Runs mdk4 <iface> <mode> [options]. Common modes: d (deauth/disassoc), b (beacon flood), a (auth DoS), p (probing), g (WPA downgrade), m (Michael shutdown). See mdk4 --help <mode>.
   - Devices: Linux monitor interface + injection

### wordlist (1)

88. **Interactive Wordlist Generator**
   - Path: `generic/wordlist/wordlist_generator.py`
   - Generates custom password and username wordlists based on target profile (corporate or personal). Applies mutation rules (leet speak, case variations, number suffixes, date fragments, word combination
   - Devices: Any target — wordlist generation is target-independent

## Encoders (0)

## Payloads (0)

---

## CVE Master List (29)

| # | CVE ID | Modules |
|---:|---|---|
| 1 | CVE-2017-0781 | `generic/bluetooth/blueborne_attack.py` |
| 2 | CVE-2017-0785 | `generic/bluetooth/blueborne_attack.py` |
| 3 | CVE-2017-1000251 | `generic/bluetooth/blueborne_attack.py` |
| 4 | CVE-2017-13077 | `generic/pcap/pcap_eapol_survey.py`, `generic/wifi_lab/krack_attack.py` |
| 5 | CVE-2019-15126 | `generic/wifi_lab/kr00k_attack.py` |
| 6 | CVE-2019-16336 | `generic/bluetooth/bt_baseband_attack.py` |
| 7 | CVE-2019-17060 | `generic/bluetooth/bt_baseband_attack.py` |
| 8 | CVE-2019-17061 | `generic/bluetooth/bt_baseband_attack.py` |
| 9 | CVE-2019-17517 | `generic/bluetooth/bt_baseband_attack.py` |
| 10 | CVE-2019-17518 | `generic/bluetooth/bt_baseband_attack.py` |
| 11 | CVE-2019-17519 | `generic/bluetooth/bt_baseband_attack.py` |
| 12 | CVE-2019-17520 | `generic/bluetooth/bt_baseband_attack.py` |
| 13 | CVE-2019-19194 | `generic/bluetooth/bt_baseband_attack.py` |
| 14 | CVE-2019-19195 | `generic/bluetooth/bt_baseband_attack.py` |
| 15 | CVE-2019-19196 | `generic/bluetooth/bt_baseband_attack.py` |
| 16 | CVE-2019-9494 | `generic/pcap/pcap_dragonblood.py` |
| 17 | CVE-2019-9496 | `generic/pcap/pcap_dragonblood.py` |
| 18 | CVE-2019-9506 | `generic/bluetooth/bt_session_attack.py` |
| 19 | CVE-2020-10135 | `generic/bluetooth/bt_session_attack.py` |
| 20 | CVE-2020-24586 | `generic/wifi_lab/fragattacks.py` |
| 21 | CVE-2020-24587 | `generic/wifi_lab/fragattacks.py` |
| 22 | CVE-2020-24588 | `generic/wifi_lab/fragattacks.py` |
| 23 | CVE-2020-26144 | `generic/wifi_lab/fragattacks.py` |
| 24 | CVE-2020-26146 | `generic/wifi_lab/fragattacks.py` |
| 25 | CVE-2021-28139 | `generic/bluetooth/bt_baseband_attack.py` |
| 26 | CVE-2023-24023 | `generic/bluetooth/bt_session_attack.py` |
| 27 | CVE-2023-45866 | `generic/bluetooth/bt_hid_injection.py` |
| 28 | CVE-2023-52424 | `generic/wifi_lab/ssid_confusion.py` |
| 29 | CVE-2024-23717 | `generic/bluetooth/bt_hid_injection.py` |

## CVEs by Vendor

| Vendor | CVE Count | CVE IDs |
|---|---:|---|
| bluetooth | 19 | CVE-2017-0781, CVE-2017-0785, CVE-2017-1000251, CVE-2019-16336, CVE-2019-17060, CVE-2019-17061, CVE-2019-17517, CVE-2019-17518, CVE-2019-17519, CVE-2019-17520, CVE-2019-19194, CVE-2019-19195, CVE-2019-19196, CVE-2019-9506, CVE-2020-10135, CVE-2021-28139, CVE-2023-24023, CVE-2023-45866, CVE-2024-23717 |
| pcap | 3 | CVE-2017-13077, CVE-2019-9494, CVE-2019-9496 |
| wifi_lab | 8 | CVE-2017-13077, CVE-2019-15126, CVE-2020-24586, CVE-2020-24587, CVE-2020-24588, CVE-2020-26144, CVE-2020-26146, CVE-2023-52424 |

---

> Generated by tools/generate_full_catalog.py