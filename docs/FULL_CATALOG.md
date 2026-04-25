# wirelessxpl-Forge — Full Module Catalog

> Modules tree id: `806db47e0030` (git object)
> Author: Andre Henrique (@mrhenrike) | Uniao Geek

## Summary

| Category | Modules | Vendor / group buckets |
|---|---:|---:|
| Exploits | 0 | 0 |
| Credential Modules | 0 | 0 |
| Scanners | 0 | 0 |
| Generic Modules | 132 | 6 |
| Encoders | 0 | 0 |
| Payloads | 0 | 0 |
| **Total Modules** | **132** | — |
| Distinct CVEs | 42 | — |

## Program footprint

Approximate on-disk size (file bytes only; binary prefixes). When using git metadata, ``docs/`` is excluded (wiki + generated catalogs). Walk skips caches such as ``__pycache__`` and ``.git``.

| Metric | Value |
|---|---|
| Repository root | `WirelessXPL-Forge` |
| Total file bytes | 32.03 MiB |
| Files (repo walk) | 388 |
| Files under ``wirelessxpl/`` | 325 |

### Largest top-level paths (repository)

| Path | Size | Share of total |
|---|---:|---:|
| `wirelessxpl` | 31.72 MiB | 99.0% |
| `tools` | 258.60 KiB | 0.8% |
| `(repo root files)` | 48.51 KiB | 0.1% |
| `.github` | 9.62 KiB | 0.0% |
| `.travis` | 721 B | 0.0% |

### ``wirelessxpl/`` breakdown (first-level folders)

| Area | Size | Share of total |
|---|---:|---:|
| `resources` | 30.51 MiB | 95.2% |
| `modules` | 938.81 KiB | 2.9% |
| `core` | 263.05 KiB | 0.8% |
| `(wirelessxpl root files)` | 28.32 KiB | 0.1% |
| `libs` | 13.29 KiB | 0.0% |

### ``wirelessxpl/resources/*`` (largest direct children)

| Subfolder | Size | Share of total |
|---|---:|---:|
| `catalogs` | 25.62 MiB | 80.0% |
| `vendors` | 4.44 MiB | 13.9% |
| `captive_templates` | 232.93 KiB | 0.7% |
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
| `wirelessxpl/modules` | 140 |
| `wirelessxpl/libs` | 5 |
| `tools` | 35 |
| `wxf.py` | 1 |

---

## Exploits (0)

## Credential Modules (0)

## Scanners (0)

## Generic Modules (132)

### bluetooth (21)

1. **BIAS BT Impersonation Attack Bridge**
   - Path: `generic/bluetooth/bias_attack_bridge.py`
   - BIAS (CVE-2020-10135) — impersonates a Bluetooth BR/EDR device without the long-term key by exploiting authentication bypass in Legacy and Secure Connections modes. Requires BT MITM position. Bridges 
   - CVEs: CVE-2020-10135
   - Devices: bluetooth, BT BR/EDR Classic

2. **BLE Crackle (Legacy Pairing Cracker)**
   - Path: `generic/bluetooth/ble_crackle.py`
   - Pure Python BLE Legacy Pairing cracker. Extracts SMP pairing data from PCAPs, brute-forces the Temporary Key (TK, 0-999999), derives STK and Session Key, decrypts all traffic, and extracts the Long-Te
   - Devices: bluetooth, bluetooth_le

3. **BLE Extra Attacks (BLURtooth/BLESA/GATTacker/Relay)**
   - Path: `generic/bluetooth/ble_extra_attacks.py`
   - Additional BLE attack modules: BLURtooth CTKD cross-transport key overwrite (CVE-2020-15802), BLESA reconnection spoofing (CVE-2020-9770), GATTacker BLE MITM proxy, and BLE relay over IP for range ext
   - CVEs: CVE-2020-15802, CVE-2020-9770
   - Devices: bluetooth, ble

4. **BLE Phishing & Spoof**
   - Path: `generic/bluetooth/ble_phishing.py`
   - BLE-based social engineering: advertisement spam (Apple/Samsung/Google device spoofing), name-based lure for pairing, BLE MITM via btlejuice, iBeacon/Eddystone cloning, and notification spam. Requires
   - Devices: bluetooth

5. **BLUFFS — BLE Session Key Downgrade**
   - Path: `generic/bluetooth/ble_bluffs_native.py`
   - BLUFFS (CVE-2023-24023) — forces predictable BLE session keys by manipulating LL_FEATURE_RSP/PAIRING_FEATURE_REQ to disable session key diversification. Breaks BLE forward and future secrecy. Requires
   - CVEs: CVE-2023-24023
   - Devices: ble, Bluetooth Low Energy

6. **BT Baseband Attacks (BrakTooth + SweynTooth)**
   - Path: `generic/bluetooth/bt_baseband_attack.py`
   - Orchestrates hardware-based BT Classic (BrakTooth/ESP32) and BLE (SweynTooth/nRF52840) baseband-level attacks. Manages attack firmware, serial communication, crash detection, and result analysis. Requ
   - CVEs: CVE-2019-16336, CVE-2019-17060, CVE-2019-17061, CVE-2019-17517, CVE-2019-17518, CVE-2019-17519, CVE-2019-17520, CVE-2019-19194, CVE-2019-19195, CVE-2019-19196, CVE-2021-28139
   - Devices: bluetooth, bluetooth_classic, bluetooth_le

7. **BT HID Injection (CVE-2023-45866 / CVE-2024-23717)**
   - Path: `generic/bluetooth/bt_hid_injection.py`
   - Unauthenticated Bluetooth HID injection. Registers as a keyboard or mouse via SDP, forces Just Works SSP pairing, then injects arbitrary keystrokes and mouse events. CVE-2024-23717 extends the attack 
   - CVEs: CVE-2023-45866, CVE-2024-23717
   - Devices: bluetooth, bluetooth_classic

8. **BT Session Key Attacks (KNOB/BIAS/BLUFFS)**
   - Path: `generic/bluetooth/bt_session_attack.py`
   - Unified Bluetooth BR/EDR session security analysis. KNOB (CVE-2019-9506): entropy reduction to 1 byte + brute force. BIAS (CVE-2020-10135): impersonation via legacy auth downgrade. BLUFFS (CVE-2023-24
   - CVEs: CVE-2019-9506, CVE-2020-10135, CVE-2023-24023
   - Devices: bluetooth, bluetooth_classic

9. **BTLEJack BLE Attack**
   - Path: `generic/bluetooth/ble_btlejack.py`
   - BLE sniff/jam/hijack orchestration using BTLEJack toolchain. Supports passive sniffing, active jamming, and takeover attempts against authorized lab BLE links.
   - Devices: bluetooth, bluetooth_le, ble

10. **BlueBorne Attack (CVE-2017-0781/0785/1000251)**
   - Path: `generic/bluetooth/blueborne_attack.py`
   - Native implementation of BlueBorne Bluetooth attacks. SDP info leak extracts ASLR bases from Android Bluedroid stack. BNEP heap overflow achieves code execution via heap corruption. L2CAP stack overfl
   - CVEs: CVE-2017-0781, CVE-2017-0785, CVE-2017-1000251
   - Devices: bluetooth, bluetooth_classic

11. **Bluetooth Classic (BR/EDR) Security Suite**
   - Path: `generic/bluetooth/bt_classic_suite.py`
   - SDP service discovery, PIN brute-force, L2CAP probing, and MITM for Bluetooth Classic BR/EDR devices. Uses BlueZ tools (hcitool, sdptool, l2ping) and optional InternalBlue for firmware-level attacks.
   - Devices: bluetooth, bt-classic, br-edr

12. **Bluetooth LE Enumerate**
   - Path: `generic/bluetooth/btle_enumerate.py`
   - Enumerating services and characteristics of a given Bluetooth Low Energy devices.

13. **Bluetooth LE Scan**
   - Path: `generic/bluetooth/btle_scan.py`
   - Scans for Bluetooth Low Energy devices.

14. **Bluetooth LE Write**
   - Path: `generic/bluetooth/btle_write.py`
   - Writes data to target Bluetooth Low Energy device to given characteristic.

15. **BrAcketooth BT Classic Stack Attack Bridge**
   - Path: `generic/bluetooth/braktooth_bridge.py`
   - Bridges BrAcketooth 16+ BT Classic (BR/EDR) vulnerabilities: deadlock, memory corruption, L2CAP abuse, feature injection. Targets: Intel, Qualcomm, Zhuhai Jieli, Silicon Labs, Cypress, Espressif chips
   - Devices: bluetooth, BT BR/EDR Classic

16. **KNOB BT Key Negotiation Attack Bridge**
   - Path: `generic/bluetooth/knob_attack_bridge.py`
   - KNOB (CVE-2019-9506) — forces 1-byte entropy in BT BR/EDR key negotiation, enabling real-time brute-force of the session key. Affects BT 1.0–5.1. Requires attacker-in-the-middle BT position and compat
   - CVEs: CVE-2019-9506
   - Devices: bluetooth, BT BR/EDR Classic

17. **KillerBee Zigbee Bridge**
   - Path: `generic/bluetooth/killerbee_zigbee_bridge.py`
   - Bridges KillerBee (IEEE 802.15.4 / Zigbee toolkit) as WXF module. Modes: zbid (hardware enum), zbdump (capture), zbreplay (replay), zbstumbler (discovery), zbassocflood (DoS), zbscapy (Scapy shell). R
   - Devices: zigbee, IEEE 802.15.4

18. **SweynTooth BLE Stack Attack Bridge**
   - Path: `generic/bluetooth/ble_sweyntooth_bridge.py`
   - Bridges SweynTooth BLE stack exploits: deadlock, crash, DoS, and FIPS pairing bypass on vulnerable SoCs (TI, NXP, Dialog, Microchip, ST, Telink, Cypress). Requires nRF52-series dongle with custom firm
   - CVEs: CVE-2019-16336, CVE-2019-17071, CVE-2019-17516, CVE-2019-17517, CVE-2019-17518, CVE-2019-17519, CVE-2019-17520, CVE-2019-17521, CVE-2019-9506
   - Devices: ble, Bluetooth Low Energy SoC

19. **Zigator Zigbee Analysis Bridge**
   - Path: `generic/bluetooth/zigator_bridge.py`
   - Bridges Zigator for Zigbee / IEEE 802.15.4 security analysis. Modes: info, decrypt (PCAP decryption with network key), forge (craft Zigbee frames), inject (transmit forged frames), sniffer (live captu
   - Devices: zigbee, IEEE 802.15.4

20. **Zigbee Key Extract**
   - Path: `generic/bluetooth/zigbee_key_extract.py`
   - Parse Zigbee PCAP captures to extract network encryption keys from unencrypted APS Transport Key frames. Also scans captured traffic against known default keys (HA, 3.0, vendor defaults). Requires Sca
   - Devices: zigbee, IEEE 802.15.4

21. **Zigbee Realignment Attack**
   - Path: `generic/bluetooth/zigbee_realignment_attack.py`
   - Force Zigbee devices to rejoin the network by injecting IEEE 802.15.4 Coordinator Realignment or Orphan Notification frames. During rejoin, the network key may be exposed via APS Transport Key if defa
   - Devices: zigbee, IEEE 802.15.4

### cve (2)

22. **CVE Lookup by Banner / Vendor / Product**
   - Path: `generic/cve/cve_lookup.py`
   - Queries the embedded CVE database for known vulnerabilities matching a target's vendor, product, version or raw banner. Classifies each CVE as REMOTE (exploitable in-tree via wxf), LOCAL or PHYSICAL. 
   - Devices: Wireless lab — subset emphasises 802.11/WPA/WPA3/BLE-adjacent CVE strings

23. **Zigbee Security Analysis (KillerBee Native)**
   - Path: `generic/cve/zigbee_attack.py`
   - Native Zigbee/IEEE 802.15.4 security toolkit. Protocol parsing, AES-CCM* decryption, network key extraction, beacon crafting, association flood generation, and network reconnaissance. Radio operations
   - Devices: zigbee, ieee802154

### external (30)

24. **Aircrack-ng Full Suite Bridge**
   - Path: `generic/external/aircrack_full_bridge.py`
   - Unified orchestration for the entire aircrack-ng toolkit: airmon-ng, airodump-ng, aireplay-ng (all 7 attack modes), aircrack-ng (WEP/WPA), airdecap-ng, airolib-ng (PMK DB), besside-ng (auto-crack), pa
   - Devices: wifi, 802.11

25. **Airgeddon Bridge**
   - Path: `generic/external/airgeddon_bridge.py`
   - Subprocess bridge to Airgeddon for handshake/WPS/evil-twin/WPA3 operations in authorized labs.
   - Devices: wifi

26. **Bruce Serial Bridge**
   - Path: `generic/external/bruce_serial_bridge.py`
   - Serial orchestration bridge for Bruce firmware CLI. Sends command profiles (wifi/webui/arp/sniffer/nav/options), captures responses, and persists output logs for lab reproducibility.
   - Devices: esp32, wifi, bluetooth

27. **Bruce Upstream Tracker**
   - Path: `generic/external/bruce_upstream_tracker.py`
   - Shows complete BruceDevices/firmware issues+PRs catalog and a categorized useful subset mapped to WirelessXPL modules.
   - Devices: wifi, bluetooth, esp32

28. **Bruce/ESP32 Marauder firmware (lab notes)**
   - Path: `generic/external/bruce_esp32_lab_notes.py`
   - Pointers to BruceDevices and ESP32 Marauder firmware: wardriving, raw sniffer hooks, deauth/beacon attacks and BLE scans on dedicated hardware. Export PCAP to this framework's ``generic/pcap/*`` modul
   - Devices: ESP32 / Cardputer / M5Stack (user hardware)

29. **Bully WPS Brute-Force Bridge**
   - Path: `generic/external/bully_bridge.py`
   - WPS PIN brute-force via bully (C binary, GPL-2.0). Supports standard PIN enumeration, specific PIN attempt, and Pixie Dust (--pixiedust). Alternative to reaver with different WPS lock handling. subpro
   - Devices: wifi, 802.11 WPS

30. **EAPHammer Bridge**
   - Path: `generic/external/eaphammer_bridge.py`
   - Evil twin WPA-Enterprise, PMKID, EAP spray e portais via EAPHammer (GPL-3.0 subprocess). PEAP/TTLS/MD5/GTC via --phase-1/2-methods, KARMA, known beacons, cloaking, PMF, OWE transition e cert wizard.
   - Devices: wifi

31. **Fluxion Bridge**
   - Path: `generic/external/fluxion_bridge.py`
   - Evil twin + captive portal with handshake verification via Fluxion (GPL-3.0 subprocess). 54+ vendor-branded templates, OS connectivity detection, auto-mode, and multi-language support.
   - Devices: wifi

32. **Hashcatch Passive WPA Handshake Bridge**
   - Path: `generic/external/hashcatch_bridge.py`
   - Purely passive WPA/WPA2 handshake capture using hashcatch (C binary). Hops channels and saves EAPOL handshakes to files without transmitting. Output compatible with aircrack-ng and hashcat (mode 2500/
   - Devices: wifi, 802.11 WPA/WPA2 EAPOL

33. **Kismet Wardriving Bridge**
   - Path: `generic/external/kismet_bridge.py`
   - Bridge for Kismet wireless survey tool. Start Kismet in wardrive mode for optimized AP mapping, parse kismetdb databases, export to WiGLE CSV for upload, and KML for map visualization.
   - Devices: wifi, bluetooth, 802.11

34. **OT Protocol Tools Bridge**
   - Path: `generic/external/ot_protocol_bridge.py`
   - Orquestra ferramentas em submodules/OT: isf (Industrial Exploitation Framework / icssploit), ModBusSploit (console e módulos Modbus TCP: scan, read/write, DoS, ARP MITM) e BusPwn (Flask + pymodbus). N
   - Devices: ot, ics, modbus, plc, wifi

35. **OneShot Bridge**
   - Path: `generic/external/oneshot_bridge.py`
   - WPS Pixie Dust, brute force online de PIN e WPS PBC via OneShot (subprocess), usando wpa_supplicant em modo gerenciado — sem monitor mode. Suporta lista vulnwsc.txt, WPSpin e flags -K / -B / --pbc.
   - Devices: wifi, wps

36. **Proxmark3 RFID/NFC Bridge**
   - Path: `generic/external/proxmark_rfid_bridge.py`
   - Bridge for Proxmark3 RFID/NFC research tool. Supports Mifare Classic key recovery (MFOC/MFCUK/darkside), tag cloning, emulation, brute-force, NFC relay, and LF/HF identification. Covers EM4100, T5577,
   - Devices: rfid, nfc, mifare, hid

37. **Pwnagotchi WPA Handshake Bridge**
   - Path: `generic/external/pwnagotchi_bridge.py`
   - Interfaces with a Pwnagotchi device (RPi + AI) for autonomous WPA handshake harvesting. Modes: status (read device JSON API), pull_handshakes (scp/rsync .pcap from device), crack (hcxpcapngtool + hash
   - Devices: wifi, 802.11 WPA2 EAPOL handshake

38. **Reaver / Wash / Pixiewps Bridge**
   - Path: `generic/external/reaver_bridge.py`
   - WPS: brute force de PIN e Pixie Dust via reaver (GPL-2.0), varredura WPS via wash, recuperação offline via pixiewps (GPL-3.0). Somente subprocess.
   - Devices: wifi, 802.11 WPS

39. **Rogue Evil Twin Bridge**
   - Path: `generic/external/rogue_bridge.py`
   - Orquestração de evil twin via processo externo (GPL-3.0): open/WEP/WPA/WPA-EAP, hostapd, DHCP, FreeRADIUS, certificados, Responder, sslsplit e Modlishka — invocado somente como subprocess.
   - Devices: wifi, evil_twin

40. **Router Firmware Analysis Bridge**
   - Path: `generic/external/router_firmware_bridge.py`
   - Orquestra ferramentas em submodules/IoT/third-party-router-poc: AESCrypt2 (C) para decrypt de config Huawei, HuaweiPasswordTool (C++) para formato de senha, hwfw-tool (Python 2) unpack/pack de firmwar
   - Devices: router, huawei, firmware, iot

41. **SigFox + LoRaWAN Attack Bridge**
   - Path: `generic/external/sigfox_lorawan_bridge.py`
   - Security research bridge for LPWAN protocols. SigFox: replay attacks (12-bit SN vulnerability), MAC tag forgery (O(1) complexity), SN overflow DoS, downlink replay. LoRaWAN: packet sniffing, join-requ
   - Devices: sigfox, lorawan, lpwan

42. **SniffAir Passive Wi-Fi Recon Bridge**
   - Path: `generic/external/sniffair_passive_recon.py`
   - Passive Wi-Fi reconnaissance using SniffAir: captures probe requests, beacons, and EAP authentication frames. Modules: Auto_EAP (rogue RADIUS for PEAP/MSCHAPv2 capture), Auto_PSK (WPA handshake), Hand
   - Devices: wifi, 802.11 passive recon EAP WPA

43. **Social / Web OSINT Bridge**
   - Path: `generic/external/social_recon_bridge.py`
   - Reconhecimento OSINT para campanhas Wi‑Fi autorizadas: consulta social via RapidAPI (social-search e similares), extração léxica de site com cewler (subprocess) e geração de wordlist a partir de perfi
   - Devices: osint, wifi_workflow

44. **Wifiphisher Bridge**
   - Path: `generic/external/wifiphisher_bridge.py`
   - Evil twin + credential phishing via Wifiphisher (GPL-3.0 subprocess). Supports deauth, known-beacons, lure10, WPS-PBC, and 4 built-in phishing scenarios (firmware-upgrade, oauth-login, plugin_update, 
   - Devices: wifi

45. **Wifite2 Bridge**
   - Path: `generic/external/wifite2_bridge.py`
   - Orquestração de auditoria Wi‑Fi via Wifite2 (GPL-2.0 subprocess): WPA (handshake + crack), PMKID, WPS Pixie / PIN brute, WEP, filtros de alvo, 5 GHz, --kill, verbose e wordlist customizada.
   - Devices: wifi

46. **Wireless tool prerequisite audit**
   - Path: `generic/external/wireless_tool_prereq_audit.py`
   - Checks PATH for aircrack-ng suite, hcxtools, hashcat, bettercap, tshark. Use before wardriving / lab capture pipelines.
   - Devices: Workstation / Kali / WSL lab host

47. **Wirespy Wi-Fi Monitor Bridge**
   - Path: `generic/external/wirespy_bridge.py`
   - Automates Wi-Fi monitor mode, channel hopping, SSID discovery, and rogue AP creation via the wirespy Bash script (subprocess). Useful for quick Wi-Fi survey and evil-twin setup automation.
   - Devices: wifi, 802.11 monitor recon

48. **bettercap Bridge**
   - Path: `generic/external/bettercap_bridge.py`
   - Orquestra bettercap (GPL-3.0 subprocess): wifi.recon, wifi.deauth, wifi.assoc (PMKID), handshake para arquivo, arp.spoof/dns.spoof com net.sniff, http.proxy/https.proxy (via -eval), ble.recon, caplets
   - Devices: wifi, ble, lan

49. **hcxdumptool Live PMKID/EAPOL Capture Bridge**
   - Path: `generic/external/hcxdumptool_live_bridge.py`
   - Live Wi-Fi capture using hcxdumptool: PMKID from 802.11 association frames and 4-way EAPOL handshakes, written to pcapng. Output fed directly to hcxpcapngtool + hashcat (mode 22000/22001). Complements
   - Devices: wifi, 802.11 WPA2/WPA3 PMKID/EAPOL

50. **hcxtools PCAP bridge**
   - Path: `generic/external/hcx_toolchain_bridge.py`
   - Invokes hcxpcapngtool (preferred) or hcxpcaptool on a WPA/WPA2/WPA3 capture to emit hashcat-compatible lines (22000 for EAPOL, 22001 for PMKID). Also supports hcxhashtool for format conversion and qua
   - Devices: 802.11 WPA2/WPA3-transition PCAP/PCAPNG

51. **hostapd-WPE EAP Harvest Bridge**
   - Path: `generic/external/hostapd_wpe_bridge.py`
   - Starts a rogue WPA2-Enterprise AP using hostapd-WPE to capture EAP credentials (PEAP/MSCHAPv2, EAP-TTLS, LEAP, EAP-MD5). Writes captured challenge-response hashes to a log file for offline cracking (h
   - Devices: wifi, 802.11 WPA2-Enterprise EAP

52. **mdk4 Bridge**
   - Path: `generic/external/mdk4_bridge.py`
   - Invoca mdk4 (GPL-3.0) como subprocesso: beacon flood (b), auth DoS (a), probe/SSID bruteforce (p), deauth (d), Michael TKIP shutdown (m), EAPOL start/logoff flood (e), WIDS confusion (w), 802.11 fuzze
   - Devices: wifi

53. **wifipumpkin3 Bridge**
   - Path: `generic/external/wifipumpkin3_bridge.py`
   - Advanced rogue AP framework via wifipumpkin3 (Apache-2.0 subprocess). Supports captiveflask, Phishkin3 (MFA phishing), EvilQR3 (QR phishing), KARMA mode, Responder, Sniffkin3, PumpkinProxy, and REST A
   - Devices: wifi

### pcap (15)

54. **PCAP AP & Station Mapper**
   - Path: `generic/pcap/pcap_ap_station_mapper.py`
   - Offline analysis of PCAP/PCAPNG captures to enumerate access points (BSSID, SSID, channel, encryption) and client stations (probed SSIDs, associated BSSID, data frames). Useful after wardriving captur
   - Devices: Any 802.11 wireless capture

55. **PCAP BLE / HCI advertising survey**
   - Path: `generic/pcap/pcap_ble_advertising_survey.py`
   - Iterates packets counting Scapy BTLE/HCI layer names — useful for Ubertooth, nRF Sniffer, or BlueZ *hcidump* exports. Pair with live `generic/bluetooth/btle_*` modules on Linux.
   - Devices: BLE HCI / sniffer PCAP

56. **PCAP EAPOL 4-way handshake survey**
   - Path: `generic/pcap/pcap_eapol_survey.py`
   - Offline analysis: classify EAPOL-Key frames (M1–M4), track nonces and replay counters, emit KRACK-family hints (CVE-2017-13077 …). Complements hashcat (mode 22000/22001) and aircrack-ng cracking workf
   - CVEs: CVE-2017-13077
   - Devices: 802.11 WPA2/WPA3-transition captures

57. **PCAP GTK RNG Weakness Analyzer**
   - Path: `generic/pcap/pcap_rng_gtk_predictor.py`
   - Extracts GTK values from EAPOL Group Key Handshake (Group Message 1) in PCAP captures and analyzes entropy, byte distribution, and sequential/repeated patterns. Detects predictable GTK generation asso
   - CVEs: CVE-2017-6956
   - Devices: wifi, 802.11 WPA/WPA2 Group Key Handshake captures

58. **PCAP Hole196 GTK Abuse Detector**
   - Path: `generic/pcap/pcap_hole196_detector.py`
   - Scans PCAP/PCAPNG captures for indicators of Hole196 (GTK misuse) attacks: group-addressed data frames with unicast destination, ARP packets from unexpected sources (GTK-based ARP spoofing), transmitt
   - Devices: wifi, 802.11 WPA2/WPA captures

59. **PCAP Offline Credential Sniffer**
   - Path: `generic/pcap/pcap_credential_sniffer.py`
   - Offline extraction of cleartext credentials from PCAP/PCAPNG captures. Detects HTTP Basic/Form auth, FTP USER/PASS, Telnet logins and SNMP community strings.
   - Devices: Any network capture with cleartext protocols

60. **PCAP Offline EAP/WPE Credential Harvester**
   - Path: `generic/pcap/pcap_wpe_harvest.py`
   - Extracts EAP identities and challenge-response pairs from 802.1X authentication captures (WPA-Enterprise). Supports EAP-MD5, LEAP, MSCHAPv2, PEAP, EAP-TTLS, EAP-FAST. Produces hashcat-ready hashes for
   - Devices: Any WPA-Enterprise / 802.1X network capture

61. **PCAP Offline PMKID Attack (WPA/WPA2 Clientless)**
   - Path: `generic/pcap/pcap_pmkid_attack.py`
   - Extracts PMKID from EAPOL message 1 for clientless WPA/WPA2 offline attacks. No full 4-way handshake required. Outputs hashcat mode 22000 format and optionally runs hashcat.
   - Devices: Any WPA/WPA2-PSK network (most modern APs include PMKID)

62. **PCAP Offline TKIP/Michael Attack Analysis**
   - Path: `generic/pcap/pcap_tkip_downgrade.py`
   - Analyzes PCAP captures for TKIP vulnerabilities including Beck-Tews (QoS injection), Ohigashi-Morii (man-in-the-middle), and ChopChop (frame decryption) attack feasibility. Detects MIC failure deauths
   - Devices: Any WPA-TKIP or WPA2-TKIP mixed-mode network capture

63. **PCAP Offline WEP Key Recovery**
   - Path: `generic/pcap/pcap_wep_crack.py`
   - Extracts WEP IVs from PCAP captures and runs offline statistical key recovery using aircrack-ng (FMS/PTW/KoreK). Reports IV counts, weak IV statistics and crackability assessment.
   - Devices: Any WEP-encrypted 802.11 network capture

64. **PCAP Offline WPA/WPA2 Dictionary Attack**
   - Path: `generic/pcap/pcap_offline_wpa_crack.py`
   - Runs an offline dictionary attack against WPA/WPA2 handshakes captured in PCAP files. Supports aircrack-ng (default) and hashcat. Requires a wordlist and a capture file with a valid handshake.
   - Devices: Any WPA/WPA2 PSK network (captured handshake required)

65. **PCAP Offline WPA3 Dragonblood Analysis**
   - Path: `generic/pcap/pcap_dragonblood.py`
   - Analyzes WPA3 SAE (Dragonfly) handshakes in PCAP captures for Dragonblood vulnerabilities: CVE-2019-9494 (timing side-channel), CVE-2019-9496 (transition mode downgrade), weak group detection, and cac
   - CVEs: CVE-2019-9494, CVE-2019-9496
   - Devices: Any WPA3-SAE or WPA3-Transition mode network capture

66. **PCAP SQL Workspace**
   - Path: `generic/pcap/pcap_sql_workspace.py`
   - Creates and manages a SQLite workspace for PCAP ingestion metadata and analyst notes.
   - Devices: wifi, pcap

67. **PCAP TKIP Michael MIC Analysis**
   - Path: `generic/pcap/pcap_tkip_mic_analysis.py`
   - Scans PCAP/PCAPNG captures for TKIP parameters in RSN/WPA IEs, QoS data frames that could be Beck-Tews injection targets, deauthentication frames with reason 14 (MIC failure countermeasure), and other
   - Devices: wifi, 802.11 WPA-TKIP captures

68. **PCAP WPA/WPA2 Handshake Extractor**
   - Path: `generic/pcap/pcap_handshake_extractor.py`
   - Offline extraction of EAPOL 4-way handshakes from PCAP/PCAPNG captures. Exports usable handshakes to individual PCAP files ready for cracking with aircrack-ng or hashcat.
   - Devices: Any 802.11 WPA/WPA2 wireless capture

### wifi_lab (63)

69. **AP-less Client Attack (hcxdumptool)**
   - Path: `generic/wifi_lab/ap_less_client_attack.py`
   - Attack Wi-Fi clients directly without their AP. hcxdumptool responds to client probe requests with beacon/association frames, triggering PMKID or partial EAPOL exchanges. Works against roaming clients
   - Devices: wifi, 802.11 WPA/WPA2

70. **AWDL Attack (OpenDrop/Owl)**
   - Path: `generic/wifi_lab/awdl_attack.py`
   - AWDL/AirDrop lab workflows using OpenDrop and Owl as subprocesses. Supports discovery, send-test simulation, and AWDL stress modes in authorized environments.
   - Devices: wifi, awdl

71. **Adaptive Harvest**
   - Path: `generic/wifi_lab/adaptive_harvest.py`
   - Score-driven collection loop for handshake/PMKID captures with adaptive channel selection.
   - Devices: wifi

72. **Aircrack-ng Crack Engine**
   - Path: `generic/wifi_lab/aircrack_crack_engine.py`
   - Orchestrates aircrack-ng for WPA/WPA2 dictionary attacks and airolib-ng PMK database precomputation. Modes: dict_crack (wordlist attack against .cap/.pcap), pmk_build (airolib-ng import + batch), pmk_
   - Devices: wifi, 802.11

73. **Auth/Assoc Flood**
   - Path: `generic/wifi_lab/auth_flood.py`
   - Exhaust AP resources via mass authentication/association requests: random MAC auth flood (mdk4), AMOK mode, EAPOL-Start flood, and CTS/NAV reservation attacks.
   - Devices: wifi

74. **Beacon Flood Advanced**
   - Path: `generic/wifi_lab/beacon_flood_advanced.py`
   - Flood the RF spectrum with fake beacon frames: random SSIDs, AP cloning, wordlist-based SSIDs, and channel-targeted floods. Uses Scapy, mdk3, or mdk4 as backend.
   - Devices: wifi

75. **CSA Multi-Channel MitM / PNL Harvester**
   - Path: `generic/wifi_lab/csa_mc_mitm_attack.py`
   - Inject fake CSA (Channel Switch Announcement) frames to steer clients to a rogue AP channel (MC-MitM-IV). Also harvests Preferred Network Lists from client probe requests, and floods known-beacon SSID
   - Devices: wifi, 802.11

76. **Captive Portal Engine**
   - Path: `generic/wifi_lab/captive_portal_engine.py`
   - Evil twin captive portal with hostapd AP, dnsmasq DNS redirect, and built-in HTTP server. 23 built-in i18n templates (11 languages): social media (Facebook, Instagram, X, LinkedIn), services (Microsof
   - Devices: wifi, 802.11

77. **Captive portal (modern lab UI)**
   - Path: `generic/wifi_lab/captive_portal_modern_lab.py`
   - Bindable HTTP portal logging form posts — intended with dnsmasq address=/#/ on a dedicated evil-twin NIC. No TLS (use reverse proxy if needed).
   - Devices: Isolated lab subnet

78. **Connectivity Portal**
   - Path: `generic/wifi_lab/connectivity_portal.py`
   - Smart captive portal with OS connectivity detection and automatic language detection (en, pt-br, pt-pt, es). Triggers native portal popup on Apple, Android, Windows, Firefox, Kindle, Samsung. 16+ vend
   - Devices: wifi

79. **DNS Spoof Engine**
   - Path: `generic/wifi_lab/dns_spoof_engine.py`
   - Native DNS spoofing engine using Scapy. Sniffs UDP port 53 on a controlled interface, matches queries against a configurable domain-to-IP map, and injects spoofed DNS A-record responses. Supports wild
   - Devices: wifi, 802.11, ethernet

80. **Deauth / CSA Suite**
   - Path: `generic/wifi_lab/deauth_csa_suite.py`
   - Deautenticação e desassociação 802.11 (aireplay-ng, Scapy, mdk4), anúncio de mudança de canal (CSA em beacon) e modos broadcast vs STA alvo, com hopping multi-canal (2.4 / 5 GHz). Exige interface em m
   - Devices: wifi

81. **Deauth Multi-Mode**
   - Path: `generic/wifi_lab/deauth_multimode.py`
   - Multi-strategy deauthentication: targeted, broadcast, multi-AP, channel-hopping, and PMF-aware modes. Uses aireplay-ng, mdk4, or Scapy as backend. All modes require monitor-mode interface in authorize
   - Devices: wifi

82. **Dragonblood WPA3-SAE Attack Suite**
   - Path: `generic/wifi_lab/dragonblood_suite.py`
   - Complete bridge for Dragonblood attacks against WPA3-SAE: timing side-channel (MODP), cache side-channel, password partitioning, SAE commit flood (DoS), EAP-pwd reflection/invalid curve. Also covers W
   - CVEs: CVE-2019-13377, CVE-2019-13456, CVE-2019-9494, CVE-2019-9495, CVE-2019-9496, CVE-2019-9497, CVE-2019-9498, CVE-2019-9499
   - Devices: wifi, 802.11 WPA3-SAE

83. **Dual-Band Evil Twin**
   - Path: `generic/wifi_lab/dualband_evil_twin.py`
   - Simultaneous 2.4/5 GHz evil twin: rogue AP on one band while deauthing target on both bands. Requires 2 Wi-Fi interfaces. Addresses Fluxion issue #1004 (5GHz deauth + 2.4GHz evil twin).
   - Devices: wifi

84. **EAP Relay / Enterprise Credential Attack**
   - Path: `generic/wifi_lab/eap_relay_attack.py`
   - Relay WPA2/WPA3-Enterprise EAP authentication via evil twin. Uses hostapd-mana for rogue AP + wpa_sycophant to relay EAP exchanges to the legitimate AP. Also supports standalone EAP username enumerati
   - Devices: wifi, 802.11 WPA2/WPA3-Enterprise

85. **Evil QR Attack**
   - Path: `generic/wifi_lab/evil_qr_attack.py`
   - Generate malicious QR codes for phishing: Wi-Fi auto-connect, captive portal redirect, session hijacking (WhatsApp/Discord), and custom URLs. Inspired by wifipumpkin3's EvilQR3.
   - Devices: wifi

86. **Evil Twin Advanced**
   - Path: `generic/wifi_lab/evil_twin_advanced.py`
   - Full evil twin workflow: AP cloning, rogue AP (hostapd), DHCP/DNS (dnsmasq), captive portal with multiple phishing templates (ISP, firmware, OAuth, hotel, VPN, Network Manager), credential capture. Op
   - Devices: wifi

87. **Evil twin lab runbook**
   - Path: `generic/wifi_lab/evil_twin_workflow.py`
   - Prints ordered steps and example hostapd/dnsmasq snippets; optional call into aireplay-ng barrage helper binary.
   - Devices: Authorised isolated RF bench

88. **Evil twin — 6× hostapd templates**
   - Path: `generic/wifi_lab/evil_twin_hostapd_templates.py`
   - Generates configuration stubs including WPA3 transition (mixed) for studying downgrade paths alongside open/WPA2/SAE/OWE sketches.
   - Devices: Authorised RF bench + compatible NIC

89. **Evilginx prerequisite pointer**
   - Path: `generic/wifi_lab/evilginx_prereq_pointer.py`
   - Locates ``evilginx`` on PATH and references the upstream project; use only in isolated phishing/MFA labs with written consent.
   - Devices: Lab attacker host

90. **FragAttacks (CVE-2020-24586..26146)**
   - Path: `generic/wifi_lab/fragattacks.py`
   - 802.11 fragmentation and aggregation attack primitives. Fragment cache poisoning, mixed-key fragment reassembly, A-MSDU injection via EAPOL, broadcast fragment cache attacks, and PN/IV reuse detection
   - CVEs: CVE-2020-24586, CVE-2020-24587, CVE-2020-24588, CVE-2020-26144, CVE-2020-26146
   - Devices: wifi

91. **GPS wardriving NMEA → NDJSON**
   - Path: `generic/wifi_lab/gps_wardriving_ndjson.py`
   - Extracts coarse position rows for correlating with Wi-Fi/BLE logs.
   - Devices: NMEA log file

92. **Handshake Snooper**
   - Path: `generic/wifi_lab/handshake_snooper.py`
   - Automated WPA handshake capture: monitor mode, target scan, deauth to force re-auth, EAPOL capture, and handshake verification via aircrack-ng/cowpatty. Inspired by Fluxion's Handshake Snooper.
   - Devices: wifi

93. **Hashcat GPU/CPU orchestrator (WPA modes)**
   - Path: `generic/wifi_lab/hashcat_gpu_orchestrator.py`
   - Builds a hashcat argv for mode 22000/2500-class WPA material; prints devices (-I) and runs or dry-runs attack.
   - Devices: Cracking workstation

94. **KARMA / MANA Attack**
   - Path: `generic/wifi_lab/karma_mana_attack.py`
   - Rogue AP that responds to all probe requests, impersonating any SSID the client searches for. Supports KARMA basic, MANA loud, targeted KARMA, and MANA-EAP for 802.1X credential capture. Requires host
   - Devices: wifi

95. **KR00K Attack (CVE-2019-15126)**
   - Path: `generic/wifi_lab/kr00k_attack.py`
   - Exploits Broadcom/Cypress Wi-Fi chip flaw: after deauth, buffered frames are transmitted encrypted with an all-zero Temporal Key. Captures CCMP frames and decrypts them without the WPA2 password. Nati
   - CVEs: CVE-2019-15126
   - Devices: wifi

96. **KRACK Attack (CVE-2017-13077..13088)**
   - Path: `generic/wifi_lab/krack_attack.py`
   - Key Reinstallation Attacks on WPA2. Detects and exploits nonce reuse in the 4-way handshake (Message 3 replay), group key handshake (group PN reset), and FT reassociation. Passive monitoring for IV/PN
   - CVEs: CVE-2017-13077
   - Devices: wifi

97. **MFA Phishing Portal**
   - Path: `generic/wifi_lab/mfa_phishing_portal.py`
   - Real-time MFA phishing via captive portal: local HTML clone with MFA field, external proxy (evilginx-style), or cloud redirect (Phishkin3-style). Captures password + MFA token/push approval. Includes 
   - Devices: wifi

98. **MITM Wi-Fi Bridge**
   - Path: `generic/wifi_lab/mitm_wifi_bridge.py`
   - Man-in-the-Middle via rogue AP bridge (NAT), ARP spoofing, DNS spoofing, or SSL stripping. Captures traffic and credentials from Wi-Fi clients. Requires two interfaces or upstream connection + betterc
   - Devices: wifi

99. **MoMo Integrated Attack**
   - Path: `generic/wifi_lab/momo_integrated_attack.py`
   - Integrated KARMA + PMKID-first + downgrade orchestration in a single authorized-lab workflow.
   - Devices: wifi

100. **PCAP RF anomaly scorer (+ optional ML)**
   - Path: `generic/wifi_lab/pcap_rf_anomaly_ml.py`
   - 802.11 management/data counters per file; optional IsolationForest when multiple PCAPs in a directory.
   - Devices: Offline PCAP/PCAPNG

101. **PCAP WPA handshake & PMKID validator**
   - Path: `generic/wifi_lab/pcap_wpa_handshake_validate.py`
   - Reports 4-way EAPOL progress per STA/BSSID, PMKID availability, and optional hc22000 export probe via hcxpcapngtool.
   - Devices: 802.11 WPA2 PCAP/PCAPNG

102. **PMK Pre-computation Pipeline**
   - Path: `generic/wifi_lab/pmk_precompute.py`
   - Build airolib-ng PMK databases or cowpatty rainbow tables for target ESSIDs. Pre-computing PMKs (PBKDF2-SHA1, 4096 iterations) converts the expensive hash step into a one-time cost, making subsequent 
   - Devices: wifi, 802.11 WPA/WPA2

103. **PMKID AutoPwn Pipeline**
   - Path: `generic/wifi_lab/pmkid_autopwn.py`
   - Automated WPA/WPA2 PMKID and EAPOL handshake capture via hcxdumptool, conversion to hashcat 22000 format via hcxpcapngtool, and GPU-accelerated offline crack via hashcat. Supports single-target (filte
   - Devices: wifi, 802.11 WPA/WPA2

104. **Packet Injection Lab**
   - Path: `generic/wifi_lab/packet_injection_lab.py`
   - Scapy-based 802.11 packet injection lab. Craft and inject data frames, ARP requests/replies, ICMP echo packets, custom hex payloads wrapped in Dot11 frames, or replay frames from a PCAP file. Requires
   - Devices: wifi, 802.11

105. **Pyrit GPU Bridge (WPA/WPA2)**
   - Path: `generic/wifi_lab/pyrit_gpu_bridge.py`
   - Bridge para computacao PBKDF2-SHA1 acelerada por GPU via Pyrit. Suporta benchmark, analise de capturas, ataques passthrough/batch/db, importacao de wordlists e pre-computacao de PMKs. Somente subproce
   - Devices: wifi, 802.11 WPA/WPA2

106. **RADIUS/EAP Credential Brute-force**
   - Path: `generic/wifi_lab/radius_credential_brute.py`
   - Online credential testing against WPA2/WPA3-Enterprise networks. Attempts EAP authentication (PEAP, TTLS, EAP-MD5) with candidate credentials via wpa_supplicant. Supports username enumeration, passwor
   - Devices: wifi, 802.11 WPA2/WPA3 Enterprise

107. **Responder Wi-Fi**
   - Path: `generic/wifi_lab/responder_wifi.py`
   - LLMNR/NBT-NS/mDNS poisoning via Responder on rogue AP interface. Captures NTLM hashes, HTTP credentials, and auth tokens from clients connected to evil twin. Requires Responder.py.
   - Devices: wifi

108. **SAE Timing Side-Channel Analysis (native)**
   - Path: `generic/wifi_lab/sae_timing_attack.py`
   - Measures SAE handshake timing to detect group-dependent variations that reveal password partition information. Captures SAE Authentication frames via Scapy and performs statistical analysis on commit/
   - CVEs: CVE-2019-13377, CVE-2019-9494
   - Devices: wifi, 802.11 WPA3 SAE

109. **SSID Confusion Attack (CVE-2023-52424)**
   - Path: `generic/wifi_lab/ssid_confusion.py`
   - Multi-Channel Man-in-the-Middle with SSID rewriting. Clones target AP beacon with a trusted SSID, injects CSA to force client migration, then relays traffic while maintaining the SSID illusion. Client
   - CVEs: CVE-2023-52424
   - Devices: wifi

110. **Selective Jammer**
   - Path: `generic/wifi_lab/selective_jammer.py`
   - Surgical deauthentication: target specific clients by MAC instead of broadcast. Whitelist, blacklist, or auto-new modes. Addresses Fluxion issue #329 (jam specific clients).
   - Devices: wifi

111. **TKIP Active Attack Suite**
   - Path: `generic/wifi_lab/tkip_attack_suite.py`
   - Active TKIP exploitation module covering Beck-Tews QoS injection, Vanhoef-Piessens extended injection, live/offline TKIP detection, and direct tkiptun-ng bridge. Supports info, beck_tews, vanhoef_pies
   - CVEs: CVE-2008-5230
   - Devices: wifi, 802.11 WPA-TKIP

112. **Transparent Proxy**
   - Path: `generic/wifi_lab/transparent_proxy.py`
   - Transparent proxy on rogue AP: HTTP inspection, JS/HTML injection, download spoofing, credential sniffing. Backends: mitmproxy, bettercap, or lightweight built-in. Inspired by wifipumpkin3's PumpkinPr
   - Devices: wifi

113. **WEP Complete Attack Suite**
   - Path: `generic/wifi_lab/wep_attack_suite.py`
   - Orchestrates all aireplay-ng WEP attack modes (ARP replay, chop-chop, fragmentation, caffe-latte, Hirte, interactive/P0841) while running airodump-ng for IV collection. Auto-triggers aircrack-ng when 
   - Devices: wifi, 802.11 WEP

114. **WPA Online Brute-force**
   - Path: `generic/wifi_lab/wpa_online_brute.py`
   - Test passwords online against a live AP. Works against WPA3-SAE (where offline attacks fail) and WPA2-PSK. Slow by nature (each attempt requires a full auth handshake), but the only option for properl
   - Devices: wifi, 802.11 WPA2/WPA3

115. **WPA3 Attack Suite**
   - Path: `generic/wifi_lab/wpa3_attack_suite.py`
   - Authorised-lab bridge: WPA3 transition downgrade (DragonShift / WPA3-Transition-mode-Downgrade-attack), SAE commit flood (dragon-drain, Nuseo1, sae_clogging_attack), CSA injection (Politician-style), 
   - Devices: wifi

116. **WPA3 SAE Commit Flood (native)**
   - Path: `generic/wifi_lab/wpa3_sae_flood_native.py`
   - Floods a WPA3 AP with SAE Authentication commit frames from random spoofed MACs, exhausting the SAE state machine. Targets both pure WPA3 (DoS) and WPA3-Transition mode APs (force WPA2 fallback). Nati
   - CVEs: CVE-2019-9494
   - Devices: wifi, 802.11 WPA3 SAE

117. **WPS Multi-Mode Attack**
   - Path: `generic/wifi_lab/wps_multimode.py`
   - WPS attack suite: pixie-dust offline PIN recovery (pixiewps), online PIN brute-force (reaver/bully), PBC window exploit, and null/empty PIN attacks. Includes WPS AP scanner (wash).
   - Devices: wifi

118. **Wardriving Deauth Loop**
   - Path: `generic/wifi_lab/wardriving_deauth_loop.py`
   - Automated wardriving pipeline with scan/deauth/capture rotations. Designed for authorized roaming assessments and handshake collection.
   - Devices: wifi

119. **Wi-Fi Frame Replay**
   - Path: `generic/wifi_lab/replay_attack.py`
   - Replay captured 802.11 frames: EAPOL (force re-auth), beacons (SSID spoof), authentication, probe responses, or arbitrary frames from PCAP. Uses Scapy for frame injection.
   - Devices: wifi

120. **Wi-Fi Security Analyzer (native)**
   - Path: `generic/wifi_lab/wifi_security_analyzer.py`
   - Passively scans Wi-Fi networks using Scapy beacon/probe-response sniffing. Parses RSN/WPA IEs to classify each BSS as WEP / WPA / WPA2-TKIP / WPA2-CCMP / WPA2-Enterprise / WPA3-SAE / WPA3-Transition /
   - Devices: wifi, 802.11 a/b/g/n/ac/ax

121. **WiFi Sniffer**
   - Path: `generic/wifi_lab/wifi_sniffer.py`
   - Traffic sniffer for rogue AP: captures HTTP forms, Basic Auth, FTP/POP3/IMAP cleartext creds, DNS queries, cookies, and EAPOL. Backends: scapy, tcpdump, tshark. Inspired by wifipumpkin3's Sniffkin3.
   - Devices: wifi

122. **WiGLE Export**
   - Path: `generic/wifi_lab/wigle_export.py`
   - Convert WXF wardrive data (airodump-ng CSV, kismetdb, PCAP) to WiGLE upload format (WigleWifi-1.4) and KML for Google Earth visualization. Supports GPS enrichment from NMEA or GPX files.
   - Devices: wifi, 802.11

123. **Wireless IDS (Baseline/Anomaly)**
   - Path: `generic/wifi_lab/wireless_ids.py`
   - Passive IDS helper that learns AP baseline from CSV scans and flags rogue/new BSSIDs for analyst review.
   - Devices: wifi

124. **Wireless research ecosystem (submodule) status**
   - Path: `generic/wifi_lab/research_ecosystem_status.py`
   - Maps GitHub WPA3/Wi-Fi research submodules to on-disk paths under the SafeLabs-style superproject layout.
   - Devices: Workstation with superproject checkout

125. **Wordlist orchestrator (Wi‑Fi / WPA lab)**
   - Path: `generic/wifi_lab/wordlist_orchestrator.py`
   - Modos static | osint | pattern | isp | combined | auto: localiza wordlists em submodules/Wordlists, invoca cewler/CeWL/wfh/pnwgen/crunch/BruteForge/Xfinity via subprocess, faz merge opcional com dedup
   - Devices: wifi, wpa_lab

126. **_disclaimer**
   - Path: `generic/wifi_lab/_disclaimer.py`

127. **_i18n_service**
   - Path: `generic/wifi_lab/_i18n_service.py`

128. **aireplay-ng deauth / disassoc barrage**
   - Path: `generic/wifi_lab/aireplay_deauth_barrage.py`
   - Runs repeated aireplay-ng -0 bursts; optional dual-target alternation (BSSID + STA) and parallel streams for stubborn clients. Requires monitor-mode interface + injection-capable driver.
   - Devices: Linux lab interface (monitor mode)

129. **hostapd rogue AP bridge**
   - Path: `generic/wifi_lab/rogue_ap_hostapd_bridge.py`
   - Writes hostapd.conf for AP mode (nl80211) and execs hostapd. Requires ap-mode capable NIC + correct driver.
   - Devices: Linux AP-capable WLAN

130. **mdk3 legacy bridge**
   - Path: `generic/wifi_lab/mdk3_bridge.py`
   - Invokes mdk3 <iface> <mode> [options]. Modes include b, a, p, d, m, x, w, f.
   - Devices: Linux monitor interface (legacy stacks)

131. **mdk4 attack bridge**
   - Path: `generic/wifi_lab/mdk4_bridge.py`
   - Runs mdk4 <iface> <mode> [options]. Common modes: d (deauth/disassoc), b (beacon flood), a (auth DoS), p (probing), g (WPA downgrade), m (Michael shutdown). See mdk4 --help <mode>.
   - Devices: Linux monitor interface + injection

### wordlist (1)

132. **Interactive Wordlist Generator**
   - Path: `generic/wordlist/wordlist_generator.py`
   - Generates custom password and username wordlists based on target profile (corporate or personal). Applies mutation rules (leet speak, case variations, number suffixes, date fragments, word combination
   - Devices: Any target — wordlist generation is target-independent

## Encoders (0)

## Payloads (0)

---

## CVE Master List (42)

| # | CVE ID | Modules |
|---:|---|---|
| 1 | CVE-2008-5230 | `generic/wifi_lab/tkip_attack_suite.py` |
| 2 | CVE-2017-0781 | `generic/bluetooth/blueborne_attack.py` |
| 3 | CVE-2017-0785 | `generic/bluetooth/blueborne_attack.py` |
| 4 | CVE-2017-1000251 | `generic/bluetooth/blueborne_attack.py` |
| 5 | CVE-2017-13077 | `generic/pcap/pcap_eapol_survey.py`, `generic/wifi_lab/krack_attack.py` |
| 6 | CVE-2017-6956 | `generic/pcap/pcap_rng_gtk_predictor.py` |
| 7 | CVE-2019-13377 | `generic/wifi_lab/dragonblood_suite.py`, `generic/wifi_lab/sae_timing_attack.py` |
| 8 | CVE-2019-13456 | `generic/wifi_lab/dragonblood_suite.py` |
| 9 | CVE-2019-15126 | `generic/wifi_lab/kr00k_attack.py` |
| 10 | CVE-2019-16336 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_baseband_attack.py` |
| 11 | CVE-2019-17060 | `generic/bluetooth/bt_baseband_attack.py` |
| 12 | CVE-2019-17061 | `generic/bluetooth/bt_baseband_attack.py` |
| 13 | CVE-2019-17071 | `generic/bluetooth/ble_sweyntooth_bridge.py` |
| 14 | CVE-2019-17516 | `generic/bluetooth/ble_sweyntooth_bridge.py` |
| 15 | CVE-2019-17517 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_baseband_attack.py` |
| 16 | CVE-2019-17518 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_baseband_attack.py` |
| 17 | CVE-2019-17519 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_baseband_attack.py` |
| 18 | CVE-2019-17520 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_baseband_attack.py` |
| 19 | CVE-2019-17521 | `generic/bluetooth/ble_sweyntooth_bridge.py` |
| 20 | CVE-2019-19194 | `generic/bluetooth/bt_baseband_attack.py` |
| 21 | CVE-2019-19195 | `generic/bluetooth/bt_baseband_attack.py` |
| 22 | CVE-2019-19196 | `generic/bluetooth/bt_baseband_attack.py` |
| 23 | CVE-2019-9494 | `generic/pcap/pcap_dragonblood.py`, `generic/wifi_lab/dragonblood_suite.py`, `generic/wifi_lab/sae_timing_attack.py`, `generic/wifi_lab/wpa3_sae_flood_native.py` |
| 24 | CVE-2019-9495 | `generic/wifi_lab/dragonblood_suite.py` |
| 25 | CVE-2019-9496 | `generic/pcap/pcap_dragonblood.py`, `generic/wifi_lab/dragonblood_suite.py` |
| 26 | CVE-2019-9497 | `generic/wifi_lab/dragonblood_suite.py` |
| 27 | CVE-2019-9498 | `generic/wifi_lab/dragonblood_suite.py` |
| 28 | CVE-2019-9499 | `generic/wifi_lab/dragonblood_suite.py` |
| 29 | CVE-2019-9506 | `generic/bluetooth/ble_sweyntooth_bridge.py`, `generic/bluetooth/bt_session_attack.py`, `generic/bluetooth/knob_attack_bridge.py` |
| 30 | CVE-2020-10135 | `generic/bluetooth/bias_attack_bridge.py`, `generic/bluetooth/bt_session_attack.py` |
| 31 | CVE-2020-15802 | `generic/bluetooth/ble_extra_attacks.py` |
| 32 | CVE-2020-24586 | `generic/wifi_lab/fragattacks.py` |
| 33 | CVE-2020-24587 | `generic/wifi_lab/fragattacks.py` |
| 34 | CVE-2020-24588 | `generic/wifi_lab/fragattacks.py` |
| 35 | CVE-2020-26144 | `generic/wifi_lab/fragattacks.py` |
| 36 | CVE-2020-26146 | `generic/wifi_lab/fragattacks.py` |
| 37 | CVE-2020-9770 | `generic/bluetooth/ble_extra_attacks.py` |
| 38 | CVE-2021-28139 | `generic/bluetooth/bt_baseband_attack.py` |
| 39 | CVE-2023-24023 | `generic/bluetooth/ble_bluffs_native.py`, `generic/bluetooth/bt_session_attack.py` |
| 40 | CVE-2023-45866 | `generic/bluetooth/bt_hid_injection.py` |
| 41 | CVE-2023-52424 | `generic/wifi_lab/ssid_confusion.py` |
| 42 | CVE-2024-23717 | `generic/bluetooth/bt_hid_injection.py` |

## CVEs by Vendor

| Vendor | CVE Count | CVE IDs |
|---|---:|---|
| bluetooth | 24 | CVE-2017-0781, CVE-2017-0785, CVE-2017-1000251, CVE-2019-16336, CVE-2019-17060, CVE-2019-17061, CVE-2019-17071, CVE-2019-17516, CVE-2019-17517, CVE-2019-17518, CVE-2019-17519, CVE-2019-17520, CVE-2019-17521, CVE-2019-19194, CVE-2019-19195, CVE-2019-19196, CVE-2019-9506, CVE-2020-10135, CVE-2020-15802, CVE-2020-9770, CVE-2021-28139, CVE-2023-24023, CVE-2023-45866, CVE-2024-23717 |
| pcap | 4 | CVE-2017-13077, CVE-2017-6956, CVE-2019-9494, CVE-2019-9496 |
| wifi_lab | 17 | CVE-2008-5230, CVE-2017-13077, CVE-2019-13377, CVE-2019-13456, CVE-2019-15126, CVE-2019-9494, CVE-2019-9495, CVE-2019-9496, CVE-2019-9497, CVE-2019-9498, CVE-2019-9499, CVE-2020-24586, CVE-2020-24587, CVE-2020-24588, CVE-2020-26144, CVE-2020-26146, CVE-2023-52424 |

---

> Generated by tools/generate_full_catalog.py