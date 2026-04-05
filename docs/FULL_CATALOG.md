# wirelessxpl-Forge — Full Module Catalog

> Generated: 2026-04-05T05:46:53.913356+00:00
> Author: Andre Henrique (@mrhenrike) | Uniao Geek

## Summary

| Category | Modules | Vendor / group buckets |
|---|---:|---:|
| Exploits | 0 | 0 |
| Credential Modules | 0 | 0 |
| Scanners | 0 | 0 |
| Generic Modules | 19 | 5 |
| Encoders | 13 | 3 |
| Payloads | 32 | 9 |
| **Total Modules** | **64** | — |
| Distinct CVEs | 3 | — |

## Program footprint

Approximate on-disk size (file bytes only; binary prefixes). Walk skips caches such as ``__pycache__`` and ``.git``.

| Metric | Value |
|---|---|
| Repository root | `D:/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge` |
| Total file bytes | 117.90 MiB |
| Files (repo walk) | 2636 |
| Files under ``wirelessxpl/`` | 1955 |

### Largest top-level paths (repository)

| Path | Size | Share of total |
|---|---:|---:|
| `wirelessxpl` | 113.11 MiB | 95.9% |
| `docs` | 4.10 MiB | 3.5% |
| `tests` | 319.00 KiB | 0.3% |
| `tools` | 293.14 KiB | 0.2% |
| `routerxpl.egg-info` | 58.36 KiB | 0.0% |
| `(repo root files)` | 39.48 KiB | 0.0% |

### ``wirelessxpl/`` breakdown (first-level folders)

| Area | Size | Share of total |
|---|---:|---:|
| `resources` | 112.73 MiB | 95.6% |
| `core` | 218.75 KiB | 0.2% |
| `modules` | 132.77 KiB | 0.1% |
| `(wirelessxpl root files)` | 26.18 KiB | 0.0% |
| `libs` | 13.68 KiB | 0.0% |

### ``wirelessxpl/resources/*`` (largest direct children)

| Subfolder | Size | Share of total |
|---|---:|---:|
| `mibs` | 83.21 MiB | 70.6% |
| `catalogs` | 24.92 MiB | 21.1% |
| `vendors` | 4.52 MiB | 3.8% |
| `wordlists` | 44.91 KiB | 0.0% |
| `arsenal` | 30.34 KiB | 0.0% |
| `ssh_keys` | 9.89 KiB | 0.0% |
| `ml` | 1.22 KiB | 0.0% |

### First-party Python files (``.py`` count, excluding ``__pycache__``)

| Tree | Files |
|---|---:|
| `wirelessxpl/core` | 44 |
| `wirelessxpl/modules` | 84 |
| `wirelessxpl/libs` | 5 |
| `tools` | 40 |
| `wxf.py` | 1 |

---

## Exploits (0)

## Credential Modules (0)

## Scanners (0)

## Generic Modules (19)

### bluetooth (3)

1. **Bluetooth LE Enumerate**
   - Path: `generic/bluetooth/btle_enumerate.py`
   - Enumerating services and characteristics of a given Bluetooth Low Energy devices.

2. **Bluetooth LE Scan**
   - Path: `generic/bluetooth/btle_scan.py`
   - Scans for Bluetooth Low Energy devices.

3. **Bluetooth LE Write**
   - Path: `generic/bluetooth/btle_write.py`
   - Writes data to target Bluetooth Low Energy device to given characteristic.

### cve (1)

4. **CVE Lookup by Banner / Vendor / Product**
   - Path: `generic/cve/cve_lookup.py`
   - Queries the embedded CVE database for known vulnerabilities matching a target's vendor, product, version or raw banner. Classifies each CVE as REMOTE (exploitable in-tree via wxf), LOCAL or PHYSICAL. 
   - Devices: Wireless lab — subset emphasises 802.11/WPA/WPA3/BLE-adjacent CVE strings

### external (3)

5. **Bruce ESP32 firmware (lab notes)**
   - Path: `generic/external/bruce_esp32_lab_notes.py`
   - Pointers to BruceDevices firmware: wardriving, raw sniffer hooks, deauth/evil-portal patterns on dedicated hardware. Export PCAP to this framework's ``generic/pcap/*`` modules for offline WPA3 / EAPOL
   - Devices: ESP32 / Cardputer / M5Stack (user hardware)

6. **Wireless tool prerequisite audit**
   - Path: `generic/external/wireless_tool_prereq_audit.py`
   - Checks PATH for aircrack-ng suite, hcxtools, hashcat, bettercap, tshark. Use before wardriving / lab capture pipelines.
   - Devices: Workstation / Kali / WSL lab host

7. **hcxtools PCAP bridge**
   - Path: `generic/external/hcx_toolchain_bridge.py`
   - Invokes hcxpcapngtool (preferred) or hcxpcaptool on a WPA/WPA2 capture to emit hashcat-compatible lines (e.g. 22000). Does not ship hcxtools.
   - Devices: 802.11 WPA2/WPA3-transition PCAP/PCAPNG

### pcap (11)

8. **PCAP AP & Station Mapper**
   - Path: `generic/pcap/pcap_ap_station_mapper.py`
   - Offline analysis of PCAP/PCAPNG captures to enumerate access points (BSSID, SSID, channel, encryption) and client stations (probed SSIDs, associated BSSID, data frames). Useful after wardriving captur
   - Devices: Any 802.11 wireless capture

9. **PCAP BLE / HCI advertising survey**
   - Path: `generic/pcap/pcap_ble_advertising_survey.py`
   - Iterates packets counting Scapy BTLE/HCI layer names — useful for Ubertooth, nRF Sniffer, or BlueZ *hcidump* exports. Pair with live `generic/bluetooth/btle_*` modules on Linux.
   - Devices: BLE HCI / sniffer PCAP

10. **PCAP EAPOL 4-way handshake survey**
   - Path: `generic/pcap/pcap_eapol_survey.py`
   - Offline analysis: classify EAPOL-Key frames (M1–M4), track nonces and replay counters, emit KRACK-family hints (CVE-2017-13077 …). Complements hashcat (mode 22000/22001) and aircrack-ng cracking workf
   - CVEs: CVE-2017-13077
   - Devices: 802.11 WPA2/WPA3-transition captures

11. **PCAP Offline Credential Sniffer**
   - Path: `generic/pcap/pcap_credential_sniffer.py`
   - Offline extraction of cleartext credentials from PCAP/PCAPNG captures. Detects HTTP Basic/Form auth, FTP USER/PASS, Telnet logins and SNMP community strings.
   - Devices: Any network capture with cleartext protocols

12. **PCAP Offline EAP/WPE Credential Harvester**
   - Path: `generic/pcap/pcap_wpe_harvest.py`
   - Extracts EAP identities and challenge-response pairs from 802.1X authentication captures (WPA-Enterprise). Supports EAP-MD5, LEAP, MSCHAPv2, PEAP, EAP-TTLS, EAP-FAST. Produces hashcat-ready hashes for
   - Devices: Any WPA-Enterprise / 802.1X network capture

13. **PCAP Offline PMKID Attack (WPA/WPA2 Clientless)**
   - Path: `generic/pcap/pcap_pmkid_attack.py`
   - Extracts PMKID from EAPOL message 1 for clientless WPA/WPA2 offline attacks. No full 4-way handshake required. Outputs hashcat mode 22000 format and optionally runs hashcat.
   - Devices: Any WPA/WPA2-PSK network (most modern APs include PMKID)

14. **PCAP Offline TKIP/Michael Attack Analysis**
   - Path: `generic/pcap/pcap_tkip_downgrade.py`
   - Analyzes PCAP captures for TKIP vulnerabilities including Beck-Tews (QoS injection), Ohigashi-Morii (man-in-the-middle), and ChopChop (frame decryption) attack feasibility. Detects MIC failure deauths
   - Devices: Any WPA-TKIP or WPA2-TKIP mixed-mode network capture

15. **PCAP Offline WEP Key Recovery**
   - Path: `generic/pcap/pcap_wep_crack.py`
   - Extracts WEP IVs from PCAP captures and runs offline statistical key recovery using aircrack-ng (FMS/PTW/KoreK). Reports IV counts, weak IV statistics and crackability assessment.
   - Devices: Any WEP-encrypted 802.11 network capture

16. **PCAP Offline WPA/WPA2 Dictionary Attack**
   - Path: `generic/pcap/pcap_offline_wpa_crack.py`
   - Runs an offline dictionary attack against WPA/WPA2 handshakes captured in PCAP files. Supports aircrack-ng (default) and hashcat. Requires a wordlist and a capture file with a valid handshake.
   - Devices: Any WPA/WPA2 PSK network (captured handshake required)

17. **PCAP Offline WPA3 Dragonblood Analysis**
   - Path: `generic/pcap/pcap_dragonblood.py`
   - Analyzes WPA3 SAE (Dragonfly) handshakes in PCAP captures for Dragonblood vulnerabilities: CVE-2019-9494 (timing side-channel), CVE-2019-9496 (transition mode downgrade), weak group detection, and cac
   - CVEs: CVE-2019-9494, CVE-2019-9496
   - Devices: Any WPA3-SAE or WPA3-Transition mode network capture

18. **PCAP WPA/WPA2 Handshake Extractor**
   - Path: `generic/pcap/pcap_handshake_extractor.py`
   - Offline extraction of EAPOL 4-way handshakes from PCAP/PCAPNG captures. Exports usable handshakes to individual PCAP files ready for cracking with aircrack-ng or hashcat.
   - Devices: Any 802.11 WPA/WPA2 wireless capture

### wordlist (1)

19. **Interactive Wordlist Generator**
   - Path: `generic/wordlist/wordlist_generator.py`
   - Generates custom password and username wordlists based on target profile (corporate or personal). Applies mutation rules (leet speak, case variations, number suffixes, date fragments, word combination
   - Devices: Any target — wordlist generation is target-independent

## Encoders (13)

### perl (4)

1. **Perl Base64 Encoder**
   - Path: `encoders/perl/base64.py`
   - Module encodes PERL payload to Base64 format.

2. **Perl Hex Encoder**
   - Path: `encoders/perl/hex.py`
   - Module encodes PERL payload to Hex format.

3. **Perl ROT13 Encoder**
   - Path: `encoders/perl/rot13.py`
   - Module encodes PERL payload to ROT13 format.

4. **Perl URL Encoder**
   - Path: `encoders/perl/url.py`
   - Module encodes PERL payload to URL-encoded format.

### php (4)

5. **PHP Base64 Encoder**
   - Path: `encoders/php/base64.py`
   - Module encodes PHP payload to Base64 format.

6. **PHP Hex Encoder**
   - Path: `encoders/php/hex.py`
   - Module encodes PHP payload to Hex format.

7. **PHP ROT13 Encoder**
   - Path: `encoders/php/rot13.py`
   - Module encodes PHP payload to ROT13 format.

8. **PHP URL Encoder**
   - Path: `encoders/php/url.py`
   - Module encodes PHP payload to URL-encoded format.

### python (5)

9. **Python Base32 Encoder**
   - Path: `encoders/python/base32.py`
   - Module encodes Python payload to Base32 format.

10. **Python Base64 Encoder**
   - Path: `encoders/python/base64.py`
   - Module encodes Python payload to Base64 format.

11. **Python Hex Encoder**
   - Path: `encoders/python/hex.py`
   - Module encodes Python payload to Hex format.

12. **Python ROT13 Encoder**
   - Path: `encoders/python/rot13.py`
   - Module encodes Python payload to ROT13 format.

13. **Python URL Encoder**
   - Path: `encoders/python/url.py`
   - Module encodes Python payload to URL-encoded format.

## Payloads (32)

### armle (2)

1. **ARMLE Bind TCP**
   - Path: `payloads/armle/bind_tcp.py`
   - Creates interactive tcp bind shell for ARMLE architecture.

2. **ARMLE Reverse TCP**
   - Path: `payloads/armle/reverse_tcp.py`
   - Creates interactive tcp reverse shell for ARMLE architecture.

### cmd (14)

3. **Awk Bind TCP**
   - Path: `payloads/cmd/awk_bind_tcp.py`
   - Creates an interactive tcp bind shell by using (g)awk.

4. **Awk Bind UDP**
   - Path: `payloads/cmd/awk_bind_udp.py`
   - Creates an interactive udp bind shell by using (g)awk.

5. **Awk Reverse TCP**
   - Path: `payloads/cmd/awk_reverse_tcp.py`
   - Creates an interactive tcp reverse shell by using (g)awk.

6. **Bash Reverse TCP**
   - Path: `payloads/cmd/bash_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using bash.

7. **Netcat Bind TCP**
   - Path: `payloads/cmd/netcat_bind_tcp.py`
   - Creates interactive tcp bind shell by using netcat.

8. **Netcat Reverse TCP**
   - Path: `payloads/cmd/netcat_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using netcat.

9. **PHP Bind TCP One-Liner**
   - Path: `payloads/cmd/php_bind_tcp.py`
   - Creates interactive tcp bind shell by using php one-liner.

10. **PHP Reverse TCP One-Liner**
   - Path: `payloads/cmd/php_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using php one-liner.

11. **Perl Bind TCP One-Liner**
   - Path: `payloads/cmd/perl_bind_tcp.py`
   - Creates interactive tcp bind shell by using perl one-liner.

12. **Perl Reverse TCP One-Liner**
   - Path: `payloads/cmd/perl_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using perl one-liner.

13. **Python Bind UDP One-Liner**
   - Path: `payloads/cmd/python_bind_udp.py`
   - Creates interactive udp bind shell by using python one-liner.

14. **Python Reverse TCP One-Liner**
   - Path: `payloads/cmd/python_bind_tcp.py`
   - Creates interactive tcp bind shell by using python one-liner.

15. **Python Reverse TCP One-Liner**
   - Path: `payloads/cmd/python_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using python one-liner.

16. **Python Reverse UDP One-Liner**
   - Path: `payloads/cmd/python_reverse_udp.py`
   - Creates interactive udp reverse shell by using python one-liner.

### mipsbe (2)

17. **MIPSBE Bind TCP**
   - Path: `payloads/mipsbe/bind_tcp.py`
   - Creates interactive tcp bind shell for MIPSBE architecture.

18. **MIPSBE Reverse TCP**
   - Path: `payloads/mipsbe/reverse_tcp.py`
   - Creates interactive tcp reverse shell for MIPSBE architecture.

### mipsle (2)

19. **MIPSLE Bind TCP**
   - Path: `payloads/mipsle/bind_tcp.py`
   - Creates interactive tcp bind shell for MIPSLE architecture.

20. **MIPSLE Reverse TCP**
   - Path: `payloads/mipsle/reverse_tcp.py`
   - Creates interactive tcp reverse shell for MIPSLE architecture.

### perl (2)

21. **Perl Bind TCP**
   - Path: `payloads/perl/bind_tcp.py`
   - Creates interactive tcp bind shell by using perl.

22. **Perl Reverse TCP**
   - Path: `payloads/perl/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using perl.

### php (2)

23. **PHP Bind TCP**
   - Path: `payloads/php/bind_tcp.py`
   - Creates interactive tcp bind shell by using php.

24. **PHP Reverse TCP**
   - Path: `payloads/php/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using php.

### python (4)

25. **Python Bind TCP**
   - Path: `payloads/python/bind_tcp.py`
   - Creates interactive tcp bind shell by using python.

26. **Python Bind UDP**
   - Path: `payloads/python/bind_udp.py`
   - Creates interactive udp bind shell by using python.

27. **Python Reverse TCP**
   - Path: `payloads/python/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using python.

28. **Python Reverse UDP**
   - Path: `payloads/python/reverse_udp.py`
   - Creates interactive udp reverse shell by using python.

### x64 (2)

29. **X64 Bind TCP**
   - Path: `payloads/x64/bind_tcp.py`
   - Creates interactive tcp bind shell for X64 architecture.

30. **X64 Reverse TCP**
   - Path: `payloads/x64/reverse_tcp.py`
   - Creates interactive tcp reverse shell for X64 architecture.

### x86 (2)

31. **X86 Bind TCP**
   - Path: `payloads/x86/bind_tcp.py`
   - Creates interactive tcp bind shell for X86 architecture.

32. **X86 Reverse TCP**
   - Path: `payloads/x86/reverse_tcp.py`
   - Creates interactive tcp reverse shell for X86 architecture.

---

## CVE Master List (3)

| # | CVE ID | Modules |
|---:|---|---|
| 1 | CVE-2017-13077 | `generic/pcap/pcap_eapol_survey.py` |
| 2 | CVE-2019-9494 | `generic/pcap/pcap_dragonblood.py` |
| 3 | CVE-2019-9496 | `generic/pcap/pcap_dragonblood.py` |

## CVEs by Vendor

| Vendor | CVE Count | CVE IDs |
|---|---:|---|
| pcap | 3 | CVE-2017-13077, CVE-2019-9494, CVE-2019-9496 |

---

> Generated by tools/generate_full_catalog.py