# WirelessXPL-Forge

> **Modular wireless security research framework** for 802.11 (WPA2/WPA3/WPE/EAPOL), Bluetooth Classic, BLE, Zigbee, RFID and ESP32 lab workflows — designed for authorised penetration testing, research, and education.

**Version:** 2.0.3 | **License:** BSD-3-Clause | **Python:** 3.8 - 3.13

**Language:** **English (en-US)** — default · **Português (pt-BR):** [README.pt-BR.md](README.pt-BR.md)

<p align="center">
  <a href="https://github.com/mrhenrike/WirelessXPL-Forge/actions"><img src="https://img.shields.io/github/actions/workflow/status/mrhenrike/WirelessXPL-Forge/compat-matrix.yml?branch=master&label=CI&logo=github" alt="CI"></a>
  <img src="https://img.shields.io/badge/License-BSD%203--Clause-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0.3-green" alt="Version">
  <img src="https://img.shields.io/badge/Modules-329%2B-brightgreen" alt="Modules">
  <img src="https://img.shields.io/badge/Python-3.8--3.13-blue" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
</p>

---

## Instalacao / Installation

### Basico / Basic (clone)

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
python3 -m pip install -r requirements.txt
cp pyproject.toml.example pyproject.toml   # opcional — editable install
pip install -e ".[wifi]"
python wxf.py
```

> `pyproject.toml` é **local** (não versionado no GitHub). Use o template `pyproject.toml.example`.

### Por tecnologia / By technology (editable, após `pyproject.toml` local)

| Extra | Tecnologia | Pacotes incluidos | Tamanho estimado |
|---|---|---|---|
| `[wifi]` | WiFi 802.11 (WPS, WPA, evil twin, PMKID...) | scapy, dnslib, cryptography | +45 MB |
| `[bt]` | Bluetooth BLE + Classic (KNOB, BLESA, GATT...) | bleak, pybluez | +8 MB |
| `[cellular]` | Celular / SIM / LTE / 5G (IMSI, SS7, SIMjacker...) | pyscard, pytlv, pyserial | +5 MB |
| `[rf]` | RF / SDR / SubGHz (RTL-SDR, replay, jam...) | pyrtlsdr, pyserial, pyusb, numpy | +50 MB |
| `[drone]` | Drones / UAV / MAVLink (skyjack, spoof, deauth...) | pymavlink, dronekit | +20 MB |
| `[ir]` | Infrared (blaster, replay...) | pyserial, pyusb | +3 MB |
| `[gps]` | GPS / Wardriving (GPSD, GPX export...) | gpsd-py3, gpxpy | +3 MB |
| `[iot]` | IoT / Zigbee / RFID (Killerbee, Zigator...) | pyserial, pyusb | +3 MB |
| `[all]` | Todos os extras acima | (tudo acima) | ~135 MB |

```bash
# Exemplos (com pyproject.toml local):
pip install -e ".[wifi]"
pip install -e ".[wifi,bt,cellular]"
pip install -e ".[all]"
```

> **Nota:** Ferramentas externas (aircrack-ng, hashcat, hcxdumptool) não são instaladas via pip.
> Consulte [PREREQUISITES.md](docs/PREREQUISITES.md) para requisitos de hardware e software externos.

### By technology (English)

Same extras as the table above; use `pip install -e ".[wifi]"` etc. after creating local `pyproject.toml` from `pyproject.toml.example`.

| Extra | Technology | Included packages | Estimated size |
|---|---|---|---|
| `[wifi]` | WiFi 802.11 (WPS, WPA, evil twin, PMKID...) | scapy, dnslib, cryptography | +45 MB |
| `[bt]` | Bluetooth BLE + Classic (KNOB, BLESA, GATT...) | bleak, pybluez | +8 MB |
| `[cellular]` | Cellular / SIM / LTE / 5G (IMSI, SS7, SIMjacker...) | pyscard, pytlv, pyserial | +5 MB |
| `[rf]` | RF / SDR / SubGHz (RTL-SDR, replay, jam...) | pyrtlsdr, pyserial, pyusb, numpy | +50 MB |
| `[drone]` | Drones / UAV / MAVLink (skyjack, spoof, deauth...) | pymavlink, dronekit | +20 MB |
| `[ir]` | Infrared (blaster, replay...) | pyserial, pyusb | +3 MB |
| `[gps]` | GPS / Wardriving (GPSD, GPX export...) | gpsd-py3, gpxpy | +3 MB |
| `[iot]` | IoT / Zigbee / RFID (Killerbee, Zigator...) | pyserial, pyusb | +3 MB |
| `[all]` | All extras above | (all above) | ~135 MB |

> **Note:** External tools (aircrack-ng, hashcat, hcxdumptool) are not installed via pip.
> See [PREREQUISITES.md](docs/PREREQUISITES.md) for hardware and external software requirements.

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

## System prerequisites (host tools)

The Python package and its declared dependencies install from the repo clone. The table below lists **host tools** and **firmware** that are **not** bundled: they are normal OS-level installs (apt, brew, upstream installers).

| Tool | Role |
|------|------|
| **aircrack-ng suite** | `aircrack-ng`, `airodump-ng`, `aireplay-ng` — PCAP / wifi_lab workflows |
| **hcxtools / hcxdumptool** | PMKID capture and hash conversion for hashcat |
| **hashcat** | WPA2/WPA3 offline cracking (modes 22000/22001) |
| **tshark** *(optional)* | BLE / 802.11 dissection when Scapy layers are thin |
| **mdk4 / mdk3** *(optional)* | Deauth storms, beacon floods, mesh flooding |
| **hostapd + dnsmasq** *(optional)* | Rogue AP / evil-twin + DHCP/DNS for captive portal flows |
| **wifiphisher** *(optional)* | Phishing via **bridge** (`generic/external/wifiphisher_bridge`) |
| **eaphammer** *(optional)* | EAP/PEAP capture via **bridge** |
| **airgeddon** *(optional)* | Menu-driven attacks via **bridge** |
| **btlejack** *(optional)* | BLE sniff/jam/hijack via **bridge** |
| **opendrop / owl** *(optional)* | AWDL/AirDrop lab via **bridge** |
| **Bruce ESP32 firmware** *(optional)* | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) — device image; export PCAP to `generic/pcap/*` |
| **pyserial** *(optional)* | Serial to Bruce (`pip install -e ".[serial]"` with local `pyproject.toml`) |

Run `use generic/external/wireless_tool_prereq_audit` after install to verify your PATH.

---

## Quick Install

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
pip install -r requirements.txt
cp pyproject.toml.example pyproject.toml   # local only — not on GitHub
pip install -e ".[wifi]"
python wxf.py
```

### WSL2 / Kali (recommended for capture tools)

```bash
sudo apt install aircrack-ng hcxtools hcxdumptool mdk4 hostapd dnsmasq tshark
pip install -r requirements.txt
pip install -e ".[wifi]"
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

### Bluetooth / BLE / Zigbee (generic/bluetooth)

| Module | Description |
|--------|-------------|
| `bt_hid_injection` | Bluetooth HID keyboard injection (Broadcom fallback) |
| `bt_baseband_attack` | BrakTooth / SweynTooth via ESP32 serial |
| `bt_session_attack` | KNOB, BIAS, BLUFFS session-layer attacks |
| `blueborne_attack` | BlueBorne L2CAP overflow (kernel offset profiles) |
| `ble_btlejack` | BTLEJack BLE sniff/jam/hijack |
| `ble_crackle` | BLE Legacy Pairing key recovery |
| `knob_native_cve_2019_9506` | **CVE-2019-9506** — BT BR/EDR key entropy downgrade para 1 byte |
| `zigbee_touchlink_factory_reset` | Zigbee ZLL Touchlink Factory Reset sem autenticação (Hue, TRADFRI) |
| `zigbee_network_key_extract` | **novo v1.7.0** — Extração de Network Key Zigbee via decrypt de Transport Key com TC Link Key pública |
| `zigbee_rejoin_hijack` | **novo v1.7.0** — Zigbee Rejoin Hijack: beacon spoof → desassociação → captura Transport Key |
| `ble_gatt_enum_unauth` | **novo v1.7.0** — BLE GATT enumeration sem autenticação (serviços, características, writable handles) |
| `ble_spoofing_impersonation` | **novo v1.7.0** — BLE device cloning via advertising data replay (nome, UUIDs, manufacturer data) |

### IoT Protocols (generic/iot_proto) — *novo v1.3.0+*

| Module | Description |
|--------|-------------|
| `mqtt_broker_enum_inject` | MQTT — acesso anônimo, enumeração de tópicos e injeção de payload |
| `mqtt_lateral_pivot` | MQTT — pivot via broker para alcançar dispositivos IoT internos |
| `mqtt_broker_dos` | **novo v1.7.0** — **CVE-2017-7651** DoS por CONNECT/DISCONNECT cycling com LWT oversized |
| `mqtt_sys_acl_bypass_cve_2020_13849` | **novo v1.7.0** — **CVE-2020-13849** Mosquitto ACL bypass via $SYS/# subscription |
| `coap_resource_enum` | CoAP — discovery `.well-known/core` + fator de amplificação UDP |
| `coap_block_overflow` | **novo v1.7.0** — **CVE-2019-9750** CoAP Block2 option heap overflow em stacks embarcados |
| `upnp_ssdp_attack` | UPnP/SSDP — descoberta de dispositivos + **CVE-2020-12695** CallStranger SSRF |
| `upnp_ssdp_rce_inject` | **novo v1.7.0** — **CVE-2013-0229** SOAP action injection + AddPortMapping sem auth |
| `upnp_ssdp_amplification` | **novo v1.7.0** — SSDP amplification/reflection 20-50x via spoofed M-SEARCH |
| `mdns_poisoning` | mDNS — enumeração passiva de serviços + envenenamento de respostas |
| `mdns_amplification` | **novo v1.7.0** — mDNS amplification 5-30x via QTYPE=ANY queries (Bonjour/Avahi) |
| `dds_rtps_attack` | DDS/RTPS — enumeração de participantes ROS2/automotivo (unauthenticated R/W) |
| `tftp_firmware_attack` | TFTP — download/upload de firmware sem autenticação em dispositivos embarcados |

### LoRaWAN (generic/lorawan) — *novo v1.3.0*

| Module | Description |
|--------|-------------|
| `lorawan_adr_bitflip_cve_2022_39274` | **CVE-2022-39274** — ADR bit-flip para degradação de sinal/DoS em end-devices |
| `lorawan_join_replay` | Join Accept Replay — session hijack por falta de replay protection (LoRaWAN 1.0.x) |

### Automotive / CAN bus (generic/automotive) — *novo v1.3.0+*

| Module | Description |
|--------|-------------|
| `can_bus_attack` | CAN bus — enumeração ECU via OBD-II, fuzzing de IDs, UDS ECU reset, frame replay |
| `mercedes_mbux_bt_rce_cve_2023_37462` | **novo v1.7.0** — **CVE-2023-37462** Mercedes MBUX NTG6 Bluetooth RCE (scan, info, probe) |

### Z-Wave (generic/zwave) — *novo v1.7.0*

| Module | Description |
|--------|-------------|
| `zwave_s0_key_extract` | **CVE-2019** — Z-Wave S0 pairing sniff: temp key all-zeros → network key extraction |
| `zwave_replay_attack` | Z-Wave command replay sem S2 (door_unlock, switch, thermostat) via SDR |

### Wearables BLE (generic/wearables) — *novo v1.7.0*

| Module | Description |
|--------|-------------|
| `xiaomi_miband_ble_breakmi` | Xiaomi Mi Band 3-7: advertising clone, auth key replay, biometric exfil (passos, HR, bateria) |

### IoT Lateral Movement (generic/lateral_iot) — *novo v1.3.0*

| Module | Description |
|--------|-------------|
| `arp_spoof_iot_pivot` | ARP Spoofing — MitM entre dispositivos IoT e gateway para interceptação |
| `uart_shell_detect` | UART — detecção de console serial embarcado (multi-baud: 9600→921600) |
| `fake_dhcp_server` | Rogue DHCP — servidor desonesto para redirecionar tráfego IoT (gateway/DNS control) |

### Wi-Fi Lab - SweynTooth BLE (generic/bluetooth/sweyntooth) - NEW v1.8.0

| Module | Description |
|--------|-------------|
| `sweyntooth_scanner` | Passive BLE scanner detecting SweynTooth-vulnerable firmware signatures |
| `sweyntooth_cve_2019_16336` | CVE-2019-16336 - BLE Link Layer length overflow (Texas Instruments) |
| `sweyntooth_cve_2019_17517` | CVE-2019-17517 - BLE data channel PDU overflow (Microchip) |
| `sweyntooth_cve_2019_17519` | CVE-2019-17519 - BLE slave connection reject bypass (Dialog Semiconductor) |
| `sweyntooth_cve_2019_17520` | CVE-2019-17520 - BLE public key crash on pairing (Telink) |

### Wi-Fi Lab - FragAttacks (generic/wifi_lab/fragattacks) - NEW v1.8.0

| Module | Description |
|--------|-------------|
| `fragattacks_scanner` | Passive scanner detecting FragAttacks-vulnerable APs by beacon flags |
| `fragattacks_cve_2020_26140` | CVE-2020-26140 - Plaintext data injection in non-strict WPA2 APs |
| `fragattacks_cve_2020_26141` | CVE-2020-26141 - Fragment cache abuse / non-contiguous fragment injection |
| `fragattacks_cve_2020_26143` | CVE-2020-26143 - Mixed plaintext/encrypted fragment acceptance |

### Wi-Fi Lab - KRACK (generic/wifi_lab/krack) - NEW v1.8.0

| Module | Description |
|--------|-------------|
| `krack_scanner` | Passive scanner for KRACK nonce-reuse indicators (CVE-2017-13077..13088) |
| `krack_4way_retransmit` | CVE-2017-13077 - PTK reinstallation via Msg3 retransmission |
| `krack_group_key_retransmit` | CVE-2017-13080 - GTK reinstallation via group key handshake replay |

### Wi-Fi Lab - Kr00k (generic/wifi_lab)

| Module | Description |
|--------|-------------|
| `wifi_kr00k_cve_2019_15126` | **CVE-2019-15126** KR00K: deauth + CCMP zero-TK decryption (Broadcom/Cypress chips) |

### CVE / Exploits (generic/cve)

| Module | Description |
|--------|-------------|
| `zigbee_attack` | Zigbee / IEEE 802.15.4 via KillerBee (Sewio driver) |
| `krack_attack` | KRACK (WPA2 4-way replay + msg3 collection) |
| `ssid_confusion` | SSID Confusion attack |
| `pmkid_attack` | PMKID clientless attack |

### Sub-GHz Attack Suite (generic/subghz) - NEW v1.8.0

> **LEGAL WARNING:** Transmitting on licensed Sub-GHz bands without authorization
> is illegal in most jurisdictions. Use only on your own licensed equipment,
> inside RF-shielded enclosures, or in authorized red team engagements.
> Garage/gate spoofing without property owner consent is a criminal offense.

#### Supported Protocols

| Protocol | Bits | Frequency | Security | Module | HW Required |
|----------|------|-----------|----------|--------|-------------|
| EV1527 | 24 | 433 MHz | None | `subghz/static_code_replay` | HackRF / CC1101 |
| Princeton/PT2262 | 24 | 315/433 MHz | None | `subghz/static_code_replay` | HackRF / CC1101 |
| CAME | 12 | 303-868 MHz | None | `subghz/debruijn_bruteforce` | HackRF |
| NICE Flo | 12 | 433/868 MHz | None | `subghz/debruijn_bruteforce` | HackRF |
| KeeLoq | 64 | 433/868 MHz | Rolling code | `subghz/keeloq_*` | HackRF |
| TPMS | var | 315/433 MHz | CRC only | `subghz/tpms/*` | RTL-SDR |

#### Module Reference

| Module | Description |
|--------|-------------|
| `static_code_replay` | EV1527/Princeton/CAME/NICE/Holtek/Chamberlain static code replay |
| `debruijn_bruteforce` | DeBruijn sequence bruteforce for 12-bit garage door protocols |
| `keeloq_decoder` | KeeLoq rolling code frame decoder and analyzer |
| `keeloq_replay` | KeeLoq rolling code replay within counter window |
| `ev1527_vehicle_cve_2025_70994` | CVE-2025-70994 - EV1527 vehicle remote keyless entry replay |
| `subghz_jammer` | Sub-GHz selective jammer (authorized testing only) |
| `br_gate_scanner` | Brazilian gate/garage protocol scanner and recorder |
| `tpms/tpms_decoder` | TPMS tire pressure sensor passive decoder |
| `tpms/tpms_spoof` | TPMS spoofed tire pressure alert injection |
| `tools/ook_analyzer` | OOK signal analyzer: preamble, bit timing, protocol identification |

#### Usage Example - DeBruijn Bruteforce (CAME garage doors)

```
wxf > use generic/subghz/debruijn_bruteforce
wxf (DeBruijn) > set protocol CAME
wxf (DeBruijn) > set frequency 433.92
wxf (DeBruijn) > set output_sub /tmp/came_brute.sub
wxf (DeBruijn) > run

[*] Generating DeBruijn sequence for CAME 12-bit at 433.92 MHz
[*] Total codes to test: 4096
[*] Estimated time at 287ms/code: ~4.8 minutes
[+] Generated: /tmp/came_brute.sub (Flipper Zero compatible)
[*] Load on Flipper: Sub-GHz -> Saved -> came_brute.sub -> Send
```

#### Usage Example - EV1527 Static Replay

```
wxf > use generic/subghz/static_code_replay
wxf (StaticCodeReplay) > set protocol EV1527
wxf (StaticCodeReplay) > set code 0xA3F21B
wxf (StaticCodeReplay) > set frequency 433.92
wxf (StaticCodeReplay) > set interface hackrf
wxf (StaticCodeReplay) > set simulate true
wxf (StaticCodeReplay) > run

[SIMULATE] Would transmit EV1527 code 0xA3F21B at 433.92 MHz
[SIMULATE] OOK pulse sequence: 24 bits, 350us/bit
[!] Set simulate=false and interface=hackrf to transmit live
```

---

### Drone/UAV Security (generic/drones) - NEW v1.8.0

> **LEGAL WARNING:** Unauthorized drone interference (deauth, disarm, GPS spoof,
> command injection) violates aviation law in all jurisdictions.
> In many countries it constitutes a federal criminal offense with severe penalties.
> Use ONLY on drones you own, in shielded environments, or under explicit
> written authorization from both the drone owner and relevant aviation authority.

| Module | Description |
|--------|-------------|
| `drone_scanner` | Drone discovery by WiFi SSID fingerprint (DJI, Parrot, Holy Stone, FPV) |
| `mavlink/mavlink_scanner` | MAVLink device scanner on UDP 14550 / TCP 5760 |
| `mavlink/mavlink_force_disarm` | Force disarm command via MAV_CMD_COMPONENT_ARM_DISARM |
| `mavlink/mavlink_gps_spoof` | Inject spoofed GPS NMEA to ground station / GCS |
| `mavlink/mavlink_waypoint_inject` | Overwrite active mission waypoints |
| `mavlink/mavlink_geofence_disable` | Disable geofence parameters via PARAM_SET |
| `mavlink/mavlink_param_dump` | Dump all autopilot parameters (read-only audit) |
| `mavlink/mavlink_flood_dos` | MAVLink message flood DoS |
| `dji/dji_wifi_scan` | DJI drone SSID scanner and version extractor |
| `dji/dji_deauth` | DJI WiFi deauthentication (landing interruption) |
| `dji/dji_quicktransfer_exfil_cve_2023_6951` | CVE-2023-6951 - DJI QuickTransfer unauthenticated file exfil |
| `parrot/parrot_anafi_deauth_cve_2019_3944` | CVE-2019-3944 - Parrot ANAFI WiFi deauth |
| `parrot/parrot_anafi_webcrash_cve_2019_3945` | CVE-2019-3945 - Parrot ANAFI REST API crash |
| `parrot/parrot_anafi_udp_cmd_inject` | Parrot ANAFI UDP command injection |
| `parrot/parrot_bebop_dhcp_exhaust_cve_2022_46416` | CVE-2022-46416 - Parrot Bebop DHCP pool exhaustion |
| `holystone/hsrid01_ble_dos_cve_2024_52876` | CVE-2024-52876 - Holy Stone HSRID01 BLE DoS |
| `fpv/eachine_e52_tcp_takeover` | Eachine E52 TCP replay takeover |

#### Usage Example - MAVLink Force Disarm

```
wxf > use generic/drones/mavlink/mavlink_force_disarm
wxf (MAVForceDisarm) > set rhost 192.168.1.100
wxf (MAVForceDisarm) > set rport 14550
wxf (MAVForceDisarm) > set simulate true
wxf (MAVForceDisarm) > run

[SIMULATE] Would send MAV_CMD_COMPONENT_ARM_DISARM (param1=0, param2=21196)
[SIMULATE] To: udp://192.168.1.100:14550 sysid=1 compid=1
[!] Set simulate=false to send live command
[!] PREREQ: Network access to drone on UDP 14550
[!] WARNING: Force disarm on airborne drone causes crash
```

#### Usage Example - DJI QuickTransfer Exfil (CVE-2023-6951)

```
wxf > use generic/drones/dji/dji_quicktransfer_exfil_cve_2023_6951
wxf (DJIQuickTransferExfil) > set rhost 192.168.2.1
wxf (DJIQuickTransferExfil) > set output_dir /tmp/dji_exfil
wxf (DJIQuickTransferExfil) > set simulate true
wxf (DJIQuickTransferExfil) > run

[SIMULATE] CVE-2023-6951: DJI QuickTransfer unauthenticated file access
[SIMULATE] Target: http://192.168.2.1:80
[SIMULATE] Would enumerate /DCIM/ and download media files
[!] Set simulate=false for live exfil - requires WiFi association to DJI drone
```

---

### Maritime Security (generic/maritime) - NEW v1.8.0

> **LEGAL WARNING:** AIS and NMEA spoofing at sea is illegal under SOLAS and
> maritime law in all jurisdictions. It creates navigation safety hazards.
> Use only in authorized lab environments or closed RF chambers.

| Module | Description |
|--------|-------------|
| `nmea_spoof` | NMEA 0183 GPS/navigation sentence injection (TCP multiplexer) |
| `ais_spoof` | AIS vessel position report spoofing with Type 1 bit encoding |

#### Usage Example - AIS Vessel Spoof

```
wxf > use generic/maritime/ais_spoof
wxf (AISSpoofAttack) > set target_host 192.168.1.100
wxf (AISSpoofAttack) > set target_port 10110
wxf (AISSpoofAttack) > set simulate true
wxf (AISSpoofAttack) > run

[SIMULATE] AIS Type 1 sentence for MMSI 123456789 (PHANTOM)
[SIMULATE] Position: 1.264N / 103.826E at 12.0kn COG 90
[SIMULATE] Sentence: !AIVDM,1,1,,A,15NN...
[!] Set simulate=false + network access to AIS multiplexer (TCP 10110) to inject
[!] WARNING: AIS spoofing is a maritime criminal offense
```

---

### Vehicular Radar (generic/vehicular_radar) - NEW v1.8.0

> **LEGAL WARNING:** Active radar jamming or spoofing is illegal in most
> jurisdictions and creates road safety hazards. Use ONLY in shielded
> anechoic chambers or authorized test tracks with controlled access.

| Module | Description |
|--------|-------------|
| `traffic_enforcement_scanner` | Kapsch RSU / Motorola Vigilant / Selea ANPR fingerprint scanner |
| `fmcw_radar_attack` | FMCW automotive radar signal parameter calculator (MadRadar/mmSpoof) |

#### Usage Example - Traffic Enforcement Scanner

```
wxf > use generic/vehicular_radar/traffic_enforcement_scanner
wxf (TrafficEnforcementScanner) > set target_cidr 10.0.1.0/24
wxf (TrafficEnforcementScanner) > run

[*] Scanning 10.0.1.0/24 for traffic enforcement devices...
[+] 10.0.1.42: Kapsch TrafficCom RSU | ports: 443,8443
     CVEs: CVE-2025-25734, CVE-2025-25735, CVE-2025-25736
[+] 10.0.1.67: Motorola Vigilant LPR | ports: 80,443
     CVEs: CVE-2024-51023, CVE-2024-51024
[*] Scan complete: 2 devices found
```

### Forensics, Wardriving and Session Management (generic) - v1.8.0

| Module | Description |
|--------|-------------|
| `evidence_vault/evidence_vault` | Hash-chained tamper-evident audit ledger (ISO/IEC 27037 chain-of-custody) |
| `wardrive/wardrive_logger` | GPS-tagged WiFi discovery logger with CSV/JSON/KML export |
| `wids/wifi_ids` | Native Python WIDS: deauth flood, evil twin, rogue AP, beacon flood detection |
| `session_manager/session_manager` | SQLite-backed pentest session manager with JSON export |
| `bluetooth/bt_hid_keyboard_inject` | Bluetooth HID keyboard injection (Broadcom/BlueZ) |

#### Usage Example - Evidence Vault

```
wxf > use generic/evidence_vault/evidence_vault
wxf (EvidenceVault) > set session_id pentest_office_2026
wxf (EvidenceVault) > set vault_dir /evidence
wxf (EvidenceVault) > run scan --ssid "OfficeWiFi" --bssid AA:BB:CC:DD:EE:FF --channel 6 --rssi -65 --security WPA2

[+] Evidence recorded: #0001 type=scan sha256=abc123...
[+] Chain head: abc123...

wxf (EvidenceVault) > verify
[+] Chain VALID (3 records)
[+] ISO/IEC 27037 chain-of-custody maintained
```

#### Usage Example - WIDS

```
wxf > use generic/wids/wifi_ids
wxf (WirelessIDS) > set interface wlan0mon
wxf (WirelessIDS) > set simulate true
wxf (WirelessIDS) > run

[SIMULATE] WIDS scenario: DEAUTH_FLOOD detected
  BSSID: AA:BB:CC:DD:EE:FF | client: 11:22:33:44:55:66 | frames: 45/10s
  Alert: DEAUTH_FLOOD severity=HIGH
[SIMULATE] EVIL_TWIN detected - SSID 'OfficeWiFi' on new BSSID
[*] To start live monitoring: set simulate false
```

---

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

- **[GitHub Wiki](https://github.com/mrhenrike/WirelessXPL-Forge/wiki)** — complete documentation
  - [Quick Start](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/Quick-Start)
  - [CLI Reference](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/CLI-Reference)
  - [Sub-GHz Attacks](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/SubGHz-Attacks)
  - [Drone Security](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/Drone-Security)
  - [FragAttacks](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/FragAttacks)
  - [KRACK](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/KRACK)
  - [Evidence & Forensics](https://github.com/mrhenrike/WirelessXPL-Forge/wiki/Evidence-Forensics)
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
**Support:** [suporte@uniaogeek.com.br](mailto:suporte@uniaogeek.com.br)  
**Lineage:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → WirelessXPL-Forge
