# Hardware Requirements for WirelessXPL-Forge

> Author: Andre Henrique (LinkedIn/X: @mrhenrike)
> Version: 2.2.0

This document lists the dedicated hardware required by modules that depend on
physical wireless interfaces, SDR receivers, Bluetooth adapters, or specialized
peripherals.  Modules that operate purely over TCP/IP or simulate attacks in
software do not appear here.

---

## 1. WiFi (802.11) Modules

### 1.1 Monitor-Mode WiFi Adapter

**Required by:** all modules under `wifi/` that perform frame injection,
packet capture, or deauthentication.

| Device | Chipset | Interface | Notes |
|---|---|---|---|
| Alfa AWUS036ACH | Realtek RTL8812AU | USB 3.0 | Dual-band, monitor + injection, widely supported |
| Alfa AWUS036AXML | MediaTek MT7921AU | USB 3.0 | WiFi 6E tri-band, monitor mode with patched driver |
| Alfa AWUS1900 | Realtek RTL8814AU | USB 3.0 | 4x4 MIMO, high TX power |
| Panda PAU09 | Ralink RT5572 | USB 2.0 | Budget dual-band, good Linux support |
| TP-Link TL-WN722N v1 | Atheros AR9271 | USB 2.0 | Classic 2.4 GHz only, native monitor mode |

**Setup:**
```bash
# Put interface in monitor mode
sudo airmon-ng start wlan0
# Or manually:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### 1.2 WiFi 6/6E/7 Adapter (for MLD/EHT modules)

**Required by:** `iwlwifi_wifi7_mld_dos`, `mac80211_mlo_uaf`, WiFi 6E channel modules.

| Device | Chipset | Notes |
|---|---|---|
| Intel AX210 | Intel AX210 | WiFi 6E, MLD support with kernel 6.1+ |
| Intel BE200 | Intel BE200 | WiFi 7, EHT support with kernel 6.5+ |
| MediaTek MT7922 | MT7922 | WiFi 6E, Linux mt76 driver |

### 1.3 Rogue AP Platform

**Required by:** `evil_twin_*`, `karma_attack`, `captive_portal_*`, AP vendor exploit modules.

| Device | Notes |
|---|---|
| WiFi Pineapple Mark VII | Dedicated rogue AP, web UI, PineAP suite |
| Raspberry Pi 4 + external WiFi adapter | hostapd-based AP, flexible |
| Any Linux laptop + monitor-mode adapter | hostapd + dnsmasq |

---

## 2. Bluetooth / BLE Modules

### 2.1 Bluetooth HCI Adapter

**Required by:** all modules under `bluetooth/` that send raw HCI commands,
perform BLE scanning, or inject L2CAP frames.

| Device | Chipset | Interface | Notes |
|---|---|---|---|
| Sena UD100 | CSR8510 | USB | Class 1, long range, good Linux support |
| TP-Link UB500 | RTL8761B | USB | BT 5.0, compact, works with btusb driver |
| Intel AX200/AX210 (integrated) | Intel | PCIe/M.2 | BT 5.2, integrated with WiFi card |
| Parani UD100-G03 | CSR | USB | Industrial-grade, configurable TX power |

**Setup:**
```bash
# Verify adapter
hciconfig -a
# Reset and bring up
sudo hciconfig hci0 reset
sudo hciconfig hci0 up
# BLE scan
sudo hcitool lescan
```

### 2.2 Ubertooth One (BLE sniffing and injection)

**Required by:** `btle_scan`, `ble_btlejack`, `ble_mitm`, BLE protocol analysis modules.

| Device | Notes |
|---|---|
| Ubertooth One | 2.4 GHz spectrum analyzer, BLE sniffing, raw BT injection |
| Ubertooth One + external antenna | Extended range for field assessments |

**Setup:**
```bash
# Install ubertooth tools
sudo apt install ubertooth
# Sniff BLE advertising
ubertooth-btle -f
# Follow a specific connection
ubertooth-btle -t AA:BB:CC:DD:EE:FF
```

### 2.3 nRF24 / CrazyRadio PA (MouseJack)

**Required by:** `mousejack_nrf24`, `mousejack_nrf24_wireless_input_exploit`.

| Device | Notes |
|---|---|
| CrazyRadio PA | nRF24LU1+ based, 2.4 GHz, MouseJack firmware |
| nRF24L01+ module + Arduino | DIY, requires custom firmware |
| Logitech Unifying Receiver (flashed) | Repurposed for research |

**Setup:**
```bash
# Flash MouseJack firmware to CrazyRadio PA
cd mousejack/
make
sudo make install
# Run jackit for device discovery
sudo jackit
```

---

## 3. SDR (Software-Defined Radio) Modules

### 3.1 General SDR Receiver/Transceiver

**Required by:** `gnuradio_sdr_framework`, `tempest*`, `dvb_s2_intercept`,
`iridium_pager_decode`, `rolljam_replay`, `pmr_*`, `p25_*`, `dmr_*`, `tetra_*`.

| Device | Frequency Range | Interface | Notes |
|---|---|---|---|
| RTL-SDR Blog V4 | 24 MHz - 1.766 GHz | USB | RX only, cheapest option |
| HackRF One | 1 MHz - 6 GHz | USB | TX + RX, half-duplex |
| YARD Stick One | Sub-1 GHz (300/433/868/915 MHz) | USB | TX + RX, ISM bands |
| BladeRF 2.0 micro xA4 | 47 MHz - 6 GHz | USB 3.0 | Full-duplex, high bandwidth |
| LimeSDR Mini 2.0 | 10 MHz - 3.5 GHz | USB 3.0 | Full-duplex, open-source |
| USRP B210 | 70 MHz - 6 GHz | USB 3.0 | Ettus/NI, professional grade |
| Pluto SDR | 325 MHz - 3.8 GHz | USB | Analog Devices, TX + RX |

### 3.2 SDR Antennas

| Antenna | Frequency | Use Case |
|---|---|---|
| Telescopic whip (included with RTL-SDR) | 24 MHz - 1.7 GHz | General purpose |
| Discone wideband | 25 MHz - 1.3 GHz | Wideband monitoring |
| Yagi directional | 400-470 MHz or 900 MHz | PMR/P25/TETRA, long range |
| Satellite dish + LNB | 950 MHz - 2.15 GHz (L-band IF) | DVB-S2/VSAT interception |
| Patch antenna | 1.575/1.602 GHz | Iridium/GPS |

---

## 4. TEMPEST / EM Emanation Modules

**Required by:** `tempestsdr_hdmi_eavesdrop`, `deep_tempest_dl`,
`gr_tempest_gnuradio`, `em_eye_camera_eavesdrop`, `cable_emanation_sniffer`,
`keyboard_emanation_decoder`.

| Device | Notes |
|---|---|
| RTL-SDR + directional antenna | Budget TEMPEST receiver |
| HackRF One + LNA + directional antenna | Better sensitivity |
| USRP B210 | Professional grade, required for Deep-Tempest DL |
| Near-field H-loop probe | Keyboard/cable emanation capture |
| Shielded room / Faraday tent | Reduces ambient noise for testing |

**Minimum setup:** RTL-SDR Blog V4 + telescopic antenna.
**Recommended:** HackRF One + LNA + directional antenna (Yagi or log-periodic).

---

## 5. SATCOM / Satellite Modules

**Required by:** `acidrain_wiper_emulator`, `vsat_terminal_scan`,
`cobham_vsat7090_vuln`, `dvb_s2_intercept`, `iridium_pager_decode`.

| Device | Notes |
|---|---|
| RTL-SDR + Iridium patch antenna | Iridium pager decoding |
| RTL-SDR + satellite dish (60cm+) + LNB | DVB-S2 signal capture |
| HackRF One + LNA | VSAT signal analysis |
| Ethernet connection to target VSAT terminal | For IP-based VSAT exploits |

**Note:** `acidrain_wiper_emulator` operates on a local simulation and does
NOT require satellite hardware.  It emulates the wiper payload for research.

---

## 6. PMR (Professional Mobile Radio) Modules

**Required by:** `tetra_burst_tea1_decryptor`, `tetra_passive_sniffer`,
`dmr_traffic_sniffer`, `p25_eavesdrop_scanner`, `p25_radio_inhibit`,
`p25_jam_selective`.

| Device | Notes |
|---|---|
| RTL-SDR Blog V4 | RX-only for passive sniffing |
| HackRF One | TX + RX for active attacks (P25 jam, radio inhibit) |
| YARD Stick One | Sub-1 GHz TX for radio inhibit commands |
| Baofeng UV-5R (or similar) | Reference radio for testing |
| Uniden BCD436HP scanner | Trunking scanner for P25 monitoring |

**Frequency bands:**
- TETRA: 380-400 MHz (Europe), 410-430 MHz, 450-470 MHz
- P25: 136-174 MHz (VHF), 380-512 MHz (UHF), 700/800 MHz
- DMR: 136-174 MHz, 403-527 MHz

---

## 7. Li-Fi (Visible Light Communication) Modules

**Required by:** `lifi_signal_intercept`, `lifi_injection_attack`,
`lifi_dos_strobe`.

| Device | Notes |
|---|---|
| High-speed photodiode (e.g., Thorlabs PDA10A2) | Optical signal capture |
| Programmable LED driver (e.g., Arduino + high-power LED) | Signal injection |
| USB oscilloscope (e.g., PicoScope 2000) | Signal analysis |
| pureLiFi Gigabit dongle (or similar) | Target Li-Fi endpoint |

**Note:** Li-Fi modules require line-of-sight to the Li-Fi access point.
These are experimental modules for research environments only.

---

## 8. Qi Wireless Charging Modules (VoltSchemer)

**Required by:** `voltschemer_voice_injection`, `voltschemer_overheating`,
`voltschemer_fod_bypass`, `voltschemer_signal_interference`,
`qi_communication_eavesdrop`, `qi_eavesdrop_power_analysis`.

| Device | Notes |
|---|---|
| Qi-compatible wireless charger (5W-15W) | Target device |
| EM probe coil (near-field) | Qi communication eavesdrop |
| Signal generator (e.g., Rigol DG1022Z) | Voltage manipulation |
| Oscilloscope with current probe | Power analysis |
| Custom interposer PCB | Between charger and phone for MITM |
| HackRF One + amplifier | RF interference injection |

**VoltSchemer attack setup:**
The attacker places a custom interposer or modifies the charging pad to
inject malicious voltage patterns.  The signal generator drives the coil
at frequencies that cause the target phone's Qi controller to
misinterpret commands.

---

## 9. Zigbee / IEEE 802.15.4 Modules

**Required by:** `zigbee_*` modules, Zigbee ecosystem expansion.

| Device | Chipset | Notes |
|---|---|---|
| CC2531 USB dongle | TI CC2531 | Sniffer, flashed with Zigbee sniffer firmware |
| CC2652R LaunchPad | TI CC2652R | Multi-protocol (Zigbee, Thread, BLE) |
| SONOFF Zigbee 3.0 Dongle Plus | CC2652P | Zigbee coordinator, high TX power |
| ApiMote | CC2420 | KillerBee compatible, injection capable |
| Atmel RZUSBstick | AT86RF230 | Legacy, KillerBee compatible |

**Setup:**
```bash
# Install KillerBee
pip install killerbee
# Scan for Zigbee networks
zbstumbler
# Sniff traffic on channel 15
zbdump -c 15 -w capture.pcap
```

---

## 10. Physical Attack Modules

### 10.1 RollJam (Sub-GHz Replay)

**Required by:** `rolljam_replay_attack`.

| Device | Notes |
|---|---|
| 2x CC1101 modules + microcontroller | Jam + capture simultaneously |
| HackRF One | Alternative: single device jam + replay |
| YARD Stick One | Sub-GHz TX/RX |
| Flipper Zero | Built-in Sub-GHz with rolling code support |

### 10.2 BadUSB WiFi Exfiltration

**Required by:** `badusb_wifi_exfil`.

| Device | Notes |
|---|---|
| Rubber Ducky (Hak5) | USB HID injection |
| Digispark ATtiny85 | Budget alternative |
| O.MG Cable | Covert USB implant with WiFi exfiltration |
| Raspberry Pi Zero W | USB gadget mode + WiFi |
| WHID Injector | WiFi + HID injection combo |

### 10.3 IR Remote Replay

**Required by:** `ir_remote_replay`.

| Device | Notes |
|---|---|
| Flipper Zero | Built-in IR transceiver |
| Arduino + IR LED + IR receiver (TSOP38238) | DIY setup |
| USB IrDA adapter | Legacy, limited range |

---

## Quick Reference: Minimum Lab Setup

For a functional wireless security lab covering the majority of modules:

| Priority | Device | Covers |
|---|---|---|
| 1 (Essential) | Alfa AWUS036ACH (RTL8812AU) | WiFi monitor mode, frame injection, deauth |
| 2 (Essential) | USB Bluetooth 5.0 adapter (CSR8510 or RTL8761B) | BLE/BT scanning, HCI attacks |
| 3 (Recommended) | HackRF One | SDR TX/RX, Sub-GHz, TEMPEST, PMR, SATCOM |
| 4 (Recommended) | CrazyRadio PA | MouseJack, nRF24 attacks |
| 5 (Recommended) | CC2531 USB dongle | Zigbee sniffing |
| 6 (Optional) | Ubertooth One | Advanced BLE sniffing and injection |
| 7 (Optional) | RTL-SDR Blog V4 | Budget SDR receiver, TEMPEST, Iridium |
| 8 (Optional) | WiFi Pineapple Mark VII | Rogue AP, evil twin attacks |
| 9 (Specialized) | Signal generator + oscilloscope | VoltSchemer Qi attacks |
| 10 (Specialized) | Li-Fi photodiode + LED driver | Li-Fi research modules |

**Estimated cost (minimum lab: items 1-5):** USD 250-350
**Estimated cost (recommended lab: items 1-8):** USD 800-1200
**Estimated cost (full lab: all items):** USD 2000-3000+

---

## Software Dependencies

Most hardware-dependent modules also require specific software:

| Software | Purpose | Install |
|---|---|---|
| aircrack-ng | WiFi monitor mode, injection | `apt install aircrack-ng` |
| BlueZ | Bluetooth stack, HCI tools | `apt install bluez` |
| ubertooth-tools | Ubertooth One control | `apt install ubertooth` |
| GnuRadio | SDR signal processing | `apt install gnuradio` |
| gr-tempest | TEMPEST GnuRadio blocks | Build from source |
| KillerBee | Zigbee attack framework | `pip install killerbee` |
| MouseJack | nRF24 exploit firmware | Build from source |
| hackrf tools | HackRF One control | `apt install hackrf` |
| rtl-sdr | RTL-SDR control | `apt install rtl-sdr` |
| hostapd | Rogue AP creation | `apt install hostapd` |
| scapy | Packet crafting (WiFi, BT) | `pip install scapy` |

---

*Last updated: 2026-10-20*
